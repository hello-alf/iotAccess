import {
  DynamoDBClient,
  PutItemCommand,
  DeleteItemCommand,
  ScanCommand,
  BatchWriteItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand,
} from "@aws-sdk/client-apigatewaymanagementapi";
import { processAccess } from "../accessCore.js";
const dynamo = new DynamoDBClient({});
const CONNECTIONS_TABLE = process.env.TABLE;

function createWsManagementClient(event) {
  const endpoint = `https://${event.requestContext.domainName}/${event.requestContext.stage}`;
  return new ApiGatewayManagementApiClient({ endpoint });
}

function parseConnectionId(pkAttr) {
  const pk = pkAttr?.S ?? "";
  return pk.startsWith("connection#") ? pk.slice(5) : pk;
}

async function listActiveConnectionIds({ excludeId } = {}) {
  const resp = await dynamo.send(
    new ScanCommand({
      TableName: CONNECTIONS_TABLE,
      ProjectionExpression: "pk",
    })
  );
  return (resp.Items || [])
    .map((it) => parseConnectionId(it.pk))
    .filter((id) => id && id !== excludeId);
}

async function sendJsonToConnection(wsClient, connectionId, payload) {
  await wsClient.send(
    new PostToConnectionCommand({
      ConnectionId: connectionId,
      Data: Buffer.from(JSON.stringify(payload)),
    })
  );
}

async function deleteConnectionsBatch(connectionIds) {
  if (!connectionIds?.length) return;
  await dynamo.send(
    new BatchWriteItemCommand({
      RequestItems: {
        [CONNECTIONS_TABLE]: connectionIds.map((cid) => ({
          DeleteRequest: { Key: { pk: { S: `connection#${cid}` } } },
        })),
      },
    })
  );
}

async function broadcastJson(wsClient, payload, { excludeId } = {}) {
  const ids = await listActiveConnectionIds({ excludeId });
  const results = await Promise.allSettled(
    ids.map((cid) => sendJsonToConnection(wsClient, cid, payload))
  );

  const stale = results
    .map((r, i) => ({ r, cid: ids[i] }))
    .filter(
      ({ r }) =>
        r.status === "rejected" &&
        String(r.reason?.$metadata?.httpStatusCode) === "410"
    )
    .map(({ cid }) => cid);

  await deleteConnectionsBatch(stale);
}

function parseMessageBody(raw) {
  if (!raw) return "";
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

export const connect = async (event) => {
  const connectionId = event.requestContext.connectionId;
  await dynamo.send(
    new PutItemCommand({
      TableName: CONNECTIONS_TABLE,
      Item: { pk: { S: `connection#${connectionId}` } },
    })
  );
  return { statusCode: 200 };
};

export const disconnect = async (event) => {
  const connectionId = event.requestContext.connectionId;
  await dynamo.send(
    new DeleteItemCommand({
      TableName: CONNECTIONS_TABLE,
      Key: { pk: { S: `connection#${connectionId}` } },
    })
  );
  return { statusCode: 200 };
};

export const defaultRoute = async (event) => {
  const wsManagementClient = createWsManagementClient(event);
  const me = event.requestContext.connectionId;

  const body = parseMessageBody(event.body);
  if (body && typeof body === "object" && body.action === "access.request") {
    const { userId, uidHex, doorId } = body;

    const result = await processAccess({
      userId,
      uidHex,
      doorId,
      origin: "ws",
      requestId: event.requestContext?.requestId,
      publishResult: true, // también dispara MQTT
    });

    await sendJsonToConnection(wsManagementClient, me, {
      type: "access.result",
      doorId,
      allowed: result.allowed,
      reason: result.reason,
    });

    // (Opcional) informa al resto
    // await broadcastJson(wsManagementClient, { type: "access.notice", doorId, allowed: result.allowed }, { excludeId: me });

    return { statusCode: 200 };
  }

  // Fallback: echo/broadcast como ya tenías
  const message = (body && typeof body === "object" && "data" in body)
    ? body.data : body;

  await sendJsonToConnection(wsManagementClient, me, { type: "echo", data: message });
  await broadcastJson(wsManagementClient, { type: "msg", data: message }, { excludeId: me });

  return { statusCode: 200 };
};