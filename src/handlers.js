import { DynamoDBClient, PutItemCommand, DeleteItemCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { ApiGatewayManagementApiClient, PostToConnectionCommand } from "@aws-sdk/client-apigatewaymanagementapi";

const ddb = new DynamoDBClient({});
const TABLE = process.env.TABLE;

// Util para construir el client del Management API a partir del evento
function mgmtClientFromEvent(event) {
  const endpoint = `https://${event.requestContext.domainName}/${event.requestContext.stage}`;
  return new ApiGatewayManagementApiClient({ endpoint });
}

export const connect = async (event) => {
  const connectionId = event.requestContext.connectionId;
  await ddb.send(new PutItemCommand({
    TableName: TABLE,
    Item: { pk: { S: `conn#${connectionId}` } }
  }));
  return { statusCode: 200 };
};

export const disconnect = async (event) => {
  const connectionId = event.requestContext.connectionId;
  await ddb.send(new DeleteItemCommand({
    TableName: TABLE,
    Key: { pk: { S: `conn#${connectionId}` } }
  }));
  return { statusCode: 200 };
};

export const defaultRoute = async (event) => {
  const msg = event.body || "";
  const mgmt = mgmtClientFromEvent(event);
  const me = event.requestContext.connectionId;

  // Echo al emisor
  await mgmt.send(new PostToConnectionCommand({
    ConnectionId: me,
    Data: Buffer.from(JSON.stringify({ type: "echo", data: msg }))
  }));

  // Broadcast simple al resto (tabla pequeña en demo → Scan)
  const scan = await ddb.send(new ScanCommand({ TableName: TABLE, ProjectionExpression: "pk" }));
  const ids = (scan.Items || []).map(it => it.pk.S.split("#")[1]).filter(id => id !== me);

  // Dispara en paralelo; ignora conexiones que ya no existen
  await Promise.all(ids.map(async (cid) => {
    try {
      await mgmt.send(new PostToConnectionCommand({
        ConnectionId: cid,
        Data: Buffer.from(JSON.stringify({ type: "msg", data: msg }))
      }));
    } catch (_) { /* Gone → se limpiará en $disconnect */ }
  }));

  return { statusCode: 200 };
};
