import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";

const dynamoClient = new DynamoDBClient({});
const doc = DynamoDBDocumentClient.from(dynamoClient);
const ACCESS_EVENTS_TABLE = process.env.ACCESS_EVENTS_TABLE;

const json = (status, data) => ({
  statusCode: status,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(data),
});

async function listAll(event) {
  const qs = event.queryStringParameters || {};
  const limit = Math.min(500, Math.max(1, parseInt(qs.limit ?? "200", 10)));

  let items = [];
  let startKey;
  do {
    const page = await doc.send(new ScanCommand({
      TableName: ACCESS_EVENTS_TABLE,
      ExclusiveStartKey: startKey,
      ProjectionExpression:
        "#pk, #sk, createdAt, userId, email, doorId, #res, reason, httpStatus, sourceIp, uidLast4, userAgent, origin",
      ExpressionAttributeNames: {
        "#pk": "pk",
        "#sk": "sk",
        "#res": "result",
      },
    }));
    items = items.concat(page.Items || []);
    startKey = page.LastEvaluatedKey;
  } while (startKey);

  items.sort((a, b) => (a.sk < b.sk ? 1 : a.sk > b.sk ? -1 : 0));

  return json(200, { items: items.slice(0, limit) });
}

export const handler = async (event) => {
  return listAll(event);
};