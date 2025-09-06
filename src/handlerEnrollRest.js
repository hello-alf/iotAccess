import crypto from "crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const ddb  = new DynamoDBClient({});
const doc  = DynamoDBDocumentClient.from(ddb);
const USERS_TABLE = process.env.USERS_TABLE;
const NFC_SECRET  = process.env.NFC_SECRET || "demo-secret";

const json = (code, body) => ({ statusCode: code, headers: { "Content-Type":"application/json" }, body: JSON.stringify(body) });
const safeJson = (s) => { try { return JSON.parse(s || "{}"); } catch { return {}; } };
const nfcHash = (uidHex) =>
  "nfc:hmac256:" + crypto.createHmac("sha256", NFC_SECRET)
    .update(String(uidHex).trim().toLowerCase())
    .digest("base64url");

export const handler = async (event) => {
  
  const claims = event.requestContext?.authorizer?.jwt?.claims || {};
  const tokenUserId = claims.sub;
  const pathUserId  = event.pathParameters?.userId;
  if (!tokenUserId) return json(401, { error: "unauthorized" });
  if (pathUserId && pathUserId !== tokenUserId) return json(403, { error: "forbidden_different_user" });

  const { uidHex, label } = safeJson(event.body);
  if (!uidHex) return json(400, { error: "uidHex requerido" });

  const userId = tokenUserId;          // canónico
  const hash   = nfcHash(uidHex);
  const now    = new Date().toISOString();

  const { Item: user } = await doc.send(new GetCommand({
    TableName: USERS_TABLE, Key: { userId }
  }));

  if (!user) {
    await doc.send(new PutCommand({
      TableName: USERS_TABLE,
      Item: { userId, createdAt: now, nfc: [] }
    }));
  } else {
    const list = Array.isArray(user.nfc) ? user.nfc : [];
    if (list.some(c => c?.hash === hash && (c?.status ?? "ACTIVE") === "ACTIVE")) {
      return json(409, { error: "tag_ya_asignado" });
    }
  }

  await doc.send(new UpdateCommand({
    TableName: USERS_TABLE,
    Key: { userId },
    UpdateExpression: "SET #nfc = list_append(if_not_exists(#nfc, :empty), :card), updatedAt = :now",
    ExpressionAttributeNames: { "#nfc": "nfc" },
    ExpressionAttributeValues: {
      ":empty": [],
      ":card": [{ hash, label: label || "", status: "ACTIVE", createdAt: now }],
      ":now": now
    }
  }));

  return json(201, { ok: true, userId, hash });
};