import crypto from "crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";

const ddb  = new DynamoDBClient({});
const doc  = DynamoDBDocumentClient.from(ddb);
const DOOR_CONFIG_TABLE = process.env.DOOR_CONFIG_TABLE;
const USERS_TABLE       = process.env.USERS_TABLE;
const NFC_SECRET        = process.env.NFC_SECRET || "demo-secret";

function json(statusCode, data) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  };
}

function convertJson(s) {
  try {
    return JSON.parse(s || "{}");
  } catch {
    return {};
  }
}

export const handler = async (event) => {
  const route = `${event.requestContext?.http?.method} ${event.rawPath}`;
  if (route === "POST /api/access/request") return accessRequest(event);
  return json(404, { error: "not_found" });
};

export const accessRequest = async (event) => {
  const claims = event.requestContext?.authorizer?.jwt?.claims || {};
  const userIdFromJwt = claims.sub;
  const body = convertJson(event.body);
  const { doorId, nfcUidHex, userId: userIdFromBody } = body || {};
  const userId = userIdFromJwt || userIdFromBody;

  if (!doorId) {
    return json(400, { error: "doorId requerido" });
  }

  if (!nfcUidHex) {
    return json(400, { error: "nfcUidHex requerido" });
  }

  if (!userId) {
    return json(401, { error: "userId ausente (JWT o body)" });
  }

  const hash = nfcHash(nfcUidHex);
  const user = await getUser(userId);
  if (!user) {
    return json(404, { allowed: false, reason: "user_not_found" });
  }

  if (!userHasNfc(user, hash)) {
    return json(403, { allowed: false, reason: "nfc_not_registered_for_user" });
  }

  const cfg = await loadAccessConfig();

  if (!isOpenNow(cfg)) {
    return json(403, { allowed: false, reason: "out_of_schedule" });
  }

  return json(200, { allowed: true, doorId, userId });
};

async function loadAccessConfig() {
  const { Item } = await doc.send(new GetCommand({
    TableName: DOOR_CONFIG_TABLE,
    Key: { id: "GLOBAL" }
  }));
  if (!Item) throw new Error("Config GLOBAL no encontrada");
  return Item;
}

function isOpenNow(cfg, now = new Date()) {
  const tz = cfg.timeZone || "UTC";
  const local = new Date(now.toLocaleString("en-US", { timeZone: tz }));
  const dayKey = ["sun","mon","tue","wed","thu","fri","sat"][local.getDay()];
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12:false, hour:"2-digit", minute:"2-digit" });
  const { hour, minute } = Object.fromEntries(fmt.formatToParts(now).map(p => [p.type, p.value]));
  const hhmm = `${hour}:${minute}`;
  const ranges = cfg.SCHEDULE?.[dayKey] || [];
  return ranges.some(([from, to]) => from <= hhmm && hhmm <= to);
}

function nfcHash(uidHex) {
  return "nfc:hmac256:" + crypto.createHmac("sha256", NFC_SECRET)
    .update(String(uidHex).trim().toLowerCase())
    .digest("base64url");
}

async function getUser(userId) {
  const { Item } = await doc.send(new GetCommand({
    TableName: USERS_TABLE,
    Key: { userId }
  }));
  return Item || null;
}

function userHasNfc(user, hash) {
  const list = Array.isArray(user.nfc) ? user.nfc : [];
  return list.some(card => card?.hash === hash && (card?.status ?? "ACTIVE") === "ACTIVE");
}