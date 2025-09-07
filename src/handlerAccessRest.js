import crypto from "crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";

const ddb = new DynamoDBClient({});
const doc = DynamoDBDocumentClient.from(ddb);
const DOOR_CONFIG_TABLE = process.env.DOOR_CONFIG_TABLE;
const USERS_TABLE = process.env.USERS_TABLE;
const ACCESS_EVENTS_TABLE = process.env.ACCESS_EVENTS_TABLE;
const NFC_SECRET = process.env.NFC_SECRET || "demo-secret";

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

async function logAccessEvent({
  now, requestId, sourceIp, userAgent,
  allowed, reason, http, userId, uidHex, nfcHash, email
}) {
  const iso = now.toISOString();
  const ttlDays = 30; // opcional: purga automática en 30 días
  const ttl = Math.floor(now.getTime()/1000) + ttlDays*24*3600;

  const item = {
    pk: `USER#${userId}`,
    sk: `${iso}#${allowed ? "ALLOW" : "DENY"}`,
    userId,
    result: allowed ? "ALLOW" : "DENY",
    reason,                   // ok | nfc_not_registered_for_user | out_of_schedule | ...
    httpStatus: http,
    nfcHash,                  // guarda hash (recomendado); si necesitas depurar, añade:
    requestId,
    sourceIp,
    userAgent,
    createdAt: iso,
    email                      // opcional, si está en el JWT
  };

  await doc.send(new PutCommand({
    TableName: ACCESS_EVENTS_TABLE,
    Item: item
  }));
}

export const handler = async (event) => {
  const claims = event.requestContext?.authorizer?.jwt?.claims || {};
  const userIdFromJwt = claims.sub;
  const emailFromJwt = claims.email || null;
  const body = convertJson(event.body);
  const { uidHex, userId: userIdFromBody } = body || {};
  const userId = userIdFromJwt || userIdFromBody;
  console.log("userId:", userId, "uidHex:", uidHex);

  const ctx = {
    now: new Date(),
    requestId: event.requestContext?.requestId,
    sourceIp: event.requestContext?.http?.sourceIp,
    userAgent: event.headers?.["user-agent"] || event.headers?.["User-Agent"],
    userId,
    uidHex: uidHex || null,
    nfcHash: uidHex ? nfcHash(uidHex) : null,
    email: emailFromJwt
  };

  const deny = async (http, reason) => {
    await logAccessEvent({ ...ctx, allowed: false, reason, http });
    return json(http, { allowed: false, error: reason });
  };

  const allow = async () => {
    await logAccessEvent({ ...ctx, allowed: true, reason: "ok", http: 200 });
    return json(200, { allowed: true, userId });
  };

  if (!uidHex) return deny(400, "uidHex_required");
  if (!userId) return deny(401, "userId_missing");

  const user = await getUser(userId);
  if (!user) return deny(404, "user_not_found");

  if (!userHasNfc(user, ctx.nfcHash))
    return deny(403, "nfc_not_registered_for_user");

  const cfg = await loadAccessConfig();
  if (!isOpenNow(cfg))
    return deny(403, "out_of_schedule");

  // OK
  return allow();
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
  const dayKey = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"][local.getDay()];
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12: false, hour: "2-digit", minute: "2-digit" });
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
  console.log("Verificando NFC para el usuario:", user.userId);
  return list.some(card => card?.hash === hash && (card?.status ?? "ACTIVE") === "ACTIVE");
}