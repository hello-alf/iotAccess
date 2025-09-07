import crypto from "crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { IoTClient, DescribeEndpointCommand } from "@aws-sdk/client-iot";
import { IoTDataPlaneClient, PublishCommand } from "@aws-sdk/client-iot-data-plane";

const ddb = new DynamoDBClient({});
const doc = DynamoDBDocumentClient.from(ddb);

const DOOR_CONFIG_TABLE   = process.env.DOOR_CONFIG_TABLE;
const USERS_TABLE         = process.env.USERS_TABLE;
const ACCESS_EVENTS_TABLE = process.env.ACCESS_EVENTS_TABLE;
const NFC_SECRET          = process.env.NFC_SECRET || "demo-secret";

const RESULT_TOPIC_ALLOWED = "access/allowed";
const RESULT_TOPIC_DENIED  = "access/denied";

let iotData;
async function iotDataClient() {
  if (iotData) return iotData;
  const iot = new IoTClient({});
  const { endpointAddress } = await iot.send(new DescribeEndpointCommand({ endpointType: "iot:Data-ATS" }));
  iotData = new IoTDataPlaneClient({ endpoint: `https://${endpointAddress}` });
  return iotData;
}

async function publish(topic, payload) {
  const client = await iotDataClient();
  await client.send(new PublishCommand({
    topic,
    qos: 1,
    payload: Buffer.from(JSON.stringify(payload))
  }));
}

export function nfcHash(uidHex) {
  return "nfc:hmac256:" + crypto.createHmac("sha256", NFC_SECRET)
    .update(String(uidHex).trim().toLowerCase())
    .digest("base64url");
}

async function loadAccessConfig() {
  const { Item } = await doc.send(new GetCommand({
    TableName: DOOR_CONFIG_TABLE,
    Key: { id: "GLOBAL" }
  }));
  if (!Item) throw new Error("Config GLOBAL no encontrada");
  return Item;
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
  return list.some(c => c?.hash === hash && (c?.status ?? "ACTIVE") === "ACTIVE");
}

function isOpenNow(cfg, now = new Date()) {
  const tz = cfg.timeZone || "UTC";
  const local = new Date(now.toLocaleString("en-US", { timeZone: tz }));
  const dayKey = ["sun","mon","tue","wed","thu","fri","sat"][local.getDay()];
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12: false, hour:"2-digit", minute:"2-digit" });
  const { hour, minute } = Object.fromEntries(fmt.formatToParts(now).map(p => [p.type, p.value]));
  const hhmm = `${hour}:${minute}`;
  const ranges = cfg.SCHEDULE?.[dayKey] || [];
  return ranges.some(([from,to]) => from <= hhmm && hhmm <= to);
}

async function logAccessEvent({
  now = new Date(), userId, email, doorId, uidHex, nfcHash,
  origin = "rest", allowed, reason, http = 0, requestId, sourceIp, userAgent,
}) {
  const iso = now.toISOString();
  const item = {
    pk: `USER#${userId}`,
    sk: `${iso}#${allowed ? "ALLOW" : "DENY"}`,
    userId,
    email: email ?? null,
    doorId: doorId ?? "-",
    result: allowed ? "ALLOW" : "DENY",
    reason,
    httpStatus: http,
    nfcHash,
    uidLast4: uidHex ? String(uidHex).slice(-4) : null,
    origin,
    requestId,
    sourceIp,
    userAgent,
    createdAt: iso,
  };
  await doc.send(new PutCommand({ TableName: ACCESS_EVENTS_TABLE, Item: item }));
}

export async function processAccess({
  userId, uidHex, doorId, email,
  origin = "rest",
  requestId, sourceIp, userAgent,
  publishResult = true,
}) {

  const ctx = { userId, uidHex, doorId, email, nfcHash: uidHex ? nfcHash(uidHex) : null };

  const deny = async (reason) => {
    await logAccessEvent({ ...ctx, origin, allowed: false, reason, http: origin === "rest" ? 403 : 0, requestId, sourceIp, userAgent });
    if (publishResult) await publish(RESULT_TOPIC_DENIED, { userId, doorId, reason, origin });
    return { allowed: false, reason, userId };
  };

  const allow = async () => {
    await logAccessEvent({ ...ctx, origin, allowed: true, reason: "ok", http: origin === "rest" ? 200 : 0, requestId, sourceIp, userAgent });
    if (publishResult) await publish(RESULT_TOPIC_ALLOWED, { userId, doorId, granted: true, origin });
    return { allowed: true, reason: "ok", userId };
  };

  if (!userId || !uidHex) return deny("missing_fields");

  const user = await getUser(userId);
  if (!user) return deny("user_not_found");

  if (!userHasNfc(user, ctx.nfcHash)) return deny("nfc_not_registered_for_user");

  const cfg = await loadAccessConfig();
  if (!isOpenNow(cfg)) return deny("out_of_schedule");

  return allow();
}