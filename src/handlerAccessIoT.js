import crypto from "crypto";
import { IoTClient, DescribeEndpointCommand } from "@aws-sdk/client-iot";
import { IoTDataPlaneClient, PublishCommand } from "@aws-sdk/client-iot-data-plane";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";

const ddb = new DynamoDBClient({});
const doc = DynamoDBDocumentClient.from(ddb);

const DOOR_CONFIG_TABLE     = process.env.DOOR_CONFIG_TABLE;
const USERS_TABLE           = process.env.USERS_TABLE;
const ACCESS_EVENTS_TABLE   = process.env.ACCESS_EVENTS_TABLE;
const NFC_SECRET            = process.env.NFC_SECRET || "demo-secret";
const RESULT_TOPIC_ALLOWED  = "access/allowed";
const RESULT_TOPIC_DENIED   = "access/denied";

let iotData;

async function iotDataClient() {
  if (iotData) return iotData;
  const iot = new IoTClient({});
  const { endpointAddress } = await iot.send(new DescribeEndpointCommand({ endpointType: "iot:Data-ATS" }));
  iotData = new IoTDataPlaneClient({ endpoint: `https://${endpointAddress}` });
  return iotData;
}

const publish = async (topic, payload) => {
  const client = await iotDataClient();
  await client.send(new PublishCommand({
    topic,
    qos: 1,
    payload: Buffer.from(JSON.stringify(payload))
  }));
};

const nfcHash = (uidHex) =>
  "nfc:hmac256:" + crypto.createHmac("sha256", NFC_SECRET)
    .update(String(uidHex).trim().toLowerCase())
    .digest("base64url");

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
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12: false, hour: "2-digit", minute: "2-digit" });
  const { hour, minute } = Object.fromEntries(fmt.formatToParts(now).map(p => [p.type, p.value]));
  const hhmm = `${hour}:${minute}`;
  const ranges = cfg.SCHEDULE?.[dayKey] || [];
  return ranges.some(([from, to]) => from <= hhmm && hhmm <= to);
}

async function logAccessEvent(evt) {
  const now = new Date();
  const iso = now.toISOString();
  const item = {
    pk: `USER#${evt.userId}`,
    sk: `${iso}#${evt.allowed ? "ALLOW" : "DENY"}`,
    userId:   evt.userId,
    email:    evt.email || null,
    doorId:   evt.doorId || "-",
    result:   evt.allowed ? "ALLOW" : "DENY",
    reason:   evt.reason,
    httpStatus: 0,
    nfcHash: evt.nfcHash,
    createdAt: iso
  };
  await doc.send(new PutCommand({ TableName: ACCESS_EVENTS_TABLE, Item: item }));
}

export const handler = async (event) => {
  const msg = typeof event === "string" ? JSON.parse(event)
            : event?.payload ? JSON.parse(Buffer.from(event.payload, "base64").toString("utf8"))
            : event;

  const userId = msg?.userId;
  const uidHex  = msg?.uidHex;
  const doorId  = msg?.doorId;
  const email   = msg?.email || null;

  const ctx = { userId, uidHex, doorId, email, nfcHash: uidHex ? nfcHash(uidHex) : null };

  const deny = async (reason) => {
    await logAccessEvent({ ...ctx, allowed: false, reason });
    await publish(RESULT_TOPIC_DENIED, { userId, doorId, reason });
    return { ok: false };
  };

  const allow = async () => {
    await logAccessEvent({ ...ctx, allowed: true, reason: "ok" });
    await publish(RESULT_TOPIC_ALLOWED, { userId, doorId, granted: true });
    return { ok: true };
  };

  if (!userId || !uidHex) return deny("missing_fields");

  const user = await getUser(userId);
  if (!user) return deny("user_not_found");

  if (!userHasNfc(user, ctx.nfcHash)) return deny("nfc_not_registered_for_user");

  const cfg = await loadAccessConfig();
  if (!isOpenNow(cfg)) return deny("out_of_schedule");

  return allow();
};