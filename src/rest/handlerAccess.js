import { processAccess } from "../accessCore.js";

function json(statusCode, data) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) };
}
const asHttp = (result) => {
  if (result.allowed) return json(200, { allowed: true, userId: result.userId });
  const map = { missing_fields: 400, userId_missing: 401, user_not_found: 404 };
  const status = map[result.reason] ?? 403;
  return json(status, { allowed: false, error: result.reason });
};

export const handler = async (event) => {
  const claims = event.requestContext?.authorizer?.jwt?.claims || {};
  const userIdFromJwt = claims.sub;
  const emailFromJwt = claims.email || null;

  const body = (() => { try { return JSON.parse(event.body || "{}"); } catch { return {}; } })();
  const { uidHex, userId: userIdFromBody, doorId } = body || {};
  const userId = userIdFromJwt || userIdFromBody;

  // ejecuta la lógica compartida y PUBLICA a MQTT
  const result = await processAccess({
    userId,
    uidHex,
    doorId,
    email: emailFromJwt,
    origin: "rest",
    requestId: event.requestContext?.requestId,
    sourceIp: event.requestContext?.http?.sourceIp,
    userAgent: event.headers?.["user-agent"] || event.headers?.["User-Agent"],
    publishResult: true, // <-- REST también emite MQTT
  });

  return asHttp(result);
};