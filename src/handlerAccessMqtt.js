import { processAccess } from "./accessCore.js";

export const handler = async (event) => {
  const msg = typeof event === "string" ? JSON.parse(event)
            : event?.payload ? JSON.parse(Buffer.from(event.payload, "base64").toString("utf8"))
            : event;

  const { userId, uidHex, doorId, email } = msg || {};

  const result = await processAccess({
    userId, uidHex, doorId, email,
    origin: "mqtt",
    publishResult: true,
  });

  return { ok: result.allowed };
};