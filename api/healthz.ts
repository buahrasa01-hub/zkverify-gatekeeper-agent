// GET /healthz for the Vercel deployment.
// Answers {"ok":true} with or without secrets (signed when the HMAC
// secret is configured, unsigned otherwise — the long-lived server
// signs it, and this matches that behaviour when configured).
import type { IncomingMessage, ServerResponse } from "node:http";
import { hmacSign, HMAC_HEADER } from "../src/hmac.js";

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  if (req.method !== "GET") {
    res.writeHead(405, {
      "content-type": "application/json",
      allow: "GET",
    });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }
  const body = JSON.stringify({ ok: true });
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  };
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (secret) headers[HMAC_HEADER] = hmacSign(secret, body);
  res.writeHead(200, headers);
  res.end(body);
}
