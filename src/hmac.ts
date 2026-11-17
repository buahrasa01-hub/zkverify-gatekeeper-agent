// HMAC-SHA256 signing / verification for the Agent Games protocol.
// The platform signs every inbound request with `x-agent-games-signature`
// (hex HMAC over the RAW request body) and expects every response signed
// the same way over the raw response body. Verification happens BEFORE
// any JSON parsing. Comparison is timing-safe.
import { createHmac, timingSafeEqual } from "node:crypto";

export const HMAC_HEADER = "x-agent-games-signature";

export function hmacSign(secret: string, body: Buffer | string): string {
  const data = typeof body === "string" ? Buffer.from(body, "utf-8") : body;
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function hmacVerify(
  secret: string,
  body: Buffer | string,
  headerValue: string | undefined
): boolean {
  if (!headerValue) return false;
  const expectedHex = hmacSign(secret, body);
  let provided: Buffer;
  try {
    provided = Buffer.from(headerValue.trim(), "hex");
  } catch {
    return false;
  }
  const expected = Buffer.from(expectedHex, "hex");
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}
