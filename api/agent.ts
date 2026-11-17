// Vercel serverless adapter for the Proof Gatekeeper agent.
//
// The long-lived server (src/server.ts) refuses to start without
// AGENT_GAMES_HMAC_SECRET; a serverless function must instead start
// unconfigured and fail closed per request. Behaviour:
//   - GET /healthz (see api/healthz.ts) answers {"ok":true} with or
//     without secrets.
//   - POST /agent without AGENT_GAMES_HMAC_SECRET -> 401
//     {"error":"agent not configured"}; it never accepts a placeholder
//     and never crash-loops.
//   - With the secret set, this is a thin wrapper around
//     handleAgent() from src/agent.ts (same HMAC-verify-before-parse,
//     preflight, deterministic decisions, local Groth16 proofs).
//
// Vercel Hobby function timeout is 10 s; the platform deadline is
// 60 s. The response path therefore NEVER waits for Kurier: the
// in-path Kurier call is forced off (KURIER_MODE=off) and, after the
// response body is built, the proof is submitted to Kurier
// fire-and-forget as a floating promise (best effort; proof_tx is
// optional per the spec and the platform re-verifies the local proof
// offline). The handler budget is capped at 8 s (min(env, 8500 ms)).
//
// Env vars (set in the Vercel dashboard, never in the repo):
//   AGENT_GAMES_HMAC_SECRET — required; from the ZkVerify dashboard
//     (Rotate Secret, one-time plaintext).
//   KURIER_API_KEY — optional; from https://kurier.xyz mainnet
//     dashboard (free signup). Unset = no Kurier submission.
//   KURIER_MODE — optional; "off" disables the background Kurier
//     submission entirely. Anything else (or unset) = background
//     submission runs when a key is set.
//   SEEN_STORE_PATH — optional; defaults to /tmp/seen-proof-tx.json
//     on Vercel (the function filesystem is read-only except /tmp).
//   HANDLER_BUDGET_MS — optional; capped at 8500 ms here.

import type { IncomingMessage, ServerResponse } from "node:http";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  handleAgent,
  signBody,
  HMAC_HEADER,
  type AgentContext,
} from "../src/agent.js";
import { SeenStore } from "../src/seenStore.js";
import { loadVerificationKey } from "../src/prover.js";
import { submitProofToKurier } from "../src/kurier.js";
import type { Groth16Proof } from "snarkjs";

export const config = { api: { bodyParser: false } };

const MAX_BODY_BYTES = 1_000_000;
const HANDLER_BUDGET_MS = Math.min(
  Number(process.env.HANDLER_BUDGET_MS ?? 8000),
  8500
);

// The user's KURIER_MODE (if any) is honoured only for the background
// submission. The in-path call is always off in serverless mode so the
// response never waits on Kurier.
const USER_KURIER_MODE = (process.env.KURIER_MODE ?? "").trim().toLowerCase();
process.env.KURIER_MODE = "off";


type CtxState =
  | { kind: "unconfigured" }
  | { kind: "ready"; ctx: AgentContext }
  | { kind: "broken"; error: string };

let ctxPromise: Promise<CtxState> | null = null;

function getContext(): Promise<CtxState> {
  if (!ctxPromise) ctxPromise = initContext();
  return ctxPromise;
}

async function initContext(): Promise<CtxState> {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) {
    console.log(
      JSON.stringify({
        level: "warn",
        msg: "AGENT_GAMES_HMAC_SECRET not set; /agent will 401 until it is configured",
      })
    );
    return { kind: "unconfigured" };
  }
  try {
    // On Vercel the working directory is the project root and the
    // circuits land there via vercel.json includeFiles. Prefer that
    // path; otherwise fall back to prover.ts's own resolution.
    const cwdDir = join(process.cwd(), "circuits");
    if (existsSync(join(cwdDir, "gatekeeper.wasm"))) {
      process.env.CIRCUITS_DIR = cwdDir;
    }
    const vk = (await loadVerificationKey()) as { nPublic?: unknown };
    console.log(
      JSON.stringify({
        level: "info",
        msg: "verification key loaded",
        nPublic: vk.nPublic,
      })
    );
    const seen = new SeenStore(
      process.env.SEEN_STORE_PATH ??
        (process.env.VERCEL
          ? "/tmp/seen-proof-tx.json"
          : join(process.cwd(), "data", "seen-proof-tx.json"))
    );
    await seen.load();
    return {
      kind: "ready",
      ctx: {
        hmacSecret: secret,
        seenStore: seen,
        handlerBudgetMs: HANDLER_BUDGET_MS,
      },
    };
  } catch (err) {
    console.error(
      JSON.stringify({
        level: "error",
        msg: "agent init failed",
        error: String(err),
      })
    );
    return { kind: "broken", error: String(err) };
  }
}

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let rejected = false;
    req.on("data", (chunk: Buffer) => {
      if (rejected) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        rejected = true;
        reject(
          Object.assign(new Error("body too large"), { code: "BODY_TOO_LARGE" })
        );
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!rejected) resolve(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      if (!rejected) reject(err);
    });
  });
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: string,
  sign: boolean,
  ctx?: AgentContext
): void {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  };
  if (sign && ctx) headers[HMAC_HEADER] = signBody(ctx, body);
  res.writeHead(status, headers);
  res.end(body);
}

/** Fire-and-forget Kurier submission of the proof just returned.
 *  Never blocks the response and never throws. The platform
 *  re-verifies the local proof offline; proof_tx is only an optional
 *  on-chain audit pointer. */
function maybeSubmitKurierInBackground(body: string): void {
  if (!process.env.KURIER_API_KEY) return;
  if (USER_KURIER_MODE === "off") return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return;
  }
  if (typeof parsed !== "object" || parsed === null) return;
  const p = parsed as Record<string, unknown>;
  if (typeof p.proof !== "object" || p.proof === null) return;
  if (!Array.isArray(p.public_signals)) return;
  const proof = p.proof as Groth16Proof;
  const publicSignals = p.public_signals as string[];
  const job = submitProofToKurier(
    proof,
    publicSignals,
    Date.now() + 8000,
    "live"
  )
    .then((r) =>
      console.log(
        JSON.stringify({
          level: "info",
          msg: "background kurier result",
          jobId: r.jobId,
          finalized: r.finalized,
          skipped: r.skipped,
        })
      )
    )
    .catch((err: unknown) =>
      console.error(
        JSON.stringify({
          level: "warn",
          msg: "background kurier submission failed",
          error: String(err),
        })
      )
    );
  // Fire-and-forget: the runtime may freeze the instance after the
  // response, so this is best effort only. The response already
  // carries the local proof; proof_tx is only an optional on-chain
  // audit pointer, so a dropped background submit costs nothing.
  // (Deliberately no waitUntil(): the submit rarely reaches
  // Finalized inside the 10 s Hobby budget anyway.)
  job.catch(() => {});
}

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  const started = Date.now();
  if (req.method !== "POST") {
    res.writeHead(405, {
      "content-type": "application/json",
      allow: "POST",
    });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }

  const state = await getContext();
  if (state.kind === "unconfigured") {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        error: "agent not configured: AGENT_GAMES_HMAC_SECRET is not set",
      })
    );
    return;
  }
  if (state.kind === "broken") {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "agent misconfigured" }));
    return;
  }
  const ctx = state.ctx;

  let raw: Buffer;
  try {
    raw = await readRawBody(req);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    res.writeHead(code === "BODY_TOO_LARGE" ? 413 : 400, {
      "content-type": "application/json",
    });
    res.end(
      JSON.stringify({
        error: code === "BODY_TOO_LARGE" ? "body too large" : "cannot read body",
      })
    );
    return;
  }

  const headers: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(req.headers)) headers[k] = v;
  const result = await handleAgent(ctx, raw, headers);

  // Start the background Kurier submission before responding so the
  // work begins while the request is still in flight.
  maybeSubmitKurierInBackground(result.body);

  sendJson(res, result.status, result.body, result.sign, ctx);
  console.log(
    JSON.stringify({
      level: "info",
      msg: "agent request served",
      status: result.status,
      ms: Date.now() - started,
    })
  );
}
