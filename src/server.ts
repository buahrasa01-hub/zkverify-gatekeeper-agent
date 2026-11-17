// HTTP server for the Proof Gatekeeper agent.
//
// Routes:
//   GET  /healthz  -> {"ok":true} (signed, like every 2xx response)
//   POST /agent    -> task + preflight handling (see agent.ts)
//   anything else  -> 404 / 405 JSON (unsigned — errors are not signed)
//
// Startup requirements (fail fast, clear errors):
//   - AGENT_GAMES_HMAC_SECRET must be set (the platform-generated secret
//     from dashboard "Rotate Secret"). Refusing to start without it is
//     deliberate: an unsigned or wrongly-signed endpoint fails preflight.
//   - circuits/gatekeeper.wasm, circuits/gatekeeper_final.zkey and
//     circuits/gatekeeper.vk.json must exist and the vk must load.
//   - The seen-store file is loaded (missing file = first run, empty set).
//
// Env vars:
//   PORT (default 3000), HOST (default 0.0.0.0)
//   AGENT_GAMES_HMAC_SECRET (required)
//   KURIER_API_KEY (optional; unset = Kurier skipped)
//   KURIER_MODE (mock | live | off; unset = live iff key set, else off)
//   SEEN_STORE_PATH (default data/seen-proof-tx.json)
//   CIRCUITS_DIR (default <repoRoot>/circuits)
//   HANDLER_BUDGET_MS (default 50000)

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { handleAgent, signBody, HMAC_HEADER, type AgentContext } from "./agent.js";
import { SeenStore } from "./seenStore.js";
import { loadVerificationKey } from "./prover.js";

const MAX_BODY_BYTES = 1_000_000;

function log(level: string, msg: string, extra: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ level, msg, ...extra }));
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
        reject(Object.assign(new Error("body too large"), { code: "BODY_TOO_LARGE" }));
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

async function main(): Promise<void> {
  const hmacSecret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!hmacSecret) {
    console.error(
      "FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start: " +
        "the platform secret comes from dashboard Rotate Secret."
    );
    process.exit(1);
  }

  const circuitsDir =
    process.env.CIRCUITS_DIR ?? join(process.cwd(), "circuits");
  for (const file of ["gatekeeper.wasm", "gatekeeper_final.zkey", "gatekeeper.vk.json"]) {
    if (!existsSync(join(circuitsDir, file))) {
      console.error(`FATAL: missing circuit artifact: ${join(circuitsDir, file)}`);
      process.exit(1);
    }
  }
  try {
    const vk = (await loadVerificationKey()) as { nPublic?: unknown };
    log("info", "verification key loaded", { nPublic: vk.nPublic });
  } catch (err) {
    console.error(`FATAL: cannot load verification key: ${String(err)}`);
    process.exit(1);
  }

  const seenStore = new SeenStore(
    process.env.SEEN_STORE_PATH ?? join(process.cwd(), "data", "seen-proof-tx.json")
  );
  await seenStore.load();
  log("info", "seen store loaded", { entries: seenStore.size() });

  const ctx: AgentContext = {
    hmacSecret,
    seenStore,
    handlerBudgetMs: process.env.HANDLER_BUDGET_MS
      ? Number(process.env.HANDLER_BUDGET_MS)
      : 50_000,
  };

  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? "0.0.0.0";

  const server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      try {
        if (url.pathname === "/healthz" && req.method === "GET") {
          sendJson(res, 200, JSON.stringify({ ok: true }), true, ctx);
          return;
        }
        if (url.pathname === "/agent") {
          if (req.method !== "POST") {
            res.writeHead(405, {
              "content-type": "application/json",
              allow: "POST",
            });
            res.end(JSON.stringify({ error: "method not allowed" }));
            return;
          }
          let raw: Buffer;
          try {
            raw = await readRawBody(req);
          } catch (err) {
            const code = (err as NodeJS.ErrnoException).code;
            if (code === "BODY_TOO_LARGE") {
              sendJson(res, 413, JSON.stringify({ error: "body too large" }), false);
            } else {
              sendJson(res, 400, JSON.stringify({ error: "cannot read body" }), false);
            }
            return;
          }
          const headers: Record<string, string | string[] | undefined> = {};
          for (const [k, v] of Object.entries(req.headers)) headers[k] = v;
          const result = await handleAgent(ctx, raw, headers);
          sendJson(res, result.status, result.body, result.sign, ctx);
          return;
        }
        sendJson(res, 404, JSON.stringify({ error: "not found" }), false);
      } catch (err) {
        log("error", "unhandled server error", { error: String(err) });
        if (!res.headersSent) {
          sendJson(res, 500, JSON.stringify({ error: "internal error" }), false);
        }
      }
    })();
  });

  server.listen(port, host, () => {
    log("info", "gatekeeper agent listening", { host, port });
  });

  const shutdown = () => {
    log("info", "shutting down");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err: unknown) => {
  console.error(`FATAL: ${String(err)}`);
  process.exit(1);
});
