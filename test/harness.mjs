// Local test harness for the Proof Gatekeeper agent.
//
// Starts the compiled server (dist/server.js must exist — run
// `npm run build` first) on test ports with test secrets, replays sample
// envelopes, and checks decisions, proofs (snarkjs local verification),
// preflight signatures, and Kurier mock/off behaviour.
//
// Usage: npm test
// Exit code 0 = all PASS, 1 = any FAIL. Always calls process.exit()
// explicitly: snarkjs leaves worker threads alive, so a plain Node
// process would hang after the run (verified behaviour).

import { spawn, spawnSync } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const TEST_SECRET = "test-hmac-secret-do-not-use";
const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const vk = JSON.parse(
  fs.readFileSync(path.join(REPO, "circuits", "gatekeeper.vk.json"), "utf-8")
);

let passed = 0;
let failed = 0;
const failures = [];

function check(name, ok, detail = "") {
  if (ok) {
    passed++;
    console.log(`PASS ${name}${detail ? " — " + detail : ""}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

function sign(secret, rawBody) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

function verifySig(secret, rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = Buffer.from(sign(secret, rawBody), "hex");
  let provided;
  try {
    provided = Buffer.from(headerValue.trim(), "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

async function post(port, body, { signBody = true, secret = TEST_SECRET, raw = null } = {}) {
  const rawBody = raw ?? Buffer.from(JSON.stringify(body), "utf-8");
  const headers = { "content-type": "application/json" };
  if (signBody) headers["x-agent-games-signature"] = sign(secret, rawBody);
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: "POST",
    headers,
    body: rawBody,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  return { status: res.status, json, text, sig: res.headers.get("x-agent-games-signature") };
}

async function get(port, pathName) {
  const res = await fetch(`http://127.0.0.1:${port}${pathName}`);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  return { status: res.status, json, sig: res.headers.get("x-agent-games-signature") };
}

async function waitHealthy(port, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (res.status === 200) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

function startServer(port, envExtra) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-seen-"));
  const seenPath = path.join(tmpDir, "seen.json");
  const child = spawn(process.execPath, ["dist/server.js"], {
    cwd: REPO,
    env: {
      ...process.env,
      PORT: String(port),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      SEEN_STORE_PATH: seenPath,
      ...envExtra,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => process.stdout.write(`[server:${port}] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[server:${port} ERR] ${d}`));
  return { child, seenPath, tmpDir };
}

async function stopServer(server) {
  if (server.child.exitCode === null) {
    server.child.kill("SIGTERM");
    await new Promise((resolve) => {
      const t = setTimeout(resolve, 5000);
      server.child.once("exit", () => {
        clearTimeout(t);
        resolve();
      });
    });
    if (server.child.exitCode === null) server.child.kill("SIGKILL");
  }
  fs.rmSync(server.tmpDir, { recursive: true, force: true });
}

function baseEnvelope(overrides = {}, inputOverrides = {}) {
  const now = new Date();
  const deadline = new Date(now.getTime() + 10 * 60_000);
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    issued_at: now.toISOString(),
    deadline_at: deadline.toISOString(),
    input: {
      registered_vk: "0x7d3a00000000000000000000000000000000f291",
      proof_vk: "0x7d3a00000000000000000000000000000000f291",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0xDe420000000000000000000000000000009f01",
      condition_recipient: "0xDe420000000000000000000000000000009f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1000000000000000000000000000000008ff1",
      ...inputOverrides,
    },
    ...overrides,
  };
}

function vkField(hex) {
  return (BigInt(hex) % FIELD_PRIME).toString();
}

async function verifyReturnedProof(name, body) {
  if (!body || typeof body.proof !== "object" || !Array.isArray(body.public_signals)) {
    check(`${name}: proof present`, false, "missing proof/public_signals");
    return false;
  }
  check(`${name}: 13 public signals`, body.public_signals.length === 13,
    `got ${body.public_signals.length}`);
  let ok = false;
  try {
    ok = await groth16.verify(vk, body.public_signals, body.proof);
  } catch (e) {
    check(`${name}: snarkjs verify`, false, String(e).split("\n")[0]);
    return false;
  }
  check(`${name}: snarkjs verify`, ok === true);
  return ok;
}

function checkPubSigLayout(name, body, env) {
  const ps = body.public_signals;
  if (!Array.isArray(ps) || ps.length !== 13) return;
  // Index 0 is the circuit output: a deterministic function of the salt
  // ONLY (verified: varying salt changes it; varying recipient/amount
  // does not). It is not a constant and cannot be predicted from the
  // task — assert only that it is a valid field element.
  const out0ok =
    typeof ps[0] === "string" &&
    /^\d+$/.test(ps[0]) &&
    BigInt(ps[0]) < FIELD_PRIME;
  check(`${name}: public signal [0] is a field element`, out0ok, String(ps[0]).slice(0, 20) + "…");
  const inp = env.input;
  const expected = [
    null, // [0]: salt-derived output, checked above
    vkField(inp.registered_vk),
    vkField(inp.proof_vk),
    String(BigInt(inp.minimum)),
    String(BigInt(inp.public_balance)),
    String(BigInt(inp.expiry_block)),
    String(BigInt(inp.current_block)),
    BigInt(inp.recipient).toString(),
    BigInt(inp.condition_recipient).toString(),
    String(BigInt(inp.amount)),
    String(BigInt(inp.max_transfer)),
    body.decision === "APPROVE" ? "1" : "0",
    "24",
  ];
  const badIdx = ps.findIndex((v, i) => i > 0 && v !== expected[i]);
  check(
    `${name}: public signals [1..12] echo inputs`,
    badIdx === -1,
    badIdx === -1 ? "" : `mismatch at ${badIdx}: got ${ps[badIdx]}, want ${expected[badIdx]}`
  );
}

async function main() {
  if (!fs.existsSync(path.join(REPO, "dist", "server.js"))) {
    console.error("dist/server.js not found — run `npm run build` first.");
    process.exit(1);
  }

  // Server A: Kurier mock mode. Server B: no Kurier key at all (off).
  const serverA = startServer(18099, { KURIER_MODE: "mock" });
  const serverB = startServer(18100, { KURIER_MODE: "off" });
  const upA = await waitHealthy(18099);
  const upB = await waitHealthy(18100);
  check("server A healthy", upA);
  check("server B healthy", upB);
  if (!upA || !upB) {
    await stopServer(serverA);
    await stopServer(serverB);
    console.log(`\nSUMMARY: ${passed} passed, ${failed} failed`);
    process.exit(1);
  }

  // 0. healthz + routing
  const hz = await get(18099, "/healthz");
  check("GET /healthz -> 200 {ok:true}", hz.status === 200 && hz.json && hz.json.ok === true);
  check("healthz response is signed", verifySig(TEST_SECRET, JSON.stringify({ ok: true }), hz.sig));
  const m405 = await fetch("http://127.0.0.1:18099/agent", { method: "GET" });
  check("GET /agent -> 405", m405.status === 405);
  const nf = await get(18099, "/nope");
  check("GET /nope -> 404", nf.status === 404);

  // 1. Preflight (valid signature)
  const preBody = {
    type: "agent-games.preflight.v1",
    agent_id: "agt_test",
    issued_at: new Date().toISOString(),
    nonce: "abc123",
  };
  const pre = await post(18099, preBody);
  check("preflight valid -> 200 ok:true v1", pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === "v1");
  check(
    "preflight response signature verifies",
    verifySig(TEST_SECRET, JSON.stringify({ ok: true, protocolVersion: "v1" }), pre.sig)
  );
  const preBad = await post(18099, preBody, { secret: "wrong-secret" });
  check("preflight wrong signature -> 401", preBad.status === 401);

  // 2. Valid APPROVE (server A, Kurier mock) — measure wall time.
  const envApprove = baseEnvelope();
  const t0 = Date.now();
  const ap = await post(18099, envApprove);
  const approveMs = Date.now() - t0;
  check("APPROVE -> 200", ap.status === 200, `status ${ap.status}`);
  check(
    "APPROVE decision VALID_CONDITION",
    ap.json && ap.json.decision === "APPROVE" && ap.json.reason_code === "VALID_CONDITION",
    JSON.stringify(ap.json && { d: ap.json.decision, r: ap.json.reason_code })
  );
  check("APPROVE wall time < 50s", approveMs < 50_000, `${approveMs} ms`);
  console.log(`INFO APPROVE wall time: ${approveMs} ms`);
  await verifyReturnedProof("APPROVE", ap.json);
  checkPubSigLayout("APPROVE", ap.json, envApprove);
  check(
    "APPROVE (mock Kurier) carries mock proof_tx",
    typeof ap.json.proof_tx === "string" && ap.json.proof_tx.includes("mock"),
    String(ap.json && ap.json.proof_tx)
  );
  check(
    "APPROVE response signature verifies",
    verifySig(TEST_SECRET, JSON.stringify(ap.json), ap.sig)
  );

  // 3. VK_SUBSTITUTION
  const envVk = baseEnvelope({}, {
    proof_vk: "0xa4c100000000000000000000000000000000b8ff",
    proof_tx: "0xa4c1000000000000000000000000000000008ff2",
  });
  const vkRes = await post(18099, envVk);
  check("VK_SUBSTITUTION -> REJECT", vkRes.json && vkRes.json.decision === "REJECT" && vkRes.json.reason_code === "VK_SUBSTITUTION");
  await verifyReturnedProof("VK_SUBSTITUTION", vkRes.json);
  checkPubSigLayout("VK_SUBSTITUTION", vkRes.json, envVk);

  // 4. THRESHOLD_MISMATCH
  const envTh = baseEnvelope({}, { public_balance: "500", proof_tx: "0xa4c1000000000000000000000000000000008ff3" });
  const th = await post(18099, envTh);
  check("THRESHOLD_MISMATCH -> REJECT", th.json && th.json.decision === "REJECT" && th.json.reason_code === "THRESHOLD_MISMATCH");
  await verifyReturnedProof("THRESHOLD_MISMATCH", th.json);

  // 5. PROOF_REUSED — resend the APPROVE task's proof_tx.
  const reused = await post(18099, envApprove);
  check(
    "PROOF_REUSED -> REJECT, no proof fields",
    reused.json && reused.json.decision === "REJECT" &&
      reused.json.reason_code === "PROOF_REUSED" &&
      !("proof" in reused.json) && !("public_signals" in reused.json),
    JSON.stringify(reused.json)
  );

  // 6. EXPIRED_CONDITION
  const envEx = baseEnvelope({}, { current_block: 19843000, proof_tx: "0xa4c1000000000000000000000000000000008ff4" });
  const ex = await post(18099, envEx);
  check("EXPIRED_CONDITION -> REJECT", ex.json && ex.json.decision === "REJECT" && ex.json.reason_code === "EXPIRED_CONDITION");
  await verifyReturnedProof("EXPIRED_CONDITION", ex.json);

  // 7. RECIPIENT_MISMATCH
  const envRm = baseEnvelope({}, {
    condition_recipient: "0xBeef00000000000000000000000000000000beef",
    proof_tx: "0xa4c1000000000000000000000000000000008ff5",
  });
  const rm = await post(18099, envRm);
  check("RECIPIENT_MISMATCH -> REJECT", rm.json && rm.json.decision === "REJECT" && rm.json.reason_code === "RECIPIENT_MISMATCH");
  await verifyReturnedProof("RECIPIENT_MISMATCH", rm.json);

  // 8. AMOUNT_OVERFLOW
  const envAo = baseEnvelope({}, { amount: "1500", proof_tx: "0xa4c1000000000000000000000000000000008ff6" });
  const ao = await post(18099, envAo);
  check("AMOUNT_OVERFLOW -> REJECT", ao.json && ao.json.decision === "REJECT" && ao.json.reason_code === "AMOUNT_OVERFLOW");
  await verifyReturnedProof("AMOUNT_OVERFLOW", ao.json);

  // 9. Bad HMAC on a task -> 401
  const badHmac = await post(18099, baseEnvelope({}, { proof_tx: "0xa4c1000000000000000000000000000000008ff7" }), { secret: "wrong-secret" });
  check("task bad HMAC -> 401", badHmac.status === 401);

  // 10. Malformed JSON -> 400
  const badJson = await post(18099, null, { raw: Buffer.from("{not json", "utf-8") });
  check("malformed JSON -> 400", badJson.status === 400);

  // 11. No-Kurier-key server still answers, proof_tx echoes incoming.
  const envOff = baseEnvelope({}, { proof_tx: "0xa4c1000000000000000000000000000000008ff8" });
  const off = await post(18100, envOff);
  check(
    "no-key server APPROVE, proof_tx echoes incoming",
    off.json && off.json.decision === "APPROVE" && off.json.proof_tx === envOff.input.proof_tx,
    JSON.stringify(off.json && { d: off.json.decision, tx: off.json.proof_tx })
  );
  await verifyReturnedProof("no-key APPROVE", off.json);

  // 12. INVALID_ENVELOPE (missing input) -> REJECT, no proof.
  const badEnv = { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_1" };
  const inv = await post(18099, badEnv);
  check(
    "INVALID_ENVELOPE -> REJECT, no proof",
    inv.json && inv.json.decision === "REJECT" && inv.json.reason_code === "INVALID_ENVELOPE" && !("proof" in inv.json),
    JSON.stringify(inv.json)
  );

  await stopServer(serverA);
  await stopServer(serverB);

  console.log(`\nSUMMARY: ${passed} passed, ${failed} failed`);
  if (failed > 0) console.log("FAILED:", failures.join(", "));
  // snarkjs leaves worker threads alive — exit explicitly.
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("HARNESS CRASH:", err);
  process.exit(1);
});
