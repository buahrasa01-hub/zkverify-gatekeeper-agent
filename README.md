# zkVerify Agent Games — Proof Gatekeeper agent

An AI agent endpoint for the **Proof Gatekeeper** event of the
[zkVerify Agent Games](https://agentgames.zkverify.io) (Season 01,
21 Oct – 21 Nov 2026; this track's prize pool: 100,000 VFY —
1st 50,000 / 2nd 30,000 / 3rd 20,000).

The platform POSTs signed payment-request tasks to our public HTTPS
endpoint. The agent checks every field deterministically and replies
APPROVE or REJECT with a Groth16 zero-knowledge proof (generated
locally with snarkjs) that the decision followed the rules. The
platform re-verifies the proof offline against its own registered
verification key. There is no LLM in the decision path: final safety
rules are deterministic code, and any error, timeout or uncertainty
fails closed to REJECT.

## Run locally

```bash
npm install
npm run build
cp .env.example .env   # then fill in AGENT_GAMES_HMAC_SECRET
npm start              # listens on $PORT (default 3000)
```

Required env: `AGENT_GAMES_HMAC_SECRET` (from the ZkVerify dashboard:
Rotate Secret — one-time plaintext; the server refuses to start
without it). Optional: `KURIER_API_KEY` (Kurier mainnet key,
https://kurier.xyz — free signup; unset = Kurier skipped),
`KURIER_MODE` (`mock` | `live` | `off`; unset = live iff a key is set,
else off), `SEEN_STORE_PATH` (default `data/seen-proof-tx.json`),
`CIRCUITS_DIR`, `HANDLER_BUDGET_MS` (default 50000).

Test (starts two throwaway servers on ports 18099/18100 with test
secrets, replays sample envelopes, verifies proofs with snarkjs):

```bash
npm test   # 42 checks; exit 0 = all pass
```

## Endpoints

- `GET /healthz` → `{"ok":true}` (signed).
- `POST /agent` — task + preflight. Every request must carry
  `x-agent-games-signature` (hex HMAC-SHA256 over the RAW request
  body, key `AGENT_GAMES_HMAC_SECRET`); it is verified BEFORE any
  JSON parsing (401 on mismatch). Every 2xx response carries the same
  header over the raw response body. Malformed JSON → 400; wrong
  method → 405; body > 1 MB → 413.

Preflight (`{"type":"agent-games.preflight.v1",...}`) →
`{"ok":true,"protocolVersion":"v1"}` (signed).

## Decision table

| Check (first failure wins) | Result |
|---|---|
| `proof_vk != registered_vk` | REJECT `VK_SUBSTITUTION` |
| `public_balance < minimum` | REJECT `THRESHOLD_MISMATCH` |
| `proof_tx` already answered | REJECT `PROOF_REUSED` (no proof — see below) |
| `current_block > expiry_block` | REJECT `EXPIRED_CONDITION` |
| `recipient != condition_recipient` | REJECT `RECIPIENT_MISMATCH` |
| `amount > max_transfer` | REJECT `AMOUNT_OVERFLOW` |
| all pass | APPROVE `VALID_CONDITION` |

Malformed envelope / missing fields / unparseable numbers / expired
`deadline_at` → REJECT `INVALID_ENVELOPE` (no proof). Any proof
failure → REJECT `PROOF_GENERATION_FAILED` (no proof). Any unexpected
error → REJECT `INTERNAL_ERROR` (never a 500, never a timeout).

Scoring (per the event page): correct decision +12; approving a trap
−6; rejecting a valid request −3; timeout −2; missing/invalid proof
−2; reliability bonus +0..+5. 60 s hard response deadline — the
service enforces a 50 s internal budget; local proof generation takes
~0.3–1.1 s.

## Response schema (resolved)

The event page's `{decision, reason_code, proof_tx}` sample is a
REJECT example; `/build` §01.5/§05 require the Groth16 proof +
`public_signals` on every provable task, and scoring penalises a
missing proof −2. Resolved schema (superset):

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": ["...", "...", "1"], "pi_b": [[...], [...], ["1", "0"]], "pi_c": ["...", "...", "1"], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["...", "..."],
  "proof_tx": "0x..."
}
```

`proof_tx` is the Kurier Finalized transaction hash when available,
otherwise the task's incoming `proof_tx`. `PROOF_REUSED` (and
`INVALID_ENVELOPE` / `PROOF_GENERATION_FAILED`) carry NO `proof` /
`public_signals` fields.

## Circuit input layout (verified by inspection)

Circuit: Groth16 / bn128, Circom 2.x, template
`GatekeeperEvaluation_79`. Verification key
(`circuits/gatekeeper.vk.json`, exported from the shipped zkey):
nPublic = 13. vkHash on zkVerify mainnet:
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

Exactly 13 scalar inputs (found by probing the wasm's input-signal
map via FNV hashes, then confirmed by successful witness + proof +
`groth16.verify` runs):

```
minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, taskId,
registeredVkHash, proofVkHash, decision, salt
```

Public signals (13, output-then-public order):

```
[OUT, registeredVkHash, proofVkHash, minimum, publicBalance,
 expiryBlock, currentBlock, recipient, conditionRecipient,
 amount, maxTransfer, decision, taskId]
```

- `OUT` is the circuit output: a deterministic function of the
  `salt` input ONLY (verified: changing salt changes OUT; changing
  recipient/amount/decision does not). `salt` itself is private.
- Positions 1–12 echo the inputs (asserted by the harness).
- The circuit enforces `decision == (all checks pass)`: a wrong
  decision throws at witness generation
  (`Assert Failed. Error in template GatekeeperEvaluation_79 line: 102`)
  — no witness, no proof. That is why a `PROOF_REUSED` task (all
  circuit-visible checks pass, yet the correct decision is REJECT)
  cannot carry a proof, and why the service fails closed on any
  proof-generation throw.

## Flagged assumptions (verify in practice mode)

These are the service's documented guesses where the public spec is
silent; each is isolated in one function so it can be swapped after
the first practice task:

1. **`vkStringToField`** (`src/prover.ts`): a 0x vk string becomes a
   field element via `BigInt(hex) mod FIELD_PRIME`. The sample
   envelope truncates the vk strings, so their true length/encoding
   is unknown. If the platform expects a different derivation (e.g.
   keccak of the bytes), the public signals will mismatch the task
   even though the proof verifies locally.
2. **`taskIdToField`** (`src/prover.ts`): first digit run of the task
   id (`"gk_24_9d1"` → 24); SHA-256 mod prime if there are no digits.
3. **Kurier vs the 60 s deadline**: the service submits to Kurier
   and polls for Finalized within the remaining budget, but it
   answers with the local proof even if Finalized has not arrived —
   the platform re-verifies that proof offline, and `proof_tx` is
   documented as an optional audit pointer. If the platform instead
   requires Finalized before APPROVE, approvals sent before
   finalization could be scored down; practice mode will show it.
4. **Response schema**: the superset above (proof + public_signals +
   proof_tx) is the best reading of the two conflicting samples; if
   the platform rejects extra fields, drop `proof_tx` on provable
   tasks (it is the only optional one).

## Kurier

Auth is the API key in the URL path (per Kurier's own tutorial):
`POST /submit-proof/{KEY}`, `GET /job-status/{KEY}/{jobId}`.
Submit response: `{jobId, optimisticVerify}` — proceed only on
`"success"`. Poll every 5 s until `Finalized` (`txHash` = on-chain
tx). The gatekeeper vk is already registered on mainnet, so no
`register-vk` call is needed. With no key, Kurier is skipped and the
task is still answered. `KURIER_MODE=mock` returns a fake Finalized
job for tests. The key is never logged (URLs are redacted in logs).

## Deploy notes (Vercel serverless)

- The endpoint must be a public HTTPS URL registered with its full
  handler path (`/agent`, not the root).
- The `circuits/` artifacts (~2 MB: wasm 1.76 MB + zkey 310 KB +
  vk.json 5 KB) must ship with the deployment; snarkjs needs them
  on the local filesystem at runtime.
- Proof generation is CPU-heavy (~1 s locally) but far inside the
  60 s platform deadline; the binding constraint is the serverless
  function's own timeout — use a plan/runtime whose function timeout
  exceeds ~30 s, or the 50 s internal budget is unreachable.
- `snarkjs` leaves worker threads alive: the process does not exit
  on its own after `fullProve` (verified). That is harmless for a
  long-lived server but the test harness calls `process.exit()`
  explicitly.
- Secrets (`AGENT_GAMES_HMAC_SECRET`, `KURIER_API_KEY`) come from
  the deployment environment only — never from the repo. `.env` is
  gitignored; `.env.example` ships blank values.
- After deploy: register the endpoint in the ZkVerify dashboard,
  Rotate Secret, set it as `AGENT_GAMES_HMAC_SECRET`, restart, run
  preflight (must pass), then at least one practice task before a
  scored round. Rounds run daily 17:30–03:30 WIB (8 tasks/round).

## File layout

```
circuits/                 gatekeeper.wasm, gatekeeper_final.zkey, gatekeeper.vk.json
src/server.ts             HTTP server, routing, raw-body capture, startup checks
src/agent.ts              /agent orchestration (HMAC -> decide -> prove -> Kurier -> sign)
src/decide.ts             pure deterministic decision function + reason codes
src/prover.ts             snarkjs wrapper, field helpers, vkStringToField/taskIdToField/salt
src/kurier.ts             Kurier client (mock/live/off), never logs the key
src/hmac.ts               HMAC-SHA256 sign/verify (timing-safe)
src/seenStore.ts          persistent proof_tx seen-set (atomic JSON file)
test/harness.mjs          42-check local test harness (node, no framework)
.env.example              blank env template
```

## Status

Built and locally tested 17 Nov 2026 (42/42 harness checks pass).
NOT competition-ready yet: deployment, dashboard registration,
preflight, and practice tasks are still pending — those need the
platform login + secrets the builder does not hold.
