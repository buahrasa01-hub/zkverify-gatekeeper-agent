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

Deployed on Vercel (free Hobby plan, project
`zkverify-gatekeeper-agent`, account buahrasa01@gmail.com).
Public URL: https://zkverify-gatekeeper-agent-buahrasa01.vercel.app
(the bare `zkverify-gatekeeper-agent.vercel.app` belongs to someone
else — do NOT register that one).
Serverless adapter: `api/agent.ts` (thin wrapper around
`src/agent.ts`) + `api/healthz.ts`. `vercel.json` uses legacy
`builds` + `routes` (see "Packaging" — zero-config and `rewrites`
do NOT work for this repo, proven across 6 deployments).

- **10 s Hobby function limit vs the platform's 60 s deadline.**
  The handler budget is capped at 8 s (`HANDLER_BUDGET_MS`, min(env,
  8500 ms)). Local proof generation is ~0.4 s warm / ~1.2 s cold
  (fresh process, first call), preflight ~3 ms — far inside the
  budget. Kurier NEVER blocks the response: the in-path call is
  forced off and the proof is submitted fire-and-forget as a
  floating promise after the response body is built (best effort;
  `proof_tx` is optional and the platform re-verifies the local
  proof offline). No `waitUntil()`: a Kurier job rarely reaches
  Finalized inside the 10 s budget anyway.
- **No secrets until configured.** With no
  `AGENT_GAMES_HMAC_SECRET` the function still starts and answers
  `/healthz`, while `POST /agent` returns 401 `agent not
  configured`. No placeholder is ever accepted as real.
- **Packaging (important).** Vercel's Node runtime does NOT bundle
  with esbuild — it traces files with nft and ships them as-is, so
  `snarkjs` (and its `web-worker` dependency, which uses dynamic
  `require("url")`) loads natively. Do NOT "optimise" this into a
  single esbuild ESM bundle: that breaks at import time
  (`Dynamic require of "url" is not supported`). The `circuits/`
  artifacts (~2 MB: wasm 1.76 MB + zkey 310 KB + vk.json 5 KB)
  ship via `includeFiles` in each build entry's `config` (they are
  read from disk at runtime, never traced as imports).
  `CIRCUITS_DIR` resolves to `<project-root>/circuits` on Vercel.
  The seen-store lives at `/tmp/seen-proof-tx.json` there (the
  function filesystem is read-only except `/tmp`); reuse
  protection is per-instance plus that file.
  - **Zero-config does NOT work for this repo.** The "node"
    framework's `@vercel/backends` builder detects `src/server.ts`
    (well-known filename list: app/index/server/main at root or
    in `src/`) as a root entrypoint and builds ONE server lambda,
    ignoring `api/` entirely; that lambda exits(1) without the
    HMAC secret, so every request 500s. Removing `main` from
    `package.json` does not help — the filename match comes first.
    `framework: null` is worse: static-only mode, no functions at
    all (`STATIC_BUILD_NO_OUT_DIR`).
  - **Legacy `builds` is the working path.** `vercel.json`
    declares `builds` for `api/agent.ts` + `api/healthz.ts` with
    `@vercel/node` (includeFiles/maxDuration live in each build
    entry's `config` — the top-level `functions` key CANNOT be
    combined with `builds`). In builds mode the functions are
    served at their LITERAL src paths, extension included
    (`/api/agent.ts`, `/api/healthz.ts`); the `rewrites` key is
    ignored there, so clean paths need legacy `routes` mapping
    `/agent` → `/api/agent.ts` and `/healthz` →
    `/api/healthz.ts` (verified live).
  - **Deployment Protection (SSO) must stay OFF.** New projects
    default to `ssoProtection: all_except_custom_domains`, which
    302-redirects every unauthenticated request to a Vercel login
    page — the ZkVerify platform cannot log in. It was disabled
    via the API (`PATCH /v9/projects/{id} {"ssoProtection": null}`).
- **Kurier (proven live 17 Nov).** The submit shape in
  `src/kurier.ts` was verified with a real Groth16 proof:
  HTTP 200, jobId returned, optimisticVerify "success" — do not
  change it. The job-STATUS endpoint is unreliable: it answers
  401 "Unauthorized or disabled API key" even for a real jobId
  with a proven-valid key. Never use it as an auth probe or a
  polling source; the agent already catches a Kurier failure and
  falls back to the incoming `proof_tx` while still answering
  with the local proof. A "kurier submission failed, falling back
  to incoming proof_tx" warning in the logs is expected
  behaviour, not a deploy failure.
- **Env vars — set in the Vercel dashboard** (Project → Settings →
  Environment Variables; Production). Never in the repo (`.env` is
  gitignored; `.env.example` ships blank values):

  | Variable | Required | Value source |
  |---|---|---|
  | `AGENT_GAMES_HMAC_SECRET` | Yes | ZkVerify dashboard → Rotate Secret (one-time plaintext). Without it `/agent` 401s. |
  | `KURIER_API_KEY` | No | https://kurier.xyz mainnet dashboard (free signup). Unset = no Kurier submission; the agent still answers with its local proof. |
  | `KURIER_MODE` | No | `off` disables even the background Kurier submission. Unset = background submission runs when a key is set. |
  | `SEEN_STORE_PATH` | No | Defaults to `/tmp/seen-proof-tx.json` on Vercel. |
  | `HANDLER_BUDGET_MS` | No | Defaults to 8000; capped at 8500 here regardless. |

- **Cold start (measured on Vercel, secret unset).** `GET /healthz`
  1.12 s cold / 1.13 s warm; `POST /agent` (401 unconfigured
  branch, short-circuits before proving) 1.48 s cold / 1.11 s
  warm. One outlier: the first-ever invocation of an earlier
  deployment took 10.05 s cold. The first REAL `/agent` call
  (secret set, local Groth16 proof) has NOT been measured on
  Vercel yet — local numbers say proof ~1 s, so it should land
  well inside 10 s, but treat it as unverified until preflight
  runs.
- The endpoint must be a public HTTPS URL registered with its full
  handler path (`/agent`, not the root).
- After deploy: register the endpoint in the ZkVerify dashboard,
  Rotate Secret, set it as `AGENT_GAMES_HMAC_SECRET`, restart, run
  preflight (must pass), then at least one practice task before a
  scored round. Rounds run daily 17:30–03:30 WIB (8 tasks/round).

## File layout

```
api/agent.ts            Vercel serverless adapter (HMAC, budget cap,
                        Kurier fire-and-forget, 401 until configured)
api/healthz.ts          Vercel GET /healthz (signed when configured)
vercel.json             legacy builds (api/*.ts) + routes /agent + /healthz
                        (zero-config + rewrites do NOT work here — see above)
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
