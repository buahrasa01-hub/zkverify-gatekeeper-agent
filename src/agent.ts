// /agent request orchestration.
//
// Flow per task (60 s platform deadline; 50 s internal budget):
//   1. Verify HMAC over the RAW body BEFORE parsing (401 on mismatch).
//   2. Parse JSON (400 on malformed).
//   3. Preflight envelope -> {ok:true, protocolVersion:"v1"} (signed).
//   4. Task envelope: validate shape + deadline -> INVALID_ENVELOPE
//      (signed REJECT, no proof) on any problem. FAIL CLOSED everywhere:
//      any error, timeout or uncertainty -> REJECT, never APPROVE.
//   5. Deterministic decision (decide.ts).
//   6. PROOF_REUSED -> REJECT with no proof (the circuit cannot prove a
//      REJECT for an otherwise-valid task — verified behaviour).
//   7. Else generate the Groth16 proof, verify it locally, then submit
//      to Kurier (bounded by the remaining budget). A Kurier failure
//      never fails the task: proof_tx falls back to the incoming
//      proof_tx (the platform re-verifies the local proof offline).
//   8. Sign the response over its raw body.
// On ANY unexpected error the handler returns a signed REJECT with
// reason_code INTERNAL_ERROR (HTTP 200) — never a 500, never a timeout.

import { HMAC_HEADER, hmacSign, hmacVerify } from "./hmac.js";
import { decideTask, type ReasonCode, type TaskInput } from "./decide.js";
import type { SeenStore } from "./seenStore.js";
import {
  generateProof,
  randomSalt,
  taskIdToField,
  verifyProofLocally,
  vkStringToField,
  type CircuitInputs,
} from "./prover.js";
import { submitProofToKurier } from "./kurier.js";

export interface AgentContext {
  hmacSecret: string;
  seenStore: SeenStore;
  /** Internal response budget in ms (default 50_000). */
  handlerBudgetMs?: number;
}

export interface HandlerResult {
  status: number;
  /** Raw JSON string to send. */
  body: string;
  /** True when the body must carry the HMAC signature header. */
  sign: boolean;
}

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";

function toBigInt(value: unknown, field: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`field ${field} is not a non-negative integer`);
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new Error(`field ${field} is not a non-negative integer string`);
    }
    return BigInt(trimmed);
  }
  throw new Error(`field ${field} has an unsupported type`);
}

function toNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`field ${field} must be a non-empty string`);
  }
  return value.trim();
}

function isHexAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]+$/.test(value.trim());
}

function parseTaskInput(envelope: Record<string, unknown>): {
  task: TaskInput;
  taskId: string;
} {
  if (envelope.type !== TASK_TYPE) {
    throw new Error(`unexpected type: ${String(envelope.type)}`);
  }
  const taskId = toNonEmptyString(envelope.task_id, "task_id");
  const input = envelope.input;
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("input must be an object");
  }
  const inp = input as Record<string, unknown>;
  const registeredVk = toNonEmptyString(inp.registered_vk, "registered_vk");
  const proofVk = toNonEmptyString(inp.proof_vk, "proof_vk");
  const recipient = toNonEmptyString(inp.recipient, "recipient");
  const conditionRecipient = toNonEmptyString(
    inp.condition_recipient,
    "condition_recipient"
  );
  for (const [field, value] of [
    ["registered_vk", registeredVk],
    ["proof_vk", proofVk],
    ["recipient", recipient],
    ["condition_recipient", conditionRecipient],
  ] as const) {
    if (!isHexAddress(value)) {
      throw new Error(`field ${field} must be a 0x hex string`);
    }
  }
  return {
    task: {
      registeredVk,
      proofVk,
      minimum: toBigInt(inp.minimum, "minimum"),
      publicBalance: toBigInt(inp.public_balance, "public_balance"),
      expiryBlock: toBigInt(inp.expiry_block, "expiry_block"),
      currentBlock: toBigInt(inp.current_block, "current_block"),
      recipient,
      conditionRecipient,
      amount: toBigInt(inp.amount, "amount"),
      maxTransfer: toBigInt(inp.max_transfer, "max_transfer"),
      proofTx: toNonEmptyString(inp.proof_tx, "proof_tx"),
    },
    taskId,
  };
}

function toCircuitInputs(
  task: TaskInput,
  taskId: string,
  decision: "APPROVE" | "REJECT"
): CircuitInputs {
  return {
    minimum: task.minimum.toString(),
    publicBalance: task.publicBalance.toString(),
    expiryBlock: task.expiryBlock.toString(),
    currentBlock: task.currentBlock.toString(),
    recipient: BigInt(task.recipient).toString(),
    conditionRecipient: BigInt(task.conditionRecipient).toString(),
    amount: task.amount.toString(),
    maxTransfer: task.maxTransfer.toString(),
    taskId: taskIdToField(taskId).toString(),
    registeredVkHash: vkStringToField(task.registeredVk).toString(),
    proofVkHash: vkStringToField(task.proofVk).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: randomSalt().toString(),
  };
}

function signed(
  ctx: AgentContext,
  status: number,
  payload: Record<string, unknown>
): HandlerResult {
  const body = JSON.stringify(payload);
  void ctx;
  return { status, body, sign: true };
}

function signBody(ctx: AgentContext, body: string): string {
  return hmacSign(ctx.hmacSecret, Buffer.from(body, "utf-8"));
}

export { signBody, HMAC_HEADER };

export async function handleAgent(
  ctx: AgentContext,
  rawBody: Buffer,
  headers: Record<string, string | string[] | undefined>
): Promise<HandlerResult> {
  const startedAt = Date.now();
  const budgetMs = ctx.handlerBudgetMs ?? 50_000;
  const deadlineMs = startedAt + budgetMs;

  // 1. HMAC first, before any parsing.
  const headerRaw = headers[HMAC_HEADER.toLowerCase()];
  const signature = Array.isArray(headerRaw) ? headerRaw[0] : headerRaw;
  if (!hmacVerify(ctx.hmacSecret, rawBody, signature)) {
    return {
      status: 401,
      body: JSON.stringify({ error: "invalid signature" }),
      sign: false,
    };
  }

  // 2. Parse JSON.
  let envelope: unknown;
  try {
    envelope = JSON.parse(rawBody.toString("utf-8")) as unknown;
  } catch {
    return {
      status: 400,
      body: JSON.stringify({ error: "malformed json" }),
      sign: false,
    };
  }
  if (typeof envelope !== "object" || envelope === null) {
    return {
      status: 400,
      body: JSON.stringify({ error: "envelope must be a JSON object" }),
      sign: false,
    };
  }
  const env = envelope as Record<string, unknown>;

  // 3. Preflight.
  if (env.type === PREFLIGHT_TYPE) {
    return signed(ctx, 200, { ok: true, protocolVersion: "v1" });
  }

  // 4. Task envelope validation.
  let task: TaskInput;
  let taskId = "";
  try {
    const parsed = parseTaskInput(env);
    task = parsed.task;
    taskId = parsed.taskId;
    const deadlineRaw = env.deadline_at;
    if (typeof deadlineRaw === "string" && deadlineRaw.length > 0) {
      const deadlineAt = Date.parse(deadlineRaw);
      if (!Number.isNaN(deadlineAt) && deadlineAt < Date.now()) {
        return rejectNoProof(ctx, "INVALID_ENVELOPE", task.proofTx);
      }
    }
    const issuedRaw = env.issued_at;
    if (typeof issuedRaw === "string" && issuedRaw.length > 0) {
      const issuedAt = Date.parse(issuedRaw);
      if (!Number.isNaN(issuedAt) && issuedAt > Date.now() + 5 * 60_000) {
        return rejectNoProof(ctx, "INVALID_ENVELOPE", task.proofTx);
      }
    }
  } catch {
    // No usable proof_tx here — echo nothing, just the decision.
    return signed(ctx, 200, {
      decision: "REJECT",
      reason_code: "INVALID_ENVELOPE",
    });
  }

  try {
    // 5. Deterministic decision.
    const { decision, reasonCode } = decideTask(task, (tx) =>
      ctx.seenStore.has(tx)
    );

    // Record the proof reference for every decided task (reuse guard).
    // Done before proof generation so a retried task is caught even if
    // this attempt's proof step fails afterwards.
    await ctx.seenStore.record(task.proofTx);

    // 6. PROOF_REUSED carries no proof by circuit design.
    if (reasonCode === "PROOF_REUSED") {
      return signed(ctx, 200, {
        decision,
        reason_code: reasonCode,
        proof_tx: task.proofTx,
      });
    }

    // 7. Generate + locally verify the proof.
    const inputs = toCircuitInputs(task, taskId, decision);
    let proof: Awaited<ReturnType<typeof generateProof>>;
    try {
      proof = await withDeadline(
        generateProof(inputs),
        deadlineMs - 5_000,
        "proof generation"
      );
    } catch {
      return rejectNoProof(ctx, "PROOF_GENERATION_FAILED", task.proofTx);
    }
    if (proof.publicSignals.length !== 13) {
      return rejectNoProof(ctx, "PROOF_GENERATION_FAILED", task.proofTx);
    }
    let verified = false;
    try {
      verified = await withDeadline(
        verifyProofLocally(proof.proof, proof.publicSignals),
        deadlineMs - 5_000,
        "local proof verification"
      );
    } catch {
      verified = false;
    }
    if (!verified) {
      return rejectNoProof(ctx, "PROOF_GENERATION_FAILED", task.proofTx);
    }

    // 8. Kurier submission (bounded by the remaining budget; a failure
    //    never fails the task — the local proof is the evidence).
    let proofTx: string = task.proofTx;
    try {
      const kurier = await submitProofToKurier(
        proof.proof,
        proof.publicSignals,
        deadlineMs - 2_000
      );
      if (kurier.finalized && kurier.proofTx) proofTx = kurier.proofTx;
    } catch (err) {
      console.error(
        JSON.stringify({
          level: "warn",
          msg: "kurier submission failed, falling back to incoming proof_tx",
          error: String(err),
          task_id: taskId,
        })
      );
    }

    return signed(ctx, 200, {
      decision,
      reason_code: reasonCode,
      proof: proof.proof,
      public_signals: proof.publicSignals,
      proof_tx: proofTx,
    });
  } catch (err) {
    // 9. Any unexpected error: fail closed, still a signed 200.
    console.error(
      JSON.stringify({
        level: "error",
        msg: "agent handler unexpected error",
        error: String(err),
      })
    );
    return rejectNoProof(ctx, "INTERNAL_ERROR", task.proofTx);
  }
}

function rejectNoProof(
  ctx: AgentContext,
  reasonCode: ReasonCode,
  proofTx: string | undefined
): HandlerResult {
  const payload: Record<string, unknown> = {
    decision: "REJECT",
    reason_code: reasonCode,
  };
  if (proofTx) payload.proof_tx = proofTx;
  return signed(ctx, 200, payload);
}

async function withDeadline<T>(
  promise: Promise<T>,
  deadlineMs: number,
  label: string
): Promise<T> {
  const remaining = deadlineMs - Date.now();
  if (remaining <= 0) throw new Error(`${label} deadline already passed`);
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} exceeded internal deadline`)),
          remaining
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
