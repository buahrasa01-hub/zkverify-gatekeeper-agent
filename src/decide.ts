// Deterministic decision logic for Proof Gatekeeper tasks.
//
// The circuit (GatekeeperEvaluation) enforces `decision == (all checks
// pass)` at witness-generation time: a wrong decision throws an assert
// instead of producing a proof (verified locally). This module mirrors
// those checks in plain code so the decision and the proof can never
// disagree. No LLM, no model, no randomness here — only field checks.
//
// Check order (first failure wins; reason codes match the event page's
// trap encyclopedia):
//   1. VK_SUBSTITUTION    proof_vk != registered_vk
//   2. THRESHOLD_MISMATCH  public_balance < minimum
//   3. PROOF_REUSED        proof_tx already in the local seen-set
//   4. EXPIRED_CONDITION   current_block > expiry_block
//   5. RECIPIENT_MISMATCH  recipient != condition_recipient
//   6. AMOUNT_OVERFLOW     amount > max_transfer
//   7. otherwise APPROVE / VALID_CONDITION
//
// Envelope-shape problems (missing fields, unparseable numbers, a
// deadline that already passed) are INVALID_ENVELOPE and are decided by
// the caller (agent.ts), not here — this function only runs on a
// structurally valid task.

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "INVALID_ENVELOPE"
  | "PROOF_GENERATION_FAILED"
  | "INTERNAL_ERROR";

export interface TaskInput {
  registeredVk: string;
  proofVk: string;
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: string;
  conditionRecipient: string;
  amount: bigint;
  maxTransfer: bigint;
  proofTx: string;
}

export interface DecisionResult {
  decision: Decision;
  reasonCode: ReasonCode;
}

function normAddr(addr: string): string {
  return addr.trim().toLowerCase();
}

export function decideTask(
  input: TaskInput,
  isProofTxSeen: (proofTx: string) => boolean
): DecisionResult {
  if (normAddr(input.proofVk) !== normAddr(input.registeredVk)) {
    return { decision: "REJECT", reasonCode: "VK_SUBSTITUTION" };
  }
  if (input.publicBalance < input.minimum) {
    return { decision: "REJECT", reasonCode: "THRESHOLD_MISMATCH" };
  }
  if (isProofTxSeen(input.proofTx)) {
    return { decision: "REJECT", reasonCode: "PROOF_REUSED" };
  }
  if (input.currentBlock > input.expiryBlock) {
    return { decision: "REJECT", reasonCode: "EXPIRED_CONDITION" };
  }
  if (normAddr(input.recipient) !== normAddr(input.conditionRecipient)) {
    return { decision: "REJECT", reasonCode: "RECIPIENT_MISMATCH" };
  }
  if (input.amount > input.maxTransfer) {
    return { decision: "REJECT", reasonCode: "AMOUNT_OVERFLOW" };
  }
  return { decision: "APPROVE", reasonCode: "VALID_CONDITION" };
}
