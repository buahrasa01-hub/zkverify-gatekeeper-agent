// Local Groth16 proof generation with snarkjs.
//
// Circuit facts (verified by the operator via direct wasm/zkey
// inspection, 17 Nov 2026 — see README.md "Circuit input layout"):
//   - Groth16 / bn128, Circom 2.x, template GatekeeperEvaluation_79.
//   - Verification key: nPublic = 13 (circuits/gatekeeper.vk.json).
//   - Exactly 13 scalar input signals:
//       minimum, publicBalance, expiryBlock, currentBlock, recipient,
//       conditionRecipient, amount, maxTransfer, taskId,
//       registeredVkHash, proofVkHash, decision, salt
//   - Public signals (13, output-then-public order):
//       [OUT, registeredVkHash, proofVkHash, minimum,
//        publicBalance, expiryBlock, currentBlock, recipient,
//        conditionRecipient, amount, maxTransfer, decision, taskId]
//     where OUT is the circuit output — a deterministic function of
//     the `salt` input ONLY (verified: changing salt changes OUT;
//     changing recipient/amount/decision does not). `salt` itself is
//     private (does not appear in public signals).
//   - The circuit enforces decision == (all checks pass): a wrong
//     decision throws "Assert Failed ... GatekeeperEvaluation_79
//     line: 102" at witness generation — no witness, no proof. Callers
//     must treat a throw as fail-closed, never retry with the other
//     decision.
//
// Value encodings (documented assumptions — flagged in README.md):
//   - Addresses / vk strings: vkStringToField = BigInt(hex) mod FIELD_PRIME.
//     The sample envelope truncates the 0x vk strings, so their true
//     length is unknown; this derivation is a single swappable function.
//   - taskId: first run of digits in the task id string ("gk_24_9d1" -> 24);
//     if there are no digits, SHA-256 of the string mod FIELD_PRIME.
//   - salt: fresh random field element per task (blinding).

import { randomBytes, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { groth16, type Groth16Proof } from "snarkjs";

/** bn128 scalar field prime. */
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export interface CircuitInputs {
  minimum: string;
  publicBalance: string;
  expiryBlock: string;
  currentBlock: string;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  taskId: string;
  registeredVkHash: string;
  proofVkHash: string;
  decision: string;
  salt: string;
}

/** ASSUMPTION (see README.md): 0x hex string -> field element. */
export function vkStringToField(hex: string): bigint {
  const cleaned = hex.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(cleaned)) {
    throw new Error(`vkStringToField: not a 0x hex string: ${hex}`);
  }
  return BigInt(cleaned) % FIELD_PRIME;
}

/** ASSUMPTION (see README.md): task id -> field element. */
export function taskIdToField(taskId: string): bigint {
  const match = taskId.match(/\d+/);
  if (match) return BigInt(match[0]) % FIELD_PRIME;
  const digest = createHash("sha256").update(taskId, "utf-8").digest();
  return BigInt("0x" + digest.toString("hex")) % FIELD_PRIME;
}

export function randomSalt(): bigint {
  let salt = BigInt("0x" + randomBytes(32).toString("hex")) % FIELD_PRIME;
  if (salt === 0n) salt = 1n;
  return salt;
}

function circuitsDir(): string {
  if (process.env.CIRCUITS_DIR) return process.env.CIRCUITS_DIR;
  // src/prover.ts compiles to dist/prover.js; circuits/ sits at repo root.
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "circuits");
}

let cachedVk: unknown | null = null;

export async function loadVerificationKey(): Promise<unknown> {
  if (cachedVk) return cachedVk;
  const raw = await readFile(join(circuitsDir(), "gatekeeper.vk.json"), "utf-8");
  cachedVk = JSON.parse(raw) as unknown;
  return cachedVk;
}

export interface GeneratedProof {
  proof: Groth16Proof;
  publicSignals: string[];
}

/** Generate a Groth16 proof for the given circuit inputs. Throws on
 *  witness assert failure (wrong decision) or any snarkjs error. */
export async function generateProof(
  inputs: CircuitInputs
): Promise<GeneratedProof> {
  const dir = circuitsDir();
  const { proof, publicSignals } = await groth16.fullProve(
    inputs as unknown as Record<string, unknown>,
    join(dir, "gatekeeper.wasm"),
    join(dir, "gatekeeper_final.zkey")
  );
  return { proof, publicSignals };
}

/** Verify a proof locally against the exported verification key. */
export async function verifyProofLocally(
  proof: Groth16Proof,
  publicSignals: string[]
): Promise<boolean> {
  const vk = await loadVerificationKey();
  return groth16.verify(vk, publicSignals, proof);
}
