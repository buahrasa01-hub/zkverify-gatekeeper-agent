// Kurier client (zkVerify proof verification REST API).
//
// Auth (verified from Kurier's own tutorial, kurier.xyz/docs/tutorial):
// the API key goes IN THE URL PATH —
//   POST {API_URL}/submit-proof/{API_KEY}
//   GET  {API_URL}/job-status/{API_KEY}/{jobId}
// There is no documented header-auth option. The key is NEVER logged.
//
// Submit response: { jobId, optimisticVerify: "success" | ... }.
// If optimisticVerify !== "success" the proof artifacts are bad — stop.
// Status response: { jobId, status, statusId, proofType, txHash, ... }.
// Lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized
// (also: Failed). Poll every 5 s until Finalized or the budget expires.
// On Finalized, txHash is the on-chain transaction hash.
//
// Modes (env KURIER_MODE):
//   mock — no network; returns a fake Finalized job (for tests).
//   off  — Kurier is skipped entirely (default when no key is set).
//   live — real API calls; requires KURIER_API_KEY.
// When KURIER_MODE is unset: live if KURIER_API_KEY is set, else off.
// A missing key in live mode degrades to off with a warning — the task
// must still be answered (the platform re-verifies the local proof
// offline; Kurier only supplies the on-chain audit pointer).

import type { Groth16Proof } from "snarkjs";
import { VK_HASH } from "./prover.js";

export const KURIER_API_URL = "https://api.kurier.xyz/api/v1";

export type KurierMode = "mock" | "live" | "off";

export interface KurierResult {
  jobId: string | null;
  /** On-chain tx hash, only when the job reached Finalized. */
  proofTx: string | null;
  finalized: boolean;
  skipped: boolean;
}

export function resolveKurierMode(): KurierMode {
  const raw = (process.env.KURIER_MODE ?? "").trim().toLowerCase();
  if (raw === "mock" || raw === "live" || raw === "off") return raw;
  if (raw !== "") {
    console.error(
      JSON.stringify({
        level: "warn",
        msg: "unknown KURIER_MODE, falling back to key-based default",
        mode: raw,
      })
    );
  }
  return process.env.KURIER_API_KEY ? "live" : "off";
}

function redactUrl(url: string): string {
  // The key sits in the URL path; never print it.
  return url.replace(/(\/submit-proof\/|\/job-status\/)[^/]+/, "$1<redacted>");
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Kurier POST ${redactUrl(url)} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<unknown>;
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url, { method: "GET" });
  if (!res.ok) {
    throw new Error(`Kurier GET ${redactUrl(url)} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<unknown>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Submit a proof to Kurier and wait (bounded) for Finalized.
 * `deadlineMs` is an epoch-ms budget cap; polling stops at the deadline.
 * Never throws for a skipped/off/mocked submission; throws only on a
 * live-API transport or protocol error (the caller converts that into a
 * fallback to the incoming proof_tx, not a task failure).
 */
export async function submitProofToKurier(
  proof: Groth16Proof,
  publicSignals: string[],
  deadlineMs: number
): Promise<KurierResult> {
  const mode = resolveKurierMode();
  if (mode === "mock") {
    await sleep(50);
    return {
      jobId: "mock-job-finalized",
      proofTx: "0x00000000000000000000000000000000000000000000000000000000mock00",
      finalized: true,
      skipped: false,
    };
  }
  if (mode === "off") {
    return { jobId: null, proofTx: null, finalized: false, skipped: true };
  }
  const apiKey = process.env.KURIER_API_KEY ?? "";
  if (!apiKey) {
    console.error(
      JSON.stringify({
        level: "warn",
        msg: "KURIER_MODE=live but KURIER_API_KEY is empty; skipping Kurier",
      })
    );
    return { jobId: null, proofTx: null, finalized: false, skipped: true };
  }

  const submitUrl = `${KURIER_API_URL}/submit-proof/${encodeURIComponent(apiKey)}`;
  const submitted = (await postJson(submitUrl, {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn128" },
    proofData: { proof, publicSignals, vk: VK_HASH },
  })) as { jobId?: unknown; optimisticVerify?: unknown };
  const jobId =
    typeof submitted.jobId === "string" ? submitted.jobId : null;
  if (!jobId) {
    throw new Error("Kurier submit-proof response has no jobId");
  }
  if (submitted.optimisticVerify !== "success") {
    throw new Error(
      `Kurier optimisticVerify != success: ${String(submitted.optimisticVerify)}`
    );
  }

  // Poll job-status every 5 s until Finalized or the deadline.
  for (;;) {
    if (Date.now() >= deadlineMs) {
      return { jobId, proofTx: null, finalized: false, skipped: false };
    }
    const statusUrl = `${KURIER_API_URL}/job-status/${encodeURIComponent(apiKey)}/${encodeURIComponent(jobId)}`;
    const status = (await getJson(statusUrl)) as {
      status?: unknown;
      txHash?: unknown;
    };
    const state = typeof status.status === "string" ? status.status : "";
    if (state === "Finalized") {
      const txHash =
        typeof status.txHash === "string" ? status.txHash : null;
      return { jobId, proofTx: txHash, finalized: true, skipped: false };
    }
    if (state === "Failed") {
      throw new Error(`Kurier job ${jobId} Failed`);
    }
    const waitMs = Math.min(5000, Math.max(0, deadlineMs - Date.now()));
    if (waitMs <= 0) {
      return { jobId, proofTx: null, finalized: false, skipped: false };
    }
    await sleep(waitMs);
  }
}
