// Persistent seen-set for proof references (PROOF_REUSED detection).
//
// A proof reference (proof_tx) that was already answered must be rejected
// on re-submission. The set lives in memory and is persisted to a JSON
// file (array of lowercase hex strings) with atomic write (tmp + rename)
// so a crash cannot leave a half-written file. Writes are serialised
// through a promise chain because concurrent tasks must not race.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export class SeenStore {
  private readonly filePath: string;
  private readonly seen = new Set<string>();
  private writeChain: Promise<void> = Promise.resolve();

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  static normalise(proofTx: string): string {
    return proofTx.trim().toLowerCase();
  }

  async load(): Promise<void> {
    try {
      const raw = await readFile(this.filePath, "utf-8");
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (typeof entry === "string" && entry.length > 0) {
            this.seen.add(SeenStore.normalise(entry));
          }
        }
      }
    } catch (err) {
      // Missing file on first run is normal; anything else is logged and
      // treated as an empty set (fail open on persistence only — the
      // in-memory set still protects this process lifetime).
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        console.error(
          JSON.stringify({
            level: "error",
            msg: "seen-store load failed, starting empty",
            error: String(err),
          })
        );
      }
    }
  }

  has(proofTx: string): boolean {
    return this.seen.has(SeenStore.normalise(proofTx));
  }

  size(): number {
    return this.seen.size;
  }

  /** Record a proof_tx and persist. Resolves even if persistence fails
   *  (the in-memory set is updated first); the failure is logged. */
  record(proofTx: string): Promise<void> {
    const key = SeenStore.normalise(proofTx);
    if (key.length === 0) return Promise.resolve();
    this.seen.add(key);
    this.writeChain = this.writeChain
      .then(() => this.persist())
      .catch((err: unknown) => {
        console.error(
          JSON.stringify({
            level: "error",
            msg: "seen-store persist failed",
            error: String(err),
          })
        );
      });
    return this.writeChain;
  }

  private async persist(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmpPath = `${this.filePath}.tmp-${process.pid}`;
    const data = JSON.stringify([...this.seen].sort(), null, 2);
    await writeFile(tmpPath, data, "utf-8");
    await rename(tmpPath, this.filePath);
  }
}
