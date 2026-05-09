import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import type { AgentAction, Decision, AuditRecord } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);
export function computeHash(record: Omit<AuditRecord, "hash">): string {
  return createHash("sha256").update(JSON.stringify(record)).digest("hex");
}

// export interface AuditRecord {
//   event_id: string;
//   ts: string;
//   actor: string;
//   verdict: Verdict;
//   matched_rule: string;
//   hash: string;
//   prev_hash: string;
// }
//
let prev_hash = GENESIS_HASH;
export function buildRecord(action: AgentAction, decision: Decision): AuditRecord {
  const partial: Omit<AuditRecord, "hash"> = {
    ts: action.ts,
    event_id: action.event_id,
    actor: action.actor,
    verdict: decision.verdict,
    matched_rule: decision.matched_rule,
    prev_hash,
  };

  const hash = computeHash(partial);
  prev_hash = hash;
  return { ...partial, hash };
}

export function appendRecord(record: AuditRecord, filepath: string): void {
  appendFileSync(filepath, JSON.stringify(record) + "\n");
}
