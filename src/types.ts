export interface AgentAction {
  event_id: string;
  actor: string;
  provider: string;
  kind: string;
  tool: string | null;
  path: string | null;
  url: string | null;
  payload_text: string | null;
  ts: string;
}

export type Verdict = "allow" | "sanitize" | "block";
export interface PolicyRule {
  id: string;
  when: Record<string, unknown>;
  then: Verdict;
  replace_with?: string;
}

export interface Policy {
  version: number;
  default: "block" | "allow";
  rules: PolicyRule[];
}

export interface Decision {
  verdict: Verdict;
  reason: string;
  matched_rule: string;
}

export interface AuditRecord {
  event_id: string;
  ts: string;
  actor: string;
  verdict: Verdict;
  matched_rule: string;
  hash: string;
  prev_hash: string;
}
