import type { AgentAction, Decision, Policy, PolicyRule } from "./types.js";
// export interface Decision {
//   verdict: Verdict;
//   reason: string;
//   matched_rule: string;
// }
//

function hostMatches(host: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    if (p.startsWith("*.")) return host === p.slice(2) || host.endsWith("." + p.slice(2));
    return host === p;
  });
}

function ruleMatches(rule: PolicyRule, action: AgentAction): boolean {
  if ("kind" in rule.when && action.kind !== rule.when.kind) return false;

  if ("payload_contains_any" in rule.when) {
    const patterns = rule.when.payload_contains_any as string[];
    const text = action.payload_text ?? "";
    const hit = patterns.some((p) => {
      try {
        return new RegExp(p, "i").test(text);
      } catch {
        return text.includes(p.toLowerCase());
      }
    });
    if (!hit) return false;
  }

  if ("tool_in" in rule.when) {
    const tools = rule.when.tool_in as string[];
    if (!action.tool || !tools.includes(action.tool)) return false;
  }

  if ("url_host_not_in" in rule.when) {
    const allowed = rule.when.url_host_not_in as string[];
    let host: string | null = null;
    try {
      host = new URL(action.url!).hostname;
    } catch {}
    if (host && hostMatches(host, allowed)) return false;
  }
  if ("path_prefix_any" in rule.when) {
    const prefixes = rule.when.path_prefix_any as string[];
    if (!action.path || !prefixes.some((p) => action.path!.startsWith(p))) return false;
  }

  return true;
}

export function evaluate(action: AgentAction, policy: Policy): Decision {
  for (const verdict of ["block", "sanitize", "allow"]) {
    for (const rule of policy.rules) {
      if (rule.then === verdict && ruleMatches(rule, action)) {
        return { verdict, reason: `Matched rule ${rule.id}`, matched_rule: rule.id };
      }
    }
  }
  return { verdict: "block", reason: "No matched rule", matched_rule: "default" };
}

export function sanitizePayload(payload: unknown, replaceWith: string): unknown {
  let text = JSON.stringify(payload);
  text = text.replace(/\d{3}-\d{2}-\d{4}/g, replaceWith);
  text = text.replace(/\bssn\b/gi, replaceWith);
  return JSON.parse(text);
}
