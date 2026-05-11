# cyber-mini

A minimal AI-agent activity monitor. Reads a stream of LLM provider events (OpenAI / Anthropic), evaluates each one against a YAML policy, appends a tamper-evident audit log, and raises an incident alert when a single actor accumulates enough risk.

I use claude code for quick bug fixes, project setup, hash-chained creation and decision.csv save, writting all tests, readme file generation. 

I use gemini to check APIs and code exmaples, also gemini explained to me how this project works.  

---

## How to run

### Prerequisites

- Node.js 22+
- `npm install`

### Run 

```bash
npm run dev
```

Reads `events.jsonl` and `policies.yaml` from the working directory. Writes:

| File | Contents |
|---|---|
| `audit.log` | One JSON record per event, SHA-256 hash-chained |
| `decisions.csv` | `event_id,verdict,rule_id` for incident-threshold events |
| stderr | `INCIDENT` lines when an actor's cumulative risk score ≥ 70 |

### Tests

```bash
npm test
```

Uses Node's built-in `node:test` runner via `tsx`. No extra test framework needed.

---

## Architecture

```
events.jsonl
     │
     ▼
 normalizer.ts      Translates raw OpenAI / Anthropic shapes → AgentAction
     │
     ▼
  policy.ts         Evaluates AgentAction against policies.yaml rules → Decision
     │
     ├──► audit.ts  Builds SHA-256 hash-chained AuditRecord, appends to audit.log
     │
     └──► risk.ts   Accumulates per-actor risk score, fires INCIDENT at threshold
```

### `AgentAction` — the internal canonical type

Both providers use different field names for the same concepts:

| Concept | OpenAI | Anthropic | Normalized |
|---|---|---|---|
| Actor identity | `actor.user` | `actor.email` | `actor` (string) |
| Tool event kind | `tool.call` | `tool.use` | kept as-is, matched by normalizer |
| Tool name | `payload.tool` | `payload.name` | `tool` |
| Tool args | `payload.args` | `payload.input` | `args` / `path` / `url` extracted |
| Chat input | `payload.messages` | `payload.input` | serialised into `payload_text` |

`payload_text` is a lowercased JSON string of the raw payload — used by `payload_contains_any` regex matching without needing to know the provider's payload shape.

### Policy evaluation (`policy.ts`)

Rules are evaluated in priority order: `block` → `sanitize` → `allow`. First match wins. If no rule matches, the verdict is always `block` (hard-coded default-deny — `policy.default` in the YAML documents intent but is not read by the evaluator).

Rule conditions are ANDed:

| Condition | Meaning |
|---|---|
| `kind` | Exact match on event kind |
| `payload_contains_any` | Any pattern (regex or substring) matches `payload_text` |
| `tool_in` | Tool name is in the given list |
| `url_host_not_in` | URL hostname is **not** in the allowlist (fires on external hosts) |
| `path_prefix_any` | File path starts with any of the given prefixes |

**`url_host_not_in` is a double-negative.** The condition name reads as "when the host is not in this list" — meaning the rule fires (and blocks) for *external* hosts. When the host *is* in the allowlist, this condition causes the rule to be skipped. Without an explicit `allow` rule downstream, even whitelisted URLs would still default-block. The tests in `cyber-mini.test.ts` pin this behaviour.

### Audit chain (`audit.ts`)

Each `AuditRecord` carries the SHA-256 hash of its own fields (excluding `hash`) and the hash of the previous record (`prev_hash`). The first record chains to `GENESIS_HASH` (64 zeros). Mutating any field — verdict, actor, timestamp — produces a different hash, breaking the chain at that point.

### Risk scoring (`risk.ts`)

In-memory, per-actor cumulative score. Score increments per verdict:

| Verdict | Points |
|---|---|
| `block` | +40 |
| `sanitize` | +10 |
| `allow` | +0 |

An actor reaching 70 points triggers an `INCIDENT` on stderr. Score resets on process restart (in-memory only).

---

## Design choices

**Block action after 2 high-risk action.** block could be set as 30 to give non-technical user more tolerance.

**YAML policy, not code.** Rules live in `policies.yaml` so they can be changed without a recompile. The policy schema is intentionally flat — one level of conditions, no nested logic — to keep it readable by non-engineers.

**`payload_text` as a lowercased JSON blob.** Rather than writing separate extractors for every provider's payload shape, all regex/substring matching runs against a single serialised string. It loses structure but keeps the matching logic provider-agnostic.

**Block-first evaluation order.** The evaluator checks `block` rules before `sanitize` before `allow`. This means a `block` rule always wins over an `allow` rule on the same action, which is the safe default for a security tool.


---

## What was cut

- **`policy.default` is ignored.** The YAML field exists and documents intent, but `evaluate()` always falls through to a hard-coded `block`. Wiring it up would add two lines but wasn't needed to make the pipeline correct.
- **No chain-verification CLI.** There is no tool to walk `audit.log` and verify the hash chain end-to-end. `computeHash` is exported and tested; the CLI wrapper was out of scope.
- **Risk scores don't persist.** Restarting the process resets all actor scores. A production version would checkpoint scores to disk or a KV store.
- **`decisions.csv` has no header row.** The format is `event_id,verdict,rule_id` but no column headers are written. Easy to add; skipped to keep `main.ts` minimal.
- **No streaming output for `sanitize`.** The sanitized `payload_text` is updated in memory but the sanitized version is not re-emitted anywhere. The audit record captures the pre-sanitize verdict; a downstream system would need to act on the mutated action.


## notes

- **`why block prompt injection` Because an attacker can hijack the agent's content and make it exfiltrate data.
- **`why block egress to unknown hosts` Because approved APIs are known-good; anything else is a potential data exfiltration path.
- **`why sanitize PII` Because auditi log itself is a liability if it stores raw SSNs.

---

## Time spent

| Section | Time |
|---|---|
| Project setup (TypeScript, tsconfig, scripts) | ~5 min(AI) |
| `types.ts` + `normalizer.ts` | ~20 min |
| `policy.ts` (rule engine + sanitizer) | ~50 min |
| `audit.ts` (hash chain) | ~55 min |
| `risk.ts` (score accumulator) | ~10 min |
| `main.ts` (pipeline wiring) | ~15 min |
| Tests (`cyber-mini.test.ts`) | ~5 min(AI) |
| README | ~15 min (AI+Manual) |
| **Total** | **~3 hours** |

---

## Screen Recording (3-hour session proof)

- https://youtu.be/fiwplPZ7SxU?si=LfuIKvicyVrx3Ob2
- https://youtu.be/hMHg_Q7aKBw?si=3eOaAqZKRsNbyD2D
