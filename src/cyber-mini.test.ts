import { test } from "node:test";
import assert from "node:assert/strict";
import { normalize } from "./normalizer.js";
import { evaluate } from "./policy.js";
import { computeHash, GENESIS_HASH } from "./audit.js";
import type { Policy, AuditRecord } from "./types.js";

// 1. Normalizer: OpenAI vs Anthropic shapes produce the same AgentAction structure

test("normalizer: OpenAI tool.call and Anthropic tool.use map to the same fields", () => {
  const openaiRaw = {
    id: "e3",
    provider: "openai",
    ts: "2026-05-08T15:00:10Z",
    actor: { user: "alice@acme.io" },
    kind: "tool.call",
    payload: { tool: "http_request", args: { url: "https://api.acme.io/customers", method: "GET" } },
  };
  const anthropicRaw = {
    id: "e6",
    provider: "anthropic",
    ts: "2026-05-08T15:00:25Z",
    actor: { email: "alice@acme.io" },
    kind: "tool.use",
    payload: { name: "http_request", input: { url: "https://api.acme.io/customers", method: "POST" } },
  };

  const a = normalize(openaiRaw);
  const b = normalize(anthropicRaw);

  assert.equal(a.actor, "alice@acme.io");
  assert.equal(b.actor, "alice@acme.io");
  assert.equal(a.tool, "http_request");
  assert.equal(b.tool, "http_request");
  assert.equal(a.url, "https://api.acme.io/customers");
  assert.equal(b.url, "https://api.acme.io/customers");
  assert.deepEqual(Object.keys(a).sort(), Object.keys(b).sort());
});

test("normalizer: OpenAI uses actor.user, Anthropic uses actor.email, both land on actor", () => {
  const openai = normalize({
    id: "e1", provider: "openai", ts: "2026-05-08T15:00:00Z",
    actor: { user: "alice@acme.io" },
    kind: "chat.completion",
    payload: { messages: [] },
  });
  const anthropic = normalize({
    id: "e2", provider: "anthropic", ts: "2026-05-08T15:00:05Z",
    actor: { email: "bob@acme.io" },
    kind: "messages.create",
    payload: { input: [] },
  });

  assert.equal(openai.actor, "alice@acme.io");
  assert.equal(anthropic.actor, "bob@acme.io");
  assert.equal(openai.tool, null);
  assert.equal(anthropic.tool, null);
});

// 2. Default-deny: no rule matches → verdict is always "block"

test("evaluate: empty rules always returns block regardless of policy.default", () => {
  const policy: Policy = { version: 1, default: "allow", rules: [] };
  const action = normalize({
    id: "x1", provider: "openai", ts: "2026-05-08T15:00:00Z",
    actor: { user: "test@acme.io" },
    kind: "chat.completion",
    payload: { messages: [{ role: "user", content: "hello" }] },
  });

  const decision = evaluate(action, policy);
  assert.equal(decision.verdict, "block");
  assert.equal(decision.matched_rule, "default");
});

// 3. Hash chain: mutating any field on a record produces a different hash

test("computeHash: mutating a field produces a different hash (tamper detection)", () => {
  const partial: Omit<AuditRecord, "hash"> = {
    event_id: "e1",
    ts: "2026-05-08T15:00:00Z",
    actor: "alice@acme.io",
    verdict: "allow",
    matched_rule: "R-ALLOW-CHAT",
    prev_hash: GENESIS_HASH,
  };

  const original = computeHash(partial);
  const tamperedVerdict = computeHash({ ...partial, verdict: "block" });
  const tamperedActor = computeHash({ ...partial, actor: "eve@evil.com" });
  const tamperedPrevHash = computeHash({ ...partial, prev_hash: "0".repeat(63) + "1" });

  assert.notEqual(original, tamperedVerdict);
  assert.notEqual(original, tamperedActor);
  assert.notEqual(original, tamperedPrevHash);
});

// 4. Tricky: url_host_not_in is a double-negative — the block rule only fires when
//    the host is NOT in the allowlist. When the host IS in the list, the rule is
//    skipped and the action falls through to the next matching rule. Without an
//    explicit allow rule for internal hosts, even whitelisted URLs would default-block.
//    This test pins that both halves of the condition work correctly.

test("evaluate: url_host_not_in blocks external host but skips rule for internal host", () => {
  const policy: Policy = {
    version: 1,
    default: "allow",
    rules: [
      { id: "R-BLOCK-EGRESS", when: { url_host_not_in: ["api.acme.io"] }, then: "block" },
      { id: "R-ALLOW-INTERNAL", when: { tool_in: ["http_request"] }, then: "allow" },
    ],
  };

  const external = normalize({
    id: "ext", provider: "openai", ts: "2026-05-08T15:00:00Z",
    actor: { user: "alice@acme.io" },
    kind: "tool.call",
    payload: { tool: "http_request", args: { url: "https://pastebin.com/raw", method: "POST" } },
  });
  const internal = normalize({
    id: "int", provider: "openai", ts: "2026-05-08T15:00:00Z",
    actor: { user: "alice@acme.io" },
    kind: "tool.call",
    payload: { tool: "http_request", args: { url: "https://api.acme.io/data", method: "GET" } },
  });

  assert.equal(evaluate(external, policy).verdict, "block");
  assert.equal(evaluate(internal, policy).verdict, "allow");
});
