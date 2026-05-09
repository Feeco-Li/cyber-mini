import { createInterface } from "node:readline";
import { createReadStream } from "node:fs";
import { normalize } from "./normalizer.js";
import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import { evaluate, sanitizePayload } from "./policy.js";
import type { Policy } from "./types.js";
import { appendRecord, buildRecord } from "./audit.js";
import { updateScore, INCIDENT_THRESHOLD } from "./risk.js";
import { appendFileSync } from "node:fs";

const policy = yaml.load(readFileSync("policies.yaml", "utf8")) as Policy;

const rl = createInterface({
  input: createReadStream("events.jsonl"),
  crlfDelay: Infinity, // Recognizes all instances of CR LF (\r\n) as a single line break
});

for await (const line of rl) {
  if (!line.trim()) continue;
  const raw = JSON.parse(line);
  const action = normalize(raw);
  const decision = evaluate(action, policy);
  const record = buildRecord(action, decision);
  if (decision.verdict === "sanitize") {
    const rule = policy.rules.find((r) => r.id === decision.matched_rule);
    if (rule?.replace_with && action.payload_text !== null) {
      action.payload_text = JSON.stringify(sanitizePayload(JSON.parse(action.payload_text), rule.replace_with)).toLowerCase();
    }
  }

  appendRecord(record, "audit.log");
  const score = updateScore(action.actor, decision.verdict);
  if (score >= INCIDENT_THRESHOLD) {
    console.error(`InCIDENT actor = ${action.actor} score=${score} event=${action.event_id}\n`);
    // event_id,verdict,rule_id
    appendFileSync("decisions.csv", `${action.event_id},${decision.verdict},${decision.matched_rule}\n`);
  }
}
