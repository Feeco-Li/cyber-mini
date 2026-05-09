import type { AgentAction } from "./types.js";

function extractToolFields(kind: string, payload: any) {
  if (kind === "tool.call") {
    return {
      tool: payload.tool ?? null,
      path: payload.args?.path ?? null,
      url: payload.args?.url ?? null,
    };
  }
  if (kind === "tool.use") {
    return {
      tool: payload.name ?? null,
      path: payload.input?.path ?? null,
      url: payload.input?.url ?? null,
    };
  }

  return { tool: null, path: null, url: null };
}

export function normalize(raw: any): AgentAction {
  const actor = raw.actor.user ?? raw.actor.email ?? "unknown";
  const { tool, path, url } = extractToolFields(raw.kind, raw.payload);

  return {
    event_id: raw.id,
    actor,
    provider: raw.provider,
    kind: raw.kind,
    tool,
    path,
    url,
    payload_text: JSON.stringify(raw.payload).toLowerCase(),
    ts: raw.ts,
  };
}
