import type { Verdict } from "./types.js";

export const INCIDENT_THRESHOLD = 70;
export const SCORE_INCREMENT: Record<Verdict, number> = {
  block: 40,
  sanitize: 10,
  allow: 0,
};

const scores = new Map<string, number>();

export function updateScore(actor: string, verdict: Verdict): number {
  const next = (scores.get(actor) ?? 0) + SCORE_INCREMENT[verdict];
  scores.set(actor, next);
  return next;
}
