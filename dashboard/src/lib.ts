import type { DecisionRecord, EgressRecord, EntryMsg } from './types.ts';

export const PLACEHOLDER_RE = /(\[REDACTED:[A-Z][A-Z0-9_]{1,23}#[0-9]{1,6}\])/g;

/** Splits text into plain and placeholder segments (placeholders get highlighted). */
export function splitPlaceholders(text: string): { text: string; placeholder: boolean }[] {
  return text.split(PLACEHOLDER_RE).filter((s) => s !== '').map((s) => ({ text: s, placeholder: /^\[REDACTED:/.test(s) }));
}

export interface Counters {
  sent: number; blocked: number; aiSent: number; browsing: number; bytesOut: number;
  decisions: Record<string, number>; rules: Record<string, number>;
}

export function computeCounters(entries: EntryMsg[]): Counters {
  const c: Counters = { sent: 0, blocked: 0, aiSent: 0, browsing: 0, bytesOut: 0, decisions: {}, rules: {} };
  for (const e of entries) {
    if (e.kind === 'egress_record') {
      const r = e.record as EgressRecord;
      if (r.verdict === 'sent') c.sent++; else c.blocked++;
      if (r.lane === 'ai' && r.verdict === 'sent') c.aiSent++;
      if (r.lane === 'browsing') c.browsing++;
      c.bytesOut += r.bytes_out;
      for (const k of r.checks) if (k.rule_id) c.rules[k.rule_id] = (c.rules[k.rule_id] ?? 0) + 1;
    } else if (e.kind === 'decision_record') {
      const d = e.record as DecisionRecord;
      c.decisions[d.verdict] = (c.decisions[d.verdict] ?? 0) + 1;
      c.rules[d.rule_id] = (c.rules[d.rule_id] ?? 0) + 1;
    }
  }
  return c;
}

export function ruleIdsOf(r: EgressRecord, decisions: Map<string, DecisionRecord>): string[] {
  const ids = new Set<string>();
  for (const k of r.checks) if (k.rule_id) ids.add(k.rule_id);
  const d = decisions.get(r.decision_id);
  if (d) ids.add(d.rule_id);
  return [...ids];
}

export function fmtTime(ts_ns: number): string {
  const d = new Date(ts_ns / 1e6);
  return d.toISOString().slice(11, 23);
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
