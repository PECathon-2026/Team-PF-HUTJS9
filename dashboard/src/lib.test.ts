import test from 'node:test';
import assert from 'node:assert/strict';
import { computeCounters, splitPlaceholders, fmtBytes } from './lib.ts';

test('splitPlaceholders marks placeholders', () => {
  const s = splitPlaceholders('card [REDACTED:CARD#3] ok');
  assert.deepEqual(s.map((x) => x.placeholder), [false, true, false]);
});

test('computeCounters counts verdicts and rules', () => {
  const c = computeCounters([
    { type: 'entry', seq: 1, ts_ns: 1, kind: 'egress_record', record: { verdict: 'sent', lane: 'ai', bytes_out: 10, checks: [] } },
    { type: 'entry', seq: 2, ts_ns: 2, kind: 'egress_record', record: { verdict: 'blocked', lane: 'ai', bytes_out: 5, checks: [{ check: 'canary', result: 'fail', rule_id: 'GT-002' }] } },
    { type: 'entry', seq: 3, ts_ns: 3, kind: 'decision_record', record: { verdict: 'block', rule_id: 'LG-001' } },
  ]);
  assert.equal(c.sent, 1);
  assert.equal(c.blocked, 1);
  assert.equal(c.bytesOut, 15);
  assert.equal(c.rules['GT-002'], 1);
  assert.equal(c.decisions['block'], 1);
});

test('fmtBytes', () => assert.equal(fmtBytes(2048), '2.0 KB'));
