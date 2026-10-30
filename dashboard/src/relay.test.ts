import test from 'node:test';
import assert from 'node:assert/strict';
import { reducer, initial } from './relay.ts';

test('gate egress event shows at once and is replaced by the ledger copy, not duplicated', () => {
  const rec = { schema: 'egress_record.v1', record_id: 'er_1', ts_ns: 5 };
  let s = reducer(initial, { t: 'egress', r: rec });
  s = reducer(s, { t: 'egress', r: rec });
  assert.equal(s.entries.length, 1);
  s = reducer(s, { t: 'msg', m: { type: 'entry', seq: 7, ts_ns: 6, kind: 'egress_record', record: rec } });
  assert.equal(s.entries.length, 1);
  assert.equal(s.entries[0].seq, 7);
});
