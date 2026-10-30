import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { auditLog, inclusionFor, parseSth, Tree, leafHash, verifyConsistency, unhex } from './audit.ts';

const dir = new URL('./fixtures/audit/', import.meta.url);
const lines = readFileSync(new URL('seg-00000001.jsonl', dir), 'utf8').trim().split('\n');
const sthTexts = readFileSync(new URL('sth.jsonl', dir), 'utf8').trim().split('\n');
const pub = readFileSync(new URL('ledger.pub', dir), 'utf8').trim();
const byseq = () => new Map(lines.map((l, i) => [i + 1, l]));
const sths = () => sthTexts.map((t) => parseSth(t)!);

// Fixture written by the C++ ledger (ledgerd + pl-audit verify OK): the browser must agree with it.
test('browser verifies the C++ ledger heads: signature, root, consistency', async () => {
  const r = await auditLog(byseq(), sths(), pub);
  assert.equal(r.complete, true);
  assert.equal(r.heads.length, 3);
  for (const h of r.heads) { assert.equal(h.signature, true); assert.equal(h.root, true); }
  assert.deepEqual(r.heads.map((h) => h.consistent), [null, true, true]);
});

test('inclusion proof for every entry verifies', async () => {
  const r = await auditLog(byseq(), sths(), pub);
  for (let s = 1; s <= lines.length; s++) assert.equal((await inclusionFor(r.tree!, s, lines.length)).ok, true);
});

test('wrong key, tampered entry and tampered head are caught', async () => {
  assert.equal((await auditLog(byseq(), sths(), 'aa'.repeat(32))).heads[0]!.signature, false);
  const bad = byseq(); bad.set(2, bad.get(2)!.replace('"seq":2', '"seq":9'));
  const r = await auditLog(bad, sths(), pub);
  assert.ok(r.heads.some((h) => h.root === false));
  const forged = sths(); forged[0]!.root = forged[1]!.root;
  assert.equal((await auditLog(byseq(), forged, pub)).heads[0]!.signature, false);
});

test('incomplete backlog is reported, not silently accepted', async () => {
  const part = new Map([...byseq()].filter(([s]) => s > 2));
  const r = await auditLog(part, sths(), pub);
  assert.equal(r.complete, false);
  assert.equal(r.heads[0]!.root, null);
});

test('consistency verifier rejects a wrong old root', async () => {
  const t = new Tree(await Promise.all(Array.from({ length: 9 }, (_, i) => leafHash(`e${i}`))));
  const p = await t.consistency(5, 9);
  assert.equal(await verifyConsistency(5, 9, await t.root(5), await t.root(9), p), true);
  assert.equal(await verifyConsistency(5, 9, unhex('00'.repeat(32)), await t.root(9), p), false);
});
