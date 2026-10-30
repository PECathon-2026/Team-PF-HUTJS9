// Browser-side verification of the ledger's Merkle log (RFC 6962 / 9162) and Ed25519 signed tree heads.
// Everything here is computed locally from the bytes the ledger streamed; nothing is taken on trust except the
// public key, which the operator should pin out of band (the key in the stream is only a convenience).

export type Bytes = Uint8Array;
export interface Sth { tree_size: number; root: string; ts_ns: string; key_id: string; signature: string; public_key?: string }

const enc = new TextEncoder();
const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

export function hex(b: Bytes): string { return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); }
export function unhex(s: string): Bytes {
  if (!/^([0-9a-f]{2})*$/.test(s)) throw new Error('bad hex');
  return Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
}
function concat(...p: Bytes[]): Bytes {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) { out.set(x, o); o += x.length; }
  return out;
}
async function sha256(b: Bytes): Promise<Bytes> { return new Uint8Array(await subtle().digest('SHA-256', b as BufferSource)); }
export const leafHash = (line: string): Promise<Bytes> => sha256(concat(Uint8Array.of(0), enc.encode(line)));
export const nodeHash = (l: Bytes, r: Bytes): Promise<Bytes> => sha256(concat(Uint8Array.of(1), l, r));
const eq = (a: Bytes, b: Bytes): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const split = (n: number): number => { let k = 1; while (k * 2 < n) k *= 2; return k; };

export class Tree {
  private memo = new Map<string, Bytes>();
  readonly leaves: Bytes[];
  constructor(leaves: Bytes[]) { this.leaves = leaves; }
  get size(): number { return this.leaves.length; }
  async mth(start: number, n: number): Promise<Bytes> {
    if (n === 0) return sha256(new Uint8Array());
    if (n === 1) return this.leaves[start]!;
    const key = `${start}:${n}`;
    const hit = this.memo.get(key);
    if (hit) return hit;
    const k = split(n);
    const h = await nodeHash(await this.mth(start, k), await this.mth(start + k, n - k));
    this.memo.set(key, h);
    return h;
  }
  root(n: number = this.size): Promise<Bytes> { return this.mth(0, n); }
  async inclusion(m: number, n: number): Promise<Bytes[]> {
    const out: Bytes[] = [];
    const walk = async (mm: number, start: number, nn: number): Promise<void> => {
      if (nn === 1) return;
      const k = split(nn);
      if (mm < k) { await walk(mm, start, k); out.push(await this.mth(start + k, nn - k)); }
      else { await walk(mm - k, start + k, nn - k); out.push(await this.mth(start, k)); }
    };
    await walk(m, 0, n);
    return out;
  }
  async consistency(m: number, n: number): Promise<Bytes[]> {
    const out: Bytes[] = [];
    const walk = async (mm: number, start: number, nn: number, b: boolean): Promise<void> => {
      if (mm === nn) { if (!b) out.push(await this.mth(start, nn)); return; }
      const k = split(nn);
      if (mm <= k) { await walk(mm, start, k, b); out.push(await this.mth(start + k, nn - k)); }
      else { await walk(mm - k, start + k, nn - k, false); out.push(await this.mth(start, k)); }
    };
    if (m < n) await walk(m, 0, n, true);
    return out;
  }
}

export async function verifyInclusion(leaf: Bytes, index: number, size: number, proof: Bytes[], root: Bytes): Promise<boolean> {
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r = await nodeHash(r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}

export async function verifyConsistency(first: number, second: number, firstRoot: Bytes, secondRoot: Bytes, proof: Bytes[]): Promise<boolean> {
  if (first < 1 || first > second) return false;
  if (first === second) return proof.length === 0 && eq(firstRoot, secondRoot);
  const p = (first & (first - 1)) === 0 ? [firstRoot, ...proof] : [...proof];
  if (p.length === 0) return false;
  let fn = first - 1, sn = second - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let fr = p[0]!, sr = p[0]!;
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = await nodeHash(c, fr); sr = await nodeHash(c, sr);
      if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else sr = await nodeHash(sr, c);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(fr, firstRoot) && eq(sr, secondRoot);
}

// ts_ns is a 19-digit integer: JSON.parse would round it and break the signature, so lift it out as text.
export function parseSth(text: string): Sth | null {
  try {
    const safe = text.replace(/"ts_ns":(\d{16,})/g, '"ts_ns":"$1"');
    const j = JSON.parse(safe) as Record<string, unknown>;
    if (j['type'] !== 'sth' && j['type'] !== undefined) return null;
    if (typeof j['tree_size'] !== 'number' || typeof j['root'] !== 'string' || typeof j['signature'] !== 'string' || typeof j['key_id'] !== 'string') return null;
    return { tree_size: j['tree_size'], root: j['root'], ts_ns: String(j['ts_ns']), key_id: j['key_id'], signature: j['signature'], public_key: typeof j['public_key'] === 'string' ? j['public_key'] : undefined };
  } catch { return null; }
}

export const sthMessage = (s: Sth): string => `pl-sth-v1\n${s.tree_size}\n${s.root}\n${s.ts_ns}`;

export async function verifySth(s: Sth, pubHex: string): Promise<boolean> {
  try {
    const key = await subtle().importKey('raw', unhex(pubHex) as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    const sig = Uint8Array.from(atob(s.signature), (c) => c.charCodeAt(0));
    return await subtle().verify({ name: 'Ed25519' }, key, sig as BufferSource, enc.encode(sthMessage(s)) as BufferSource);
  } catch { return false; }
}

export interface HeadCheck { sth: Sth; signature: boolean | null; root: boolean | null; consistent: boolean | null; note?: string }
export interface AuditResult { complete: boolean; entries: number; heads: HeadCheck[]; tree?: Tree; firstSeq?: number }

// lines: stored entry lines by seq. Checks every head against the pinned key, the recomputed root, and the
// previous head (consistency proof built from the entries and verified with the RFC 9162 algorithm).
export async function auditLog(lines: Map<number, string>, sths: Sth[], pubHex: string | null): Promise<AuditResult> {
  const seqs = [...lines.keys()].sort((a, b) => a - b);
  const complete = seqs.length > 0 && seqs[0] === 1 && seqs.every((s, i) => s === i + 1);
  const heads: HeadCheck[] = [];
  if (!complete) {
    for (const sth of sths) heads.push({ sth, signature: pubHex ? await verifySth(sth, pubHex) : null, root: null, consistent: null, note: 'entries before the stream backlog are missing: use pl-audit on the ledger directory' });
    return { complete, entries: seqs.length, heads, firstSeq: seqs[0] };
  }
  const tree = new Tree(await Promise.all(seqs.map((s) => leafHash(lines.get(s)!))));
  let prev: Sth | undefined;
  for (const sth of [...sths].sort((a, b) => a.tree_size - b.tree_size)) {
    const h: HeadCheck = { sth, signature: pubHex ? await verifySth(sth, pubHex) : null, root: null, consistent: null };
    if (sth.tree_size >= 1 && sth.tree_size <= tree.size) {
      const root = await tree.root(sth.tree_size);
      h.root = hex(root) === sth.root;
      if (prev && prev.tree_size <= sth.tree_size) {
        h.consistent = await verifyConsistency(prev.tree_size, sth.tree_size, await tree.root(prev.tree_size), root, await tree.consistency(prev.tree_size, sth.tree_size));
      }
    } else { h.root = false; h.note = 'head covers entries this browser has not received'; }
    heads.push(h);
    prev = sth;
  }
  return { complete, entries: seqs.length, heads, tree };
}

export interface InclusionView { seq: number; leaf: string; path: string[]; size: number; ok: boolean }
export async function inclusionFor(tree: Tree, seq: number, size: number): Promise<InclusionView> {
  const idx = seq - 1;
  const path = await tree.inclusion(idx, size);
  const ok = await verifyInclusion(tree.leaves[idx]!, idx, size, path, await tree.root(size));
  return { seq, leaf: hex(tree.leaves[idx]!), path: path.map(hex), size, ok };
}
