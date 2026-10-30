import { useEffect, useMemo, useState } from 'react';
import { auditLog, inclusionFor, type AuditResult, type InclusionView } from './audit.ts';
import type { State } from './relay.ts';
import { fmtTime } from './lib.ts';

const COMPONENTS_EXPECTED = ['core', 'vault', 'agent', 'ledger'];

function latest(state: State, kind: string): unknown {
  for (let i = state.entries.length - 1; i >= 0; i--) if (state.entries[i]!.kind === kind) return state.entries[i]!.record;
  return undefined;
}
const Empty = ({ what }: { what: string }) => <p className="muted">No {what} received from the appliance yet. Nothing is shown rather than a guess.</p>;

export function IsolationPanel({ state }: { state: State }) {
  const rec = latest(state, 'isolation_counters') as { ts_ns: number; window_ns?: number; counters: { component: string; source: string; attempts: number; blocked: number; runtime?: string }[] } | undefined;
  return (
    <section className="panel" aria-label="Isolation">
      <h2>Network isolation <span className="tag">target: 0 attempts for core, vault, agent, ledger</span></h2>
      {!rec ? <Empty what="isolation counters" /> : (
        <>
          <p className="muted">Counted at {fmtTime(rec.ts_ns)} over a {((rec.window_ns ?? 0) / 1e9).toFixed(0)} s window: connections that are neither loopback nor Unix sockets.</p>
          <table>
            <thead><tr><th>Component</th><th>Observed by</th><th>Runtime</th><th>Attempts</th><th>Blocked</th><th></th></tr></thead>
            <tbody>
              {rec.counters.map((c) => {
                const strict = COMPONENTS_EXPECTED.includes(c.component);
                const bad = strict && c.attempts > 0;
                return (
                  <tr key={c.component + c.source}>
                    <td>{c.component}</td><td>{c.source}</td><td>{c.runtime ?? '-'}</td>
                    <td className="mono">{c.attempts}</td><td className="mono">{c.blocked}</td>
                    <td><span className={`verdict ${bad ? 'v-blocked' : 'v-sent'}`}>{bad ? 'ATTEMPTS SEEN' : strict ? 'zero' : 'allowed to talk'}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

export function PosturePanel({ state }: { state: State }) {
  const cap = latest(state, 'capability_report') as { host: { os: string; kernel: string; cpu_count: number; mem_mb: number }; checks: { feature: string; status: 'green' | 'amber' | 'red'; fallback?: string; reason_code?: string }[] } | undefined;
  const att = state.entries.find((e) => e.seq === 1 && e.kind === 'attestation')?.record as { final: string; components: { kind: string; name: string; sha256: string }[] } | undefined;
  return (
    <section className="panel" aria-label="Security posture">
      <h2>Security posture</h2>
      <h3>Kernel protections</h3>
      {!cap ? <Empty what="a capability report" /> : (
        <>
          <p className="muted mono">{cap.host.os} {cap.host.kernel}, {cap.host.cpu_count} CPUs, {cap.host.mem_mb} MB</p>
          <div className="chips">
            {cap.checks.map((c) => (
              <span key={c.feature} className={`chip s-${c.status}`} title={[c.fallback && `fallback: ${c.fallback}`, c.reason_code].filter(Boolean).join(' / ')}>
                {c.feature}: {c.status}{c.fallback ? ` (${c.fallback})` : ''}
              </span>
            ))}
          </div>
        </>
      )}
      <h3>Process liveness (gate watchdog)</h3>
      {Object.keys(state.live).length === 0 ? <Empty what="liveness (needs /api/status)" /> : (
        <div className="chips">{Object.entries(state.live).map(([k, v]) => <span key={k} className={`chip ${v ? 's-green' : 's-red'}`}>{k}: {v ? 'alive' : 'NOT RESPONDING'}</span>)}</div>
      )}
      <h3>Attestation (ledger entry #0)</h3>
      {!att ? <Empty what="an attestation as entry #0 (or it is older than the stream backlog)" /> : (
        <>
          <p className="mono wrap">final {att.final}</p>
          <table><thead><tr><th>Kind</th><th>Name</th><th>SHA-256</th></tr></thead>
            <tbody>{att.components.map((c) => <tr key={c.name}><td>{c.kind}</td><td>{c.name}</td><td className="mono">{c.sha256.slice(0, 16)}...</td></tr>)}</tbody></table>
        </>
      )}
      <h3>Kill switch</h3>
      <p>{state.killed ? 'ENGAGED: the AI lane is closed.' : 'Not engaged.'}</p>
    </section>
  );
}

function pinned(): string {
  try { return localStorage.getItem('pl.ledger.pubkey') ?? ''; } catch { return ''; }
}

export function AuditPanel({ state }: { state: State }) {
  const [pin, setPin] = useState(pinned());
  const [res, setRes] = useState<AuditResult | null>(null);
  const [inc, setInc] = useState<InclusionView | null>(null);
  const [busy, setBusy] = useState(false);
  const streamKey = state.sths[state.sths.length - 1]?.public_key ?? null;
  const key = pin.trim() || streamKey;
  const lines = useMemo(() => new Map(state.entries.filter((e) => e.seq > 0 && e.line).map((e) => [e.seq, e.line!])), [state.entries]);

  useEffect(() => {
    let dead = false;
    setBusy(true);
    void auditLog(lines, state.sths, key).then((r) => { if (!dead) { setRes(r); setBusy(false); } }).catch(() => { if (!dead) setBusy(false); });
    return () => { dead = true; };
  }, [lines, state.sths, key]);

  const savePin = (v: string) => { setPin(v); try { localStorage.setItem('pl.ledger.pubkey', v.trim()); } catch { /* storage unavailable */ } };
  const show = async (seq: number) => {
    const head = res?.heads.filter((h) => h.signature && h.root).at(-1);
    if (!res?.tree || !head) { setInc(null); return; }
    setInc(await inclusionFor(res.tree, seq, head.sth.tree_size));
  };
  const mark = (v: boolean | null) => v === null ? <span className="chip s-amber">n/a</span> : v ? <span className="chip s-green">ok</span> : <span className="chip s-red">FAIL</span>;
  const cryptoOk = typeof globalThis.crypto?.subtle !== 'undefined';

  return (
    <section className="panel" aria-label="Audit log">
      <h2>Audit log <span className="tag">verified in this browser</span></h2>
      {!cryptoOk && <div className="banner err">This browser has no WebCrypto here (needs 127.0.0.1 or HTTPS). Use <code>pl-audit verify</code>.</div>}
      <p className="muted">Entries are hashed here (RFC 6962), the tree is rebuilt, and each signed head is checked: Ed25519 signature, root, and consistency with the previous head. Only the public key is taken from outside.</p>
      <label className="pin">Pinned ledger public key (hex, from <code>ledger.pub</code> or the attestation):
        <input value={pin} onChange={(e) => savePin(e.target.value)} placeholder={streamKey ? 'not pinned: using the key sent in the stream (weaker)' : 'hex'} spellCheck={false} />
      </label>
      {!pin.trim() && streamKey && <p className="banner warn">Unpinned: the key comes from the same stream as the heads, so this proves self-consistency only.</p>}
      {state.sths.length === 0 ? <Empty what="a signed tree head" /> : (
        <>
          <p className="mono">{res?.entries ?? 0} entries held, {state.sths.length} heads{busy ? ' (checking...)' : ''}{res && !res.complete ? '. INCOMPLETE: the first entries are older than the stream backlog.' : ''}</p>
          <table>
            <thead><tr><th>Tree size</th><th>Root</th><th>Signature</th><th>Root recomputed</th><th>Consistent with previous</th></tr></thead>
            <tbody>
              {(res?.heads ?? []).slice(-12).map((h) => (
                <tr key={h.sth.tree_size + h.sth.root} title={h.note}>
                  <td className="mono">{h.sth.tree_size}</td><td className="mono">{h.sth.root.slice(0, 16)}...</td>
                  <td>{mark(h.signature)}</td><td>{mark(h.root)}</td><td>{mark(h.consistent)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h3>Entries</h3>
      <div className="tablewrap short">
        <table>
          <thead><tr><th>#</th><th>Kind</th><th>Time</th><th></th></tr></thead>
          <tbody>
            {[...state.entries].filter((e) => e.seq > 0).reverse().slice(0, 100).map((e) => (
              <tr key={e.seq}><td className="mono">{e.seq}</td><td>{e.kind}</td><td className="mono">{fmtTime(e.ts_ns)}</td>
                <td><button className="link" disabled={!res?.tree} onClick={() => void show(e.seq)}>prove</button></td></tr>
            ))}
          </tbody>
        </table>
      </div>
      {inc && (
        <div className="proof">
          <p>Entry #{inc.seq} against head of size {inc.size}: <b>{inc.ok ? 'proof verifies' : 'PROOF FAILS'}</b></p>
          <p className="mono wrap">leaf {inc.leaf}</p>
          <ol className="mono wrap">{inc.path.map((p, i) => <li key={i}>{p}</li>)}</ol>
        </div>
      )}
    </section>
  );
}

interface TrainingRun { name: string; curve?: { step: number; loss?: number; val_loss?: number }[]; final?: Record<string, number | string> }
interface Training { generated?: string; sample?: boolean; runs: TrainingRun[] }

export function TrainingPanel() {
  const [data, setData] = useState<Training | null | undefined>(undefined);
  useEffect(() => {
    let dead = false;
    const get = async (u: string): Promise<Training | null> => { try { const r = await fetch(u, { cache: 'no-store' }); return r.ok ? await r.json() as Training : null; } catch { return null; } };
    void (async () => {
      const real = await get('results/training_metrics.json');
      const d = real ?? await get('fixtures/training_metrics.sample.json');
      if (!dead) setData(d ? (real ? d : { ...d, sample: true }) : null);
    })();
    return () => { dead = true; };
  }, []);
  if (data === undefined) return <section className="panel"><p className="muted">Loading ...</p></section>;
  if (data === null) return <section className="panel"><h2>Training</h2><Empty what="training_metrics.json (expected in eval/results/, copied to dist/results/ by make dashboard)" /></section>;
  return (
    <section className="panel" aria-label="Training">
      <h2>Training {data.sample && <span className="badge badge-mock">SAMPLE DATA, not a real run</span>}</h2>
      {data.generated && <p className="muted">Generated {data.generated}</p>}
      {data.runs.map((r) => (
        <div key={r.name} className="run">
          <h3>{r.name}</h3>
          {r.curve && r.curve.length > 1 && <Curve points={r.curve} />}
          {r.final && <table><tbody>{Object.entries(r.final).map(([k, v]) => <tr key={k}><td>{k}</td><td className="mono">{typeof v === 'number' ? v.toPrecision(4) : v}</td></tr>)}</tbody></table>}
        </div>
      ))}
    </section>
  );
}

function Curve({ points }: { points: { step: number; loss?: number; val_loss?: number }[] }) {
  const W = 360, H = 120, P = 24;
  const ys = points.flatMap((p) => [p.loss, p.val_loss]).filter((v): v is number => typeof v === 'number');
  const y0 = Math.min(...ys), y1 = Math.max(...ys), x0 = points[0]!.step, x1 = points[points.length - 1]!.step;
  const sx = (x: number) => P + ((x - x0) / Math.max(1e-9, x1 - x0)) * (W - 2 * P);
  const sy = (y: number) => H - P - ((y - y0) / Math.max(1e-9, y1 - y0)) * (H - 2 * P);
  const line = (k: 'loss' | 'val_loss') => points.filter((p) => typeof p[k] === 'number').map((p) => `${sx(p.step).toFixed(1)},${sy(p[k]!).toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="curve" role="img" aria-label="loss curve">
      <polyline points={line('loss')} fill="none" stroke="var(--accent)" strokeWidth="2" />
      <polyline points={line('val_loss')} fill="none" stroke="var(--warn)" strokeWidth="2" strokeDasharray="4 3" />
      <text x={P} y={12} fontSize="10" fill="currentColor">loss (solid), val_loss (dashed); min {y0.toPrecision(3)} max {y1.toPrecision(3)}</text>
    </svg>
  );
}
