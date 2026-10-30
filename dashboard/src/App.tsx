import { useEffect, useMemo, useState } from 'react';
import { computeCounters, fmtBytes, fmtTime, ruleIdsOf, splitPlaceholders } from './lib.ts';
import { useRelay } from './relay.ts';
import { AuditPanel, IsolationPanel, PosturePanel, TrainingPanel } from './Panels.tsx';
import type { DecisionRecord, EgressRecord, Mode } from './types.ts';

const MODE_LABEL: Record<Mode, string> = {
  connecting: 'CONNECTING', live: 'LIVE', mock: 'MOCK DATA', disconnected: 'NO RELAY',
};

export function App() {
  const { state, kill, answer, useMock, useLive, mockApproval } = useRelay();
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<'egress' | 'decisions'>('egress');
  const [view, setView] = useState<'operator' | 'isolation' | 'posture' | 'audit' | 'training'>('operator');

  // Kill-switch hotkey: Ctrl+Shift+K acts immediately (no confirmation by design).
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'k') { e.preventDefault(); void kill(); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [kill]);

  const egress = useMemo(() => state.entries.filter((e) => e.kind === 'egress_record').map((e) => ({ seq: e.seq, r: e.record as EgressRecord })), [state.entries]);
  const decisions = useMemo(() => state.entries.filter((e) => e.kind === 'decision_record').map((e) => ({ seq: e.seq, d: e.record as DecisionRecord })), [state.entries]);
  const decisionById = useMemo(() => new Map(decisions.map((x) => [x.d.decision_id, x.d])), [decisions]);
  const counters = useMemo(() => computeCounters(state.entries), [state.entries]);

  const shown = egress.find((x) => x.r.record_id === selected) ?? [...egress].reverse().find((x) => x.r.lane === 'ai');

  return (
    <div className="app">
      <header className="top">
        <h1>PrivacyLens <span className="muted">operator</span></h1>
        <span className={`badge badge-${state.mode}`} role="status">{MODE_LABEL[state.mode]}</span>
        <div className="spacer" />
        <button className={`kill ${state.killed ? 'engaged' : ''}`} onClick={() => void kill()} disabled={state.killed}>
          {state.killed ? 'KILL SWITCH ENGAGED' : 'Kill switch'} <kbd>Ctrl+Shift+K</kbd>
        </button>
      </header>

      {state.mode === 'mock' && (
        <div className="banner warn" role="alert">
          MOCK MODE: every record, screenshot and number below is a synthetic fixture generated in your browser. It is not coming from a PrivacyLens appliance.
          {' '}<button className="link" onClick={mockApproval}>Trigger mock approval</button>
          {' '}<button className="link" onClick={useLive}>Try live relay</button>
        </div>
      )}
      {(state.mode === 'disconnected' || state.mode === 'connecting') && (
        <div className="banner err" role="alert">
          {state.mode === 'connecting' ? 'Connecting to the relay at /api/stream ...' : 'No relay at /api/stream. Nothing below is current.'}
          {' '}<button className="link" onClick={useMock}>Use labelled mock data instead</button>
        </div>
      )}
      {state.notices.length > 0 && <div className="banner info">{state.notices[0]}</div>}

      <nav className="views" aria-label="Screens">
        {(['operator', 'isolation', 'posture', 'audit', 'training'] as const).map((v) => (
          <button key={v} aria-current={view === v} className={view === v ? 'on' : ''} onClick={() => setView(v)}>{v}</button>
        ))}
      </nav>
      {view === 'isolation' && <IsolationPanel state={state} />}
      {view === 'posture' && <PosturePanel state={state} />}
      {view === 'audit' && <AuditPanel state={state} />}
      {view === 'training' && <TrainingPanel />}

      <div hidden={view !== 'operator'}>
      <section className="counters" aria-label="Counters">
        <Counter label="AI requests sent" value={counters.aiSent} />
        <Counter label="Blocked" value={counters.blocked} tone={counters.blocked ? 'bad' : undefined} />
        <Counter label="Browsing requests" value={counters.browsing} />
        <Counter label="Bytes out" value={fmtBytes(counters.bytesOut)} />
        <Counter label="Decisions (block/allow)" value={`${counters.decisions['block'] ?? 0} / ${counters.decisions['allow'] ?? 0}`} />
        <Counter label="Ledger rejects" value={state.stats?.rejected ?? 0} tone={state.stats?.rejected ? 'bad' : undefined} />
      </section>

      <main className="panes">
        <section className="pane" aria-label="Your screen">
          <h2>Your screen <span className="tag">real, never leaves</span></h2>
          <Screen src={state.screens.user} empty="No screenshot received yet" mock={state.mode === 'mock'} />
        </section>
        <section className="pane ai" aria-label="What the AI sees">
          <h2>What the AI sees <span className="tag">exact egress payload</span></h2>
          <Screen src={state.screens.ai} empty="No redacted screenshot received yet" mock={state.mode === 'mock'} />
          <AiPayload rec={shown?.r} />
        </section>
      </main>

      <section className="log" aria-label="Outgoing log">
        <div className="tabs" role="tablist">
          <button role="tab" aria-selected={tab === 'egress'} onClick={() => setTab('egress')}>Outgoing ({egress.length})</button>
          <button role="tab" aria-selected={tab === 'decisions'} onClick={() => setTab('decisions')}>Decisions ({decisions.length})</button>
        </div>
        <div className="tablewrap">
          {tab === 'egress' ? (
            <table>
              <thead><tr><th>Time</th><th>Lane</th><th>Verdict</th><th>Rule IDs</th><th>Destination</th><th>Out</th><th>Checks</th></tr></thead>
              <tbody>
                {[...egress].reverse().map(({ seq, r }) => (
                  <tr key={seq} className={r.record_id === shown?.r.record_id ? 'sel' : ''} onClick={() => setSelected(r.record_id)} tabIndex={0}
                      onKeyDown={(e) => { if (e.key === 'Enter') setSelected(r.record_id); }}>
                    <td className="mono">{fmtTime(r.ts_ns)}</td>
                    <td>{r.lane}</td>
                    <td><span className={`verdict v-${r.verdict}`}>{r.verdict}</span></td>
                    <td className="mono">{ruleIdsOf(r, decisionById).join(' ') || '-'}</td>
                    <td className="mono">{r.destination.host}:{r.destination.port}</td>
                    <td className="mono">{fmtBytes(r.bytes_out)}</td>
                    <td className="checks">{r.checks.map((c, i) => <span key={i} className={`chk c-${c.result}`} title={c.rule_id}>{c.check}</span>)}</td>
                  </tr>
                ))}
                {egress.length === 0 && <tr><td colSpan={7} className="muted">No egress records yet.</td></tr>}
              </tbody>
            </table>
          ) : (
            <table>
              <thead><tr><th>Time</th><th>Component</th><th>Subject</th><th>Verdict</th><th>Rule</th><th>Evidence</th></tr></thead>
              <tbody>
                {[...decisions].reverse().map(({ seq, d }) => (
                  <tr key={seq}>
                    <td className="mono">{fmtTime(d.ts_ns)}</td><td>{d.component}</td><td>{d.subject}</td>
                    <td><span className={`verdict v-${d.verdict}`}>{d.verdict}</span></td>
                    <td className="mono">{d.rule_id}</td>
                    <td className="mono">{d.evidence.map((e) => [e.kind, e.field_type, e.placeholder, e.detail_code].filter(Boolean).join(':')).join('  ')}</td>
                  </tr>
                ))}
                {decisions.length === 0 && <tr><td colSpan={6} className="muted">No decisions yet.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      </section>

      </div>

      {state.approval && <Approval key={state.approval.req.approval_id} req={state.approval.req} deadlineMs={state.approval.deadlineMs} onAnswer={answer} />}
    </div>
  );
}

function Counter({ label, value, tone }: { label: string; value: string | number; tone?: 'bad' }) {
  return <div className={`counter ${tone ?? ''}`}><div className="cv">{value}</div><div className="cl">{label}</div></div>;
}

function Screen({ src, empty, mock }: { src?: string; empty: string; mock: boolean }) {
  return (
    <div className="screen">
      {src ? <img src={src} alt="" /> : <div className="muted center">{empty}</div>}
      {mock && src && <span className="mockmark">MOCK</span>}
    </div>
  );
}

function AiPayload({ rec }: { rec?: EgressRecord }) {
  if (!rec) return <div className="payload muted">No AI-lane request yet.</div>;
  return (
    <div className="payload">
      <div className="payload-meta mono">
        {rec.destination.provider ?? 'ai'} {rec.destination.host} | {rec.verdict} | images: {rec.payload?.image_count ?? 0} | sha256 {rec.payload_sha256?.slice(0, 12) ?? '-'}
      </div>
      {rec.verdict === 'blocked' && <div className="blockednote">Blocked by the gate. Nothing was sent, so there is no payload.</div>}
      {rec.payload?.messages.map((m, i) => (
        <div key={i} className="msg">
          <div className="role">{m.role}</div>
          <pre>{splitPlaceholders(m.content).map((s, j) => s.placeholder ? <mark key={j}>{s.text}</mark> : <span key={j}>{s.text}</span>)}</pre>
        </div>
      ))}
    </div>
  );
}

function Approval({ req, deadlineMs, onAnswer }: { req: { approval_id: string; action_kind: string; risk?: number }; deadlineMs: number; onAnswer: (id: string, d: 'approve' | 'deny', why?: string) => Promise<void> }) {
  const [left, setLeft] = useState(Math.max(0, deadlineMs - Date.now()));
  useEffect(() => {
    const t = setInterval(() => {
      const l = deadlineMs - Date.now();
      if (l <= 0) { clearInterval(t); void onAnswer(req.approval_id, 'deny', 'timeout'); } else setLeft(l);
    }, 200);
    return () => clearInterval(t);
  }, [deadlineMs, req.approval_id, onAnswer]);
  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-label="Approval required">
      <div className="dialog">
        <h2>Approval required</h2>
        <p className="action">{req.action_kind}</p>
        {req.risk !== undefined && <p className="muted">Risk score {req.risk.toFixed(2)}</p>}
        <p className="muted">No answer in {(left / 1000).toFixed(0)} s means deny.</p>
        <div className="row">
          <button className="deny" autoFocus onClick={() => void onAnswer(req.approval_id, 'deny')}>Deny</button>
          <button className="approve" onClick={() => void onAnswer(req.approval_id, 'approve')}>Approve</button>
        </div>
      </div>
    </div>
  );
}
