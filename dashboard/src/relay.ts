import { useCallback, useEffect, useReducer, useRef } from 'react';
import type { ApprovalRequestMsg, EntryMsg, Mode, StatsMsg, StreamMsg } from './types.ts';
import { MOCK_SCREEN_AI, MOCK_SCREEN_USER, startMock } from './mock.ts';

const MAX_ENTRIES = 600;

export interface State {
  mode: Mode;
  entries: EntryMsg[];
  stats?: StatsMsg;
  screens: { user?: string; ai?: string };
  approval?: { req: ApprovalRequestMsg; deadlineMs: number };
  killed: boolean;
  notices: string[];
}
export const initial: State = { mode: 'connecting', entries: [], screens: {}, killed: false, notices: [] };

type Action = { t: 'egress'; r: { record_id?: string; ts_ns?: number } } | { t: 'msg'; m: StreamMsg } | { t: 'mode'; mode: Mode } | { t: 'clearApproval'; notice?: string } | { t: 'killed' } | { t: 'reset' };

export function reducer(s: State, a: Action): State {
  switch (a.t) {
    case 'mode': return { ...s, mode: a.mode };
    case 'reset': return { ...initial, mode: s.mode };
    case 'killed': return { ...s, killed: true };
    case 'clearApproval': return { ...s, approval: undefined, notices: a.notice ? [a.notice, ...s.notices].slice(0, 20) : s.notices };
    case 'egress': {
      // The gate also sends its own egress records as a named SSE event. Show them at once;
      // the ledger copy (with a real seq) replaces the synthetic one when it arrives.
      const id = a.r.record_id;
      if (id && s.entries.some((e) => recordId(e) === id)) return s;
      const syn: EntryMsg = { type: 'entry', seq: -(s.entries.filter((e) => e.seq < 0).length + 1), ts_ns: a.r.ts_ns ?? 0, kind: 'egress_record', record: a.r };
      return { ...s, entries: sortEntries([...s.entries, syn]).slice(-MAX_ENTRIES) };
    }
    case 'msg': {
      const m = a.m;
      switch (m.type) {
        case 'entry': {
          if (s.entries.some((e) => e.seq === m.seq)) return s;
          const rid = m.kind === 'egress_record' ? recordId(m) : undefined;
          const kept = rid ? s.entries.filter((e) => !(e.seq < 0 && recordId(e) === rid)) : s.entries;
          const entries = sortEntries([...kept, m]).slice(-MAX_ENTRIES);
          return { ...s, entries };
        }
        case 'stats': return { ...s, stats: m };
        case 'hello': return s;
        case 'screen': {
          const src = m.png_b64 ? `data:image/png;base64,${m.png_b64}` : undefined;
          if (!src && s.mode !== 'mock') return s;
          return { ...s, screens: { ...s.screens, [m.view]: src } };
        }
        case 'approval_request':
          return { ...s, approval: { req: m, deadlineMs: Date.now() + Math.max(1000, (m.expires_ns - m.ts_ns) / 1e6) } };
        case 'kill_state': return { ...s, killed: m.engaged };
      }
    }
  }
  return s;
}

function recordId(e: EntryMsg): string | undefined {
  const r = e.record as { record_id?: string } | null;
  return e.kind === 'egress_record' ? r?.record_id : undefined;
}
function sortEntries(es: EntryMsg[]): EntryMsg[] {
  return es.sort((x, y) => (x.ts_ns - y.ts_ns) || (x.seq - y.seq));
}

async function post(path: string, body: unknown): Promise<boolean> {
  try {
    const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return r.ok;
  } catch { return false; }
}

export function useRelay() {
  const [state, dispatch] = useReducer(reducer, initial);
  const killedRef = useRef(false);
  killedRef.current = state.killed;
  const mockRef = useRef<ReturnType<typeof startMock> | null>(null);
  const modeRef = useRef<Mode>('connecting');
  modeRef.current = state.mode;

  const startLive = useCallback(() => {
    dispatch({ t: 'reset' });
    dispatch({ t: 'mode', mode: 'connecting' });
    const es = new EventSource('api/stream');
    es.onopen = () => dispatch({ t: 'mode', mode: 'live' });
    es.onmessage = (ev) => {
      try { dispatch({ t: 'msg', m: JSON.parse(ev.data) as StreamMsg }); } catch { /* ignore malformed frame */ }
    };
    // LNX gate (WB-001 reply, as built): named SSE events. `ledger` carries the ledger stream
    // frames unchanged (hello/entry/stats); `egress` carries the gate's own egress_record.v1.
    es.addEventListener('ledger', (ev) => {
      try { dispatch({ t: 'msg', m: JSON.parse((ev as MessageEvent).data) as StreamMsg }); } catch { /* ignore */ }
    });
    es.addEventListener('egress', (ev) => {
      try { dispatch({ t: 'egress', r: JSON.parse((ev as MessageEvent).data) }); } catch { /* ignore */ }
    });
    const poll = window.setInterval(async () => {
      try {
        const st = await (await fetch('api/status', { cache: 'no-store' })).json() as { killed?: boolean };
        if (st.killed) dispatch({ t: 'killed' });
      } catch { /* stream onerror handles reachability */ }
    }, 3000);
    es.onerror = () => dispatch({ t: 'mode', mode: 'disconnected' });
    return () => { es.close(); window.clearInterval(poll); };
  }, []);

  const startMockMode = useCallback(() => {
    dispatch({ t: 'reset' });
    dispatch({ t: 'mode', mode: 'mock' });
    dispatch({ t: 'msg', m: { type: 'screen', view: 'user', ts_ns: 0, width: 0, height: 0, png_b64: '' } });
    const mk = startMock((m) => dispatch({ t: 'msg', m }), () => killedRef.current);
    mockRef.current = mk;
    return mk.stop;
  }, []);

  const cleanup = useRef<() => void>(() => {});
  const useMock = useCallback(() => { cleanup.current(); cleanup.current = startMockMode(); }, [startMockMode]);
  const useLive = useCallback(() => { cleanup.current(); cleanup.current = startLive(); }, [startLive]);

  useEffect(() => {
    const forceMock = new URLSearchParams(location.search).get('mock') === '1';
    if (forceMock) useMock(); else useLive();
    return () => cleanup.current();
  }, [useMock, useLive]);

  // Mock screens are fixtures; real screens only ever come from the stream.
  const screens = state.mode === 'mock'
    ? { user: MOCK_SCREEN_USER, ai: MOCK_SCREEN_AI } : state.screens;

  const kill = useCallback(async () => {
    dispatch({ t: 'killed' }); // fail safe: show engaged at once, even if the relay is unreachable
    if (modeRef.current === 'mock') return;
    const ok = await post('api/kill', { engage: true });
    if (!ok) dispatch({ t: 'clearApproval', notice: 'Kill request could not reach the relay. Stop the stack from the host.' });
  }, []);

  const answer = useCallback(async (id: string, decision: 'approve' | 'deny', why?: string) => {
    dispatch({ t: 'clearApproval', notice: `Approval ${id.slice(-6)}: ${decision}${why ? ` (${why})` : ''}` });
    if (modeRef.current !== 'mock' && !(await post('api/approval', { approval_id: id, decision }))) dispatch({ t: 'clearApproval', notice: 'Approval could not be delivered (the relay has no approval endpoint yet); treated as deny.' });
  }, []);

  return { state: { ...state, screens }, kill, answer, useMock, useLive, mockApproval: () => mockRef.current?.approval() };
}
