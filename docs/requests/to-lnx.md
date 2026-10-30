
## WB-001: gate relay API the dashboard (WIN-B) codes against (v0)
Ask: the gate's UI relay on 127.0.0.1:8787 serves `dashboard/dist` at `/` and exposes:
- `GET /api/stream`: Server-Sent Events, one JSON object per `data:` line. Forward the ledger stream-socket messages unchanged (`{"type":"hello"|"entry"|"stats",...}`; entry = `{"type":"entry","seq","ts_ns","kind":"event|decision_record|egress_record|...","record":{<contract message>}}`; see daemons/ledger/README.md). Also pass through, when core/agent produce them: `{"type":"screen","view":"user"|"ai","ts_ns","width","height","png_b64"}` (real screenshot and the redacted screenshot actually sent), `{"type":"approval_request","approval_id","ts_ns","expires_ns","action_kind","risk"}`, `{"type":"kill_state","engaged":bool}`.
- `POST /api/approval` body `{"approval_id","decision":"approve"|"deny"}` (signed approval_token.v1 later); `POST /api/kill` (engage kill switch).
Why: Sprint 1 dashboard "your screen vs what the AI sees". Blocks: real-stream mode only (mock mode works without it). Acceptance: `curl -N 127.0.0.1:8787/api/stream` prints a hello line and entries.
Ledger sockets (my defaults): ingest `/run/pl/ledger.sock`, stream `/run/pl/ledger-stream.sock`; `ledgerd --ingest --stream --dir --schemas`.
