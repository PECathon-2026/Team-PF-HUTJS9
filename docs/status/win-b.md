T0 = 2026-10-30T00:45:19+00:00

# WIN-B status

Scope: daemons/ledger, dashboard, this file. At start, `tools/ownership.tsv` on origin/main still lists ledger and dashboard as LNX, and the pre-commit hook blocks WIN commits there (and docs/status/win-b.md has no owner line). No merge until LNX's change lands.
Make targets live in daemons/ledger/ledger.mk and dashboard/dashboard.mk (WIN-A creates mk/win.mk; WIN-B adds one `-include dashboard/dashboard.mk daemons/ledger/ledger.mk` line inside its fence once it is on main). Until then: `make -f Makefile -f dashboard/dashboard.mk dashboard`.
Requests to LNX: WB-001 (relay API) in docs/requests/to-lnx.md.

## Ledger (Sprint 1 item 1): done
- Reject rules LG-001..LG-004, hash-chained append-only segments, ingest + stream UDS server, `ledgerd`, `ledgerd --verify`. Details in daemons/ledger/README.md.
- Verified: `make ... ledger-test` and `ledger-asan` (ASan+UBSan): 100% pass (18 ledger tests incl. known-answer canary check digits, tamper detection, torn-tail recovery, UDS ingest+stream round trip). Manual run of `ledgerd` in the dev image: valid event acked seq 1, event with `raw` rejected LG-001, `--verify` OK.
- Not done: Merkle tree/signatures (Sprint 2); not yet wired into compose (LNX); no fuzzing of the ingest parser.

## Dashboard v1 (item 2): done against mock; live untested
- Built: `make ... dashboard` builds in the dev image (Node 22, pnpm), `dashboard-test` passes (3 tests). Operator view: your screen vs what the AI sees (exact egress payload with placeholder highlighting, plus redacted screenshot when the relay sends one), outgoing log with verdicts, rule IDs and checks, decisions tab, counters, approval prompt (timeout = deny), kill switch button + Ctrl+Shift+K.
- Verified in headless Chromium (Playwright, mock mode): renders with no console errors, approval dialog shows, hotkey engages kill, no-relay state shows "NO RELAY". Mock mode is labelled (badge, banner, MOCK marks on images).
- Not done: real relay (needs LNX gate: WB-001); screenshots on real stream untested; no tests for components.
