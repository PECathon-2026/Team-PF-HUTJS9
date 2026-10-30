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

## Update 01:10 UTC (usage limit hit; stopping)
- Ownership change is on origin/main (5547bf8); branch rebased onto it. NOT merged: no PR opened yet.
- After rebase: `make test-cpp-lnx` and `make test-asan-lnx` 69/69 pass; clang-tidy (platform config, run on daemons/ledger src+tests via tools/lnx/clang-tidy.sh with explicit files, since `make lint-cpp-lnx` fails inside a git worktree) reports 0 errors. `make lint-cpp-lnx` itself was not run successfully for that reason.
- mk/win.mk is not on main yet, so the `-include dashboard/dashboard.mk daemons/ledger/ledger.mk` line inside the WIN-B fence is NOT added. Without it `make dashboard` does not exist; use `make -f Makefile -f dashboard/dashboard.mk dashboard`.
- Next steps: (1) `git fetch origin && git rebase origin/main`; if mk/win.mk exists add the include line in the WIN-B fence; (2) `make test-cpp-lnx test-asan-lnx` and `make -f Makefile -f dashboard/dashboard.mk dashboard dashboard-test`; (3) `git push -u origin HEAD`, `gh pr create --fill --base main`, `gh pr checks --watch`, `gh pr merge --squash --delete-branch`; (4) wire real relay when LNX's gate implements WB-001; (5) tag sprint1-winb-done only after the real stream works.

## Update 01:30 UTC
- PR #4 (ledger + dashboard v1, relay adapted to the gate's real API) merged after CI green. Dashboard now listens to the gate's named SSE events `ledger` and `egress`, polls `/api/status` for kill state; `/api/approval` does not exist in the gate (approvals show a notice and are treated as deny). Not run against the real gate yet (the gate is on LNX's branch, unmerged); reducer unit test covers the egress/ledger dedupe.
- Merkle audit log done (branch win/winb-s2): RFC 6962 tree (CT known-answer roots, all inclusion/consistency proofs to 37 leaves, tamper tests), Ed25519 STH via libsodium, `pl-audit verify|inclusion|consistency|check`, `ledgerd --attestation` records entry #0. 25 gtest pass (debug and ASan+UBSan); clang-tidy clean on the new files. Manual E2E: ledgerd + 3 ingested fixtures -> `pl-audit verify` OK; tampered proof and tampered log rejected. Limit: signing key lives beside the log (see daemons/ledger/README.md); escalate if a separate trust domain is needed.
- `make ledger-test` previously used `ctest -L ledger`, which matched no tests (label is `unit`); it now runs the gtest binary directly. Earlier "100% pass" figures came from running the binary, not from that label.
- Next: dashboard screens (isolation, security posture, audit viewer verifying in-browser, training panel), X-ray real-data-only.

## Update 01:33 UTC (usage limit; stopping)
- Merged: PR #4 (ledger + dashboard v1). PR #5 (Merkle log, pl-audit, attestation entry 0) is open, CI "ci" was still pending at 01:32; merge with `gh pr checks 5 --watch && gh pr merge 5 --squash --delete-branch` once green.
- In progress, pushed on branch win/winb-s2-dash (NOT a PR yet, based on PR #5's commits, so open it after #5 merges and rebase): ledger stream entries now carry `line`, late subscribers get the last `sth` (+`public_key`); dashboard screens isolation, posture, audit (in-browser Ed25519/RFC 9162 verification, prove button), training (reads dist/results/training_metrics.json, else a labelled SAMPLE fixture). Files: dashboard/src/{audit.ts,Panels.tsx,audit.test.ts,relay.ts,App.tsx,styles.css}, dashboard/src/fixtures/audit/*, dashboard/public/fixtures/training_metrics.sample.json, dashboard/dashboard.mk.
- Verified: `make -f Makefile -f dashboard/dashboard.mk dashboard dashboard-test` 9/9 pass (browser code verifies the C++-generated fixture heads, inclusion proofs, and rejects tampering); ledger gtest 25 pass after the stream change. NOT verified: the screens in a browser. Playwright smoke (scratchpad winb/smoke.py, image mcr.microsoft.com/playwright/python:v1.52.0-noble after `pip install --break-system-packages playwright==1.52.0`) timed out waiting for `.proof`, cause unknown (the audit prove button probably disabled or the pinned-key/stream path failed); debug first. ASan and clang-tidy not rerun on the latest ledger.cpp edit.
- Not started: X-ray visuals, mk/win.mk include line (mk/win.mk still absent from main), running against the real gate.
