# LNX status

T0 = 2026-10-30T00:45:19+00:00

Machine: Linux Mint laptop (8 GB RAM, 4 GB VRAM). Owner of this file: LNX.

## Sprint 1 (stopped at 01:06 UTC: account usage limit, on WIN-A's instruction)

### Merged to main
- [x] PR #2 `5547bf8`: ownership change (ledger, dashboard, docs/status/win-b.md, EVALUATION/RESULTS/DEMO -> WIN). CI green. **WIN-B is unblocked.**

### Open PR (not merged yet)
- PR #3 `lnx/p0-compose-iface` (Phase 0 steps 9-12), rebased onto main after #2. Local `make ci-lnx` green (before the rebase); after the rebase `make test-py-lnx` passed 132 and `pl_hook.py ci` passed. CI was running when I stopped (it builds dev image b968bf43f5f2a1a9 in-job). Fuzz 10-min runs skipped (user decision).
  - Next: `gh pr checks 3 --watch` -> `gh pr merge 3 --squash --delete-branch` -> `git fetch origin && git tag p0-lnx-done origin/main && git push origin p0-lnx-done`.

### Branch `lnx/s1-platform` (pushed, stacked on lnx/p0-compose-iface, no PR)
After PR #3 merges: `git rebase --onto origin/main lnx/p0-compose-iface lnx/s1-platform`.
- [x] `libs/plcommon` SecureChannel (`channel.hpp/.cpp`): crypto_kx + secretstream over FramedSocket; ephemeral keys, peer by SO_PEERCRED (no pinned component keys yet). 3 tests (round trip, tamper, replay) pass.
- [x] `daemons/vault`: lib + `pl-vault` daemon. memfd_secret key (fallback mmap+mlock+MADV_DONTDUMP), per-session BLAKE2b subkey, XChaCha20-Poly1305 with AD = canonical binding, wipe, shred, vault_api.v1 handler; PR_SET_DUMPABLE 0, RLIMIT_CORE 0. 8 tests pass (debug build).
- [x] `daemons/gate`: lib + `pl-gate` daemon. AI lane checks in order: schema, kill switch, watchdog (liveness.v1 pongs, 2 s), taint == public, allow-list, local_only, independent re-check (Luhn, Verhoeff, PAN, key prefixes, PEM), canary (PLCANARY self-check mod 97 + listed canaries from `canaries[]` in truth JSON), images blocked (no gate OCR yet). Egress_record with the exact payload. Replay provider (WIN's pl.replay.v1 cassettes, model = cassette name), ollama provider. Browsing lane (CONNECT + absolute-form HTTP, domain allow-list). UI port 8787: dashboard/dist static, /api/egress, /api/status, /api/stream (SSE: egress + relay of /run/pl/ledger-stream.sock), POST /api/kill. 14 tests pass (debug build). Fuzz target `fuzz_gate_decoder` written, not run yet.
- [ ] **In progress, not built yet:** `daemons/core/runtime/` (cdp.cpp: Chrome over --remote-debugging-pipe fds 3/4; capture.cpp: DOMSnapshot -> capture model; actuator.cpp: action validation C-101..C-109; main.cpp: /run/pl/core.sock agent protocol open/observe/act/end, vault hand-off, loopback forwarder 127.0.0.1:3128 -> gate-web.sock, heartbeats). Root CMakeLists now adds daemons/gate before daemons/core and daemons/core/runtime at the end.
  - Next: `DEV=... cmake --build --preset debug` in the dev image and fix compile errors; write `daemons/core/runtime/tests/capture_test.cpp` (and add it back in that CMakeLists); run clang-tidy (`make lint-cpp-lnx`) and ASan on vault/gate/core.
  - The vault daemon does not send heartbeats yet (gate requires core,vault live by default: `PL_GATE_REQUIRE_LIVE`).
- [ ] Not started: core image with Chrome for Testing headless shell 131.0.6778.85 (`chrome-headless-shell-linux64.zip`, sha256 `a39e418d96afbc982cfd36432c775b9cbc2ae9a34703db6b0310326cb366057c`), vault/gate images, compose wiring (runsc for core, `--host-uds` question), `make llm-pull`, `make e2e` harness + isolation test + leak scan, to-win.md note on the core.sock protocol and ledger socket names.

## Phase 0: Bootstrap (in progress, paused 2026-10-30 for a machine hand-over)

### Where things stand
- **Merged to `main`:** PR #1 (`e2224d4`): steps 1–8 (CI green: ownership, dev-image, ci, fuzz-smoke).
- **On branch `lnx/p0-compose-iface` (pushed, no PR yet):** steps 9–11 plus the fixes from the step-12 independent review (table below). Local `make ci-lnx` is green on this branch (132 Python tests, 98.8 % cov; 64 C++ tests under GCC, ASan/UBSan and coverage 95.0 %; clang-tidy clean; lint-contracts clean; 27 compose policy tests).
- **Dev image changed on this branch** (Boost.Regex for the validator, pnpm hash-pinned): new tag `b968bf43f5f2a1a9`, built locally, **not yet published**. Its first CI run will build it in-job (PRs never publish); merging to `main` publishes it.

### Steps
- [x] 1. Check starting state (origin, bootstrap-only `main`)
- [x] 2. Layout: LNX folders with owner/purpose READMEs
- [x] 3. Ownership enforcement: `tools/ownership.tsv`, pre-commit hook, `make hooks`, `ownership.yml`, hook tests
- [x] 4. Dev image `platform/images/dev.Dockerfile` + `lnx-dev-image.yml`, `make dev-image`, `make shell`
- [x] 5. Build glue: root `CMakeLists.txt`, `CMakePresets.json`, `Makefile`, `mk/lnx.mk`
- [x] 6. CI: `lnx-ci.yml` (merged with steps 2–8 in PR #1)
- [x] 7. Contracts: README, OWNERS.tsv, C++/Python validators, linter, LNX schemas v1 + fixtures
- [x] 8. plcommon / plpy v0: framing, UDS, validation hooks, logging + scrubber, taint lattice, IDs; tests; fuzz ≥ 10 min
- [x] 9. Compose skeleton + `tests/e2e/platform/test_compose_policy.py` (branch, not merged)
- [x] 10. `docs/architecture/lnx.md` (branch, not merged)
- [x] 11. `detect_api_proposal.hpp`, fail-closed `NullDetector`, request `L-001` in `docs/requests/to-win.md` (branch, not merged)
- [ ] 12. Independent review **done** and findings fixed/recorded (table below); remaining: fuzz, merge, tag

### Next, in order
1. Rebuild the fuzz targets and run **`fuzz_registry` for ≥ 10 min** (new target; it was interrupted at the hand-over with no crashes). `fuzz_frame_decoder` and `fuzz_scrub` already ran 10 min each clean after the review fixes (6.9 M / 3.5 M execs):
   `make fuzz-smoke-lnx FUZZ_SECONDS=600` (runs all three; ~30 min).
2. `git fetch origin && git rebase origin/main`, `make ci-lnx` (must be green), push, `gh pr create --fill --base main`, `gh pr checks --watch`, `gh pr merge --squash --delete-branch`.
   - The `ownership` check will **not** run on this PR (it moves the workflow to `pull_request_target`, and `main` still has the old trigger). Run the checker by hand before merging:
     `python3 tools/hooks/pl_hook.py ci --base origin/main --head HEAD --branch lnx/p0-compose-iface`.
   - CI on this PR builds the new dev image in-job (slower, ~10 min extra per job).
3. After merge: confirm `lnx-dev-image` published `dev:b968bf43f5f2a1a9` on main; tick step 12; tag `p0-lnx-done` on the `main` commit (`git fetch origin && git tag p0-lnx-done origin/main && git push origin p0-lnx-done`).
4. Phase report to the user, ending with: "Run Phase 0 on WIN now."

## Step 1 findings

- `origin` = `https://github.com/PECathon-2026/Team-PF-HUTJS9.git`.
- `origin/main` = one commit (`7a85ea0 Bootstrap`), files: `.claude/settings.json`, `.gitattributes`, `.gitignore`, `CLAUDE.md`, `docs/PrivacyLens_Features.md`, `docs/SETUP.md`, `docs/prompts/{LNX,SHARED,WIN}.md`. Nothing unexpected. No tags.

## Phase 0 test results (local, LNX laptop)

| Check | Result |
|---|---|
| Python (`make test-py-lnx`): hook, plpy, pl_contracts | 110 passed, coverage 98.7 % (min 85 %) |
| ruff / ruff format / mypy --strict | clean |
| C++ GCC 13 debug, `-Wall -Wextra -Werror` | 51/51 tests |
| C++ Clang 18 ASan+UBSan | 51/51 tests |
| C++ coverage (clang source-based, plcommon + contracts) | 94.1 % lines (min 80 %) |
| clang-tidy (19 files) | clean |
| Contracts: lint + fixtures (Python and C++) | 18 schemas, 93 fixtures, both engines agree |
| fuzz-smoke 60 s: `fuzz_frame_decoder`, `fuzz_scrub` | 1.2 M / 0.95 M execs, no crashes |
| fuzz 10 min each (local): `fuzz_frame_decoder`, `fuzz_scrub` | 6.5 M / 3.7 M execs, no crashes |
| Compose policy (`make test-security-lnx`) | 22 passed |
| C++ incl. core shell NullDetector | 56/56 tests, clang-tidy clean (22 files) |
| TSan | needs `vm.mmap_rnd_bits=28` on the host (see `mk/lnx.mk`); runs in CI |

## Phase 0 independent review (fresh-context subagent) and dispositions

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | HIGH | LNX could grant itself paths by editing `ownership.tsv` in the same commit/PR | **Fixed**: rules always from the old revision (HEAD / merge base). Tests: `test_lnx_cannot_self_grant_in_same_commit`, `test_ci_judges_pr_by_base_rules` |
| 2 | HIGH | `ownership.yml` on `pull_request` runs the PR's own workflow, so a PR can neuter it | **Fixed**: `pull_request_target`, base checkout, PR head fetched as data only, read-only token. Branch protection / required review on rules files: user request U-LNX-004 |
| 3 | HIGH | `std::regex` in json-schema-validator overflows the stack on long strings (`maxLength` doesn't stop `pattern`) | **Fixed**: validator built with Boost.Regex; `Registry::validate` fails closed on any validator exception. Regression test reproduced the SEGFAULT before the fix. New fuzz target `fuzz_registry` |
| 4 | MED | Log values truncated before scrubbing | **Fixed**: scrub, then truncate; >4 KiB inputs cut at a word boundary first. Tests in C++ and Python |
| 5 | MED | Scrubber misses `.`/`/`/`_`/tab/double-space separators, 6–7 digit OTPs; digits in event names | **Fixed**: up to 2 separators from ` .-/_\t`, `[NUMBER]` from 6 digits, names with 6+ digit runs rejected. New vectors + 600-case seeded random corpus checked by both languages. Not done (LOW): full-width digits, lowercase PAN, IP-literal emails |
| 6 | MED | CI gave a package-write token to jobs running PR code | **Fixed**: `packages: read` for ci/fuzz; image published only from main; PRs that change the Dockerfile build it in-job. Actions pinned by SHA |
| 7 | MED | All daemons root, sharing one writable `/run/pl` | **Deferred to Phase 1** (daemons and images don't exist yet): distinct uids, per-daemon socket dirs, `user:` check in the policy test. Tracked in `docs/architecture/lnx.md` open questions |
| 8 | MED | Python accepted NaN/Infinity and lone surrogates that C++ rejects | **Fixed** both directions + parity tests |
| 9 | MED | No gitleaks in CI; binaries not scanned; narrow OpenAI pattern | **Fixed**: pinned gitleaks in `ownership.yml`, built-in scan on binary blobs, wider pattern |
| 10 | LOW | `user/` branch prefix is unauthenticated | **Not fixable in code**: both sessions push as the same GitHub account. Mitigation = U-LNX-004 (required human review) |
| 11 | LOW | Validator errors could quote attacker-chosen keys | **Fixed**: C++ keeps only the JSON pointer |
| 12 | LOW | JSON depth limit off by one between C++ and Python | **Fixed**: containers only, both; tests with scalars and objects |
| 13 | LOW | `ui_stream.ciphertext_b64` free-form; attestation `name` permissive | **Accepted**: ciphertext is authenticated/decoded in code (P3); a base64 pattern on 22 MB is pointless. Attestation names are image refs/paths |
| 14 | LOW | Policy test gaps (other binds, `label=disable`, `systempaths`, `sysctls`) | **Fixed**: bind allowlist (empty), `security_opt` allowlist, `sysctls` rejected; `user:` check with item 7 |
| 15 | LOW | chmod-after-bind race; send without timeout | **Fixed**: umask at bind; send timeout (default 5 s) in both |
| 16 | LOW | NullSanitizer assumed dense node ids; trusted `vault_store` output | **Fixed** + test |
| 17 | LOW | ca-certificates from live archive; pnpm not hash-pinned | pnpm **fixed** (SHA-256). ca-certificates: unavoidable bootstrap (snapshot is HTTPS-only), documented in the Dockerfile |

Bootstrap note: the PR that switches `ownership.yml` to `pull_request_target` is itself not checked by it (main still has the old trigger); its paths were checked locally with `pl_hook.py ci`.

## Notes for resuming

- On the LNX laptop the login session predated the `docker` group, so docker/make were run as `sg docker -c '...'` (U-LNX-001). Not needed after a re-login or on another machine.
- TSan runs only in CI unless `vm.mmap_rnd_bits=28` is set on the host (U-LNX-003).
- The contract schemas were generated once by a scratch script and are now maintained by hand; edit the JSON files directly.
- Open user requests: `docs/requests/to-user-lnx.md` (U-LNX-001…004).
