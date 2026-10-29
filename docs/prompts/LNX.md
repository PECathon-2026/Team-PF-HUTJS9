# LNX prompt file: Linux Mint laptop

You are **LNX**: the platform, isolation, cryptography and dashboard machine. You build the walls, the vault, the gate, the ledger, the `core` shell with Chrome, and everything the user sees.

Read `docs/prompts/SHARED.md` first. Everything there applies here.

## Your machine and how to respect it

- Linux Mint (Ubuntu 24.04 base), **8 GB RAM**, 4 GB VRAM (GTX 1650 Ti class). Native Linux, so you are the **reference platform for kernel features** (gVisor, eBPF, `memfd_secret`, Landlock, AppArmor).
- RAM is the constraint:
  - Build with `-j4` at most (`CMAKE_BUILD_PARALLEL_LEVEL=4`). Don't run two heavy builds or test suites at once, and don't spawn parallel subagents that build.
  - Close the dashboard dev server and Chrome windows you aren't using.
  - The e2e stack on this machine uses the `replay` LLM. Only run `ollama` here with a small model (≤ 3B parameters) when a phase explicitly needs a live model.
  - Every compose service gets a `mem_limit`. If the stack doesn't fit in 8 GB, that's a bug to fix (smaller limits, quantised models, lazy loading), not a reason to skip tests.
- Large models come from WIN's GitHub Releases via `make fetch-artifacts`. You don't train anything.

## What you own

See SHARED.md §3. In short: root build glue, `platform/**`, `libs/plcommon`, `libs/plpy`, `contracts/README.md` + `contracts/lib/**` + your schemas, `daemons/core/**` except `detect/`, `sanitize/`, `fourier/`, `daemons/vault`, `daemons/gate`, `daemons/ledger`, `dashboard/**`, `tests/e2e/platform/**`, `README.md`, and your docs files.

Your schemas (producer = LNX): `frame`, `page_snapshot`, `event`, `decision_record`, `vault_api`, `gate_ai_request`, `gate_ai_response`, `egress_record`, `browsing_policy`, `liveness`, `capability_report`, `isolation_counters`, `approval_token`, `ui_stream`, `taint_label`, `attestation`, `merkle_proof`, `pipeline_timing`.

---

## Phase 0: Bootstrap (you run first; WIN waits for you)

**Preconditions:** the user's bootstrap commit is on `main` (CLAUDE.md, docs/prompts, the spec, .gitattributes, .gitignore, .claude/settings.json). No tags needed.

**Spec:** §1, §2 (OS independence), §13.

Steps:
1. **Check the starting state.** The GitHub repo (`https://github.com/PECathon-2026/Team-PF-HUTJS9`) was empty before the user's bootstrap commit. Confirm `git remote get-url origin` points there and `main` contains only the bootstrap files (plus possibly `ml/reference/pl_fourier.py`, which is WIN's; leave it alone). If anything unexpected is there, list it in `docs/status/lnx.md` and ask the user before touching it.
2. **Layout:** create only **your** folders (SHARED.md §3), each with a short `README.md` stating owner and purpose. Don't create anything inside WIN's folders; WIN creates its own in its Phase 0.
3. **Ownership enforcement:**
   - `tools/ownership.tsv`: one line per path glob → owner (`USER`, `LNX`, `WIN`, or `PRODUCER` for contracts schemas, resolved through `contracts/OWNERS.tsv`). Unlisted paths default to blocked, so new top-level folders need an explicit owner.
   - `tools/hooks/pre-commit`: reads `.pl-machine`; rejects staged files the machine doesn't own; allows USER paths only when `PL_USER_COMMIT=1` is set (the human's override, SHARED §3); rejects files > 5 MB, CRLF in text files, model/data extensions, and likely secrets (gitleaks, pinned, run from the dev image; fall back to a built-in regex scan if Docker isn't available so the hook never silently passes).
   - `make hooks` installs it via `git config core.hooksPath tools/hooks` (the only sanctioned way).
   - `.github/workflows/ownership.yml`: on PRs, branch prefix `win/` may only touch WIN paths, `lnx/` only LNX paths, `user/` only USER paths. Any other branch name fails.
   - Tests for the hook itself (pytest driving a temporary git repo): allowed edit passes, foreign edit blocked, USER path blocked without the override, CRLF blocked, big file blocked, fake secret blocked, unknown path blocked.
4. **Dev image** `platform/images/dev.Dockerfile` (ubuntu:24.04, every version pinned, downloaded tarballs verified by SHA-256). Prefer Ubuntu packages or official prebuilt binaries over compiling from source: building big libraries from source on this 8 GB laptop is slow and can run out of memory. Contents: GCC 13, Clang 18 + libFuzzer + clang-tidy, CMake ≥ 3.28, Ninja, ccache, GoogleTest, Google Benchmark, RapidCheck, libsodium, Vectorscan, onnxruntime (official C++ CPU release), LightGBM (C API), Eigen, OpenCV (core, imgproc, imgcodecs), pocketfft or FFTW, nlohmann_json, json-schema-validator, yaml-cpp, spdlog, CLI11, SQLite + sqlite-vec, Tesseract (for the gate), libbpf + bpftool, Python 3.12 + uv, Node 22 + pnpm, gitleaks, lcov/llvm-cov.
   - `.github/workflows/lnx-dev-image.yml` builds it on CI and pushes `ghcr.io/pecathon-2026/team-pf-hutjs9/dev:<dockerfile-hash>` (AD-15).
   - `make dev-image` pulls that tag, or builds locally if the pull fails. `make shell` opens a shell in it. Build caches in named volumes so rebuilds are fast.
   - WIN will need extra dependencies over time; it asks through requests, and you add them promptly.
5. **Build glue:** root `CMakeLists.txt` + `CMakePresets.json` (presets: `debug`, `asan`, `tsan`, `release`, `fuzz`, `coverage`), adding each daemon/lib folder that has a `CMakeLists.txt` (so WIN's folders are picked up automatically once they exist). Root `Makefile` with `-include mk/lnx.mk mk/win.mk`. Standard targets that fan out to `<target>-lnx` and `<target>-win` when defined: `ci`, `test`, `lint`, `fuzz-smoke`, `coverage`, `test-contracts`, `test-security`, `e2e`, `e2e-live`, `eval`, `up`, `down`, `fetch-artifacts`, `clean`, `doctor`, `hooks`. A target with nothing to run yet prints "nothing to run yet" and exits 0. Unit/lint targets run inside the dev image; compose targets run on the host.
6. **CI:** `.github/workflows/lnx-ci.yml` on ubuntu-latest: build dev image (cached), `make ci` for LNX targets, `make test-contracts`, compose policy test. Must be green before you finish.
7. **Contracts:** `contracts/README.md` (conventions, versioning, banned field names), `contracts/OWNERS.tsv`, `contracts/lib/` with C++ and Python validators and a **contract linter** (banned fields, every schema has valid + invalid fixtures). Draft all your schemas listed above as v1 with fixtures. Leave WIN's schemas to WIN but list them in `OWNERS.tsv`: `detection`, `sanitized_page`, `agent_action`, `approval_request`, `policy`, `eval_results`, `xray_*`.
8. **plcommon / plpy v0:** length-prefixed framing over Unix domain sockets, schema validation hooks, structured logging with a **log scrubber** (independent PII patterns: card-like digit runs with Luhn, Aadhaar-like with Verhoeff, emails, JWT/key prefixes; replaces with type tags), the **taint lattice** type (`public < … < secret` with `join`, spec §6), monotonic IDs. Unit tests, fuzz target for the frame decoder, ASan/UBSan clean.
9. **Compose skeleton:** `platform/compose/compose.yaml` with `include:` slots for fragments (`daemons/agent/compose.yml`, `scenarios/compose.yml` may not exist yet; handle that). Services `core`, `vault`, `gate`, `ledger` as placeholders. `tests/e2e/platform/test_compose_policy.py` asserts on `docker compose config` output: only `gate` (and `ollama`/`sites` on internal networks) have networks; everything else `network_mode: none`; `read_only: true`; `cap_drop: [ALL]`; no Docker socket mounts; no `privileged` except the future `monitor`; every service has `mem_limit`; `core` uses `runtime: runsc`.
10. Write `docs/architecture/lnx.md`: your components, the IPC design, the gate lanes (AD-05), the core↔detect C++ interface boundary (see below), the vault API, and open questions.
11. **C++ interface for WIN's libraries.** You can't write inside `daemons/core/detect/`, so write a **proposal header in your own tree**: `daemons/core/shell/include/pl/detect_api_proposal.hpp`. It describes what the shell will call: `detect(const PageSnapshot&, const DetectContext&) -> DetectionSet` and `sanitize(const PageSnapshot&, const DetectionSet&, SanitizeContext&) -> SanitizedPage`, plus scroll/incremental hooks. File request `L-001` asking WIN to adopt or amend it in WIN's own headers. Provide a `NullDetector` stub in your tree so `core` builds and links before WIN's code exists; switch to WIN's library automatically when its CMake target is present.
12. **Phase 0 merge:** CI doesn't exist until step 6 lands, so merge the step-6 PR as early as possible; every PR after that waits for green checks (SHARED §4).

Tests: hook tests, plcommon/plpy unit + fuzz (≥ 10 min locally), contract tests, compose policy test, CI green.

**Exit:** merged to `main`; tag `p0-lnx-done`. Tell the user: "Run Phase 0 on WIN now."

---

## Phase 1: Walking skeleton (parallel with WIN P1)

**Preconditions:** `g0-lnx-verified`, `g0-win-verified`.
**Spec:** §1, §3 (agent's browser, typed values, data structures), §6 (vault, decrypt at last moment), §8 (fail-closed, canary, local-only), §11 (event bus, decision records, log scrubber), §12 (side-by-side view).

Goal: **one scenario end to end** through real containers: Chrome in `core` opens WIN's login scenario page via the gate's browsing lane → snapshot → WIN's detect/sanitize (or the stub until WIN merges) → agent (WIN) → gate AI lane → `replay` LLM → action → validator → actuator types a vaulted password → done. Every decision lands in the ledger; the dashboard shows both sides.

Steps:
1. **Encrypted channels** in plcommon/plpy: `crypto_kx` handshake with pinned component public keys, `secretstream` framing, sequence numbers, replay/reorder rejection. Component keypairs generated at startup and registered with the ledger (signed registration). Tests with libsodium test vectors, tamper/replay/reorder tests, fuzz the handshake parser.
2. **ledger v1:** pub/sub event bus over UDS; enforce metadata-only (schema validation + scrubber + banned fields → reject and record a violation decision); decision records; append-only segment files on a volume. Tests: forged/unsigned events rejected, events carrying planted values rejected.
3. **core shell v1:**
   - Chrome (pinned version) inside the `core` container, `--headless=new --remote-debugging-pipe`, no Chrome sandbox (gVisor replaces it, spec §2).
   - C++ CDP client over the pipe (fd 3/4): navigation, `DOMSnapshot.captureSnapshot` with input values, accessibility tree, screenshots.
   - **Capture model** (spec §3 table): flat node arrays, string table, accessibility tree linked to DOM nodes, R-tree, tile grid with fast hashes, lock-free frame ring buffer (2–3 frames). Capture data wiped after use.
   - Calls the detect/sanitize interface (WIN's library or your `NullDetector`), hands detected values to the vault immediately (AD-12), publishes the sanitized page to the agent.
   - **Actuator:** executes validated actions via CDP (click by node, fill, select, navigate, scroll). For `fill` with a placeholder: vault decrypt (binding-checked) into locked memory → type → wipe.
   - **Loopback forwarder:** Chrome `--proxy-server` → in-container loopback listener → UDS → gate browsing lane.
4. **vault v1:** session master key in `memfd_secret` (fallback: `mmap` + `mlock` + `MADV_DONTDUMP`; always `PR_SET_DUMPABLE 0`, `RLIMIT_CORE 0`); store value → returns handle; XChaCha20-Poly1305 with associated data = binding (session, placeholder, field type, site, element); decrypt only on exact binding match; explicit wipe. Tests: wrong-site/wrong-element decryption fails; memory not in core dumps; fallback path tested.
5. **gate v1:**
   - AI lane: providers `replay`, `ollama`, optional `anthropic` (key from `~/.privacylens/secrets/anthropic_api_key`, mounted only here); allow-list; **fail-closed** default; a first independent re-check (your own Luhn/Verhoeff/key-prefix scanner, not WIN's code, AD-11) and the **canary check**; publish an `egress_record` (the exact outgoing payload) to the ledger.
   - Browsing lane: CONNECT proxy restricted to the session's allowed domains.
   - Watchdog: liveness checks to `core`, `vault`, `agent`; any miss for 2 s closes the AI lane.
   - Kill switch command (closes all lanes until reset).
6. **Compose:** all services wired per AD-05 with real networks: `egress` (gate only), `llm` (gate + ollama, internal), `web` (gate + sites, internal). Because `ollama` has no internet at runtime, add `make llm-pull MODEL=<name>`: a one-off job that pulls a model into the shared `ollama` volume with network access, then exits. The model name is configured per machine (WIN chooses the default; on this laptop use a ≤ 3B model). `runtime: runsc` for `core`, using `--host-uds` options so `core` can reach its sockets (document what's needed in an ADR). If gVisor genuinely can't run Chrome on this machine yet, run `core` on `runc` with strict seccomp, record it as a **temporary amber fallback**, and make it the first item of Phase 2.
7. **dashboard v0:** `dashboard/` with Vite + React + TS (Tauri shell can come in P4). Mock relay for dev; real connection through the gate's UI relay. Shows: "your screen" (latest screenshot frame) next to "what the AI sees" (the exact `egress_record` payload), the outgoing-message log, and approval prompts (deny-on-timeout). Playwright test against the mock relay.
8. **e2e harness** in `tests/e2e/platform/`: `make e2e` brings the stack up with the `replay` provider, runs every WIN scenario test it finds in `tests/e2e/scenarios/`, collects all logs/events/egress records and runs the **leak scan** (SHARED §7) over them, then tears down. Platform e2e tests: canary planted on a page never appears in any egress record; killing `vault` closes the AI lane within 2 s; `core`'s only network interface is loopback.

Tests: everything in SHARED §7; TSan on ring buffer and bus; fuzz CDP JSON and frame decoder ≥ 10 min.
**Exit:** merged; independent review; tag `p1-lnx-done`.

---

## Phase 2: Isolation, attestation and crypto depth

**Preconditions:** `g1-lnx-verified`, `g1-win-verified`.
**Spec:** §2 (all), §6 (all), §11 (Merkle audit log), §7 (signed policy: the signing part).

Steps:
1. **gVisor for `core`, fully:** Chrome inside `runsc`, UDS via host-uds, runtime monitoring enabled with a sink feeding network-attempt counts (for spec §2 live isolation proof). Retire any P1 amber fallback.
2. **Seccomp autogeneration:** record each daemon's syscalls while running the full test suite (choose the method in an ADR, e.g. strace-based capture inside the dev image), generate per-daemon profiles, lock them in compose, and add a test that the suite still passes under the locked profiles. Regenerate via `make seccomp`.
3. **Landlock** self-restriction inside each C++ daemon (plcommon helper), **AppArmor** profiles where available, read-only root FS, tmpfs for scratch, cgroup CPU/memory limits.
4. **Capability probe** (`platform/probe/`): checks gVisor, eBPF + BTF, `memfd_secret`, seccomp, Landlock, AppArmor, hugepages, CPU topology. Emits `capability_report`; every missing feature maps to a defined fallback (spec §2). Never a crash. `make doctor` prints it. Ask WIN (request) to run it inside WSL and report.
5. **eBPF monitor:** CO-RE program counting socket/connect/sendto/sendmsg attempts per container cgroup, excluding `AF_UNIX` and loopback. It's the only privileged container (`CAP_BPF`, `CAP_PERFMON`, no network). Together with gVisor monitoring it produces `isolation_counters`. Fallback where BTF is missing (document it).
6. **Exfiltration demo:** a red-team page under `tests/e2e/platform/redteam/exfil/` plus a **test-build-only** hook in `core` (compiled only with `-DPL_TEST_EXFIL`) that, when triggered by that page, tries to open a raw socket and send a canary card. Test: blocked by gVisor and the empty netns, counted in `isolation_counters`, recorded in the ledger, and the canary appears in no capture anywhere.
7. **Attestation chain:** `platform/attest/` hashes images (by digest), binaries, ONNX models and other artifacts from `ml/artifacts.lock.json`, `policy.yaml`, threshold files and indexes, chained as `M_i = SHA-256(M_{i−1} ‖ SHA-256(component_i))` in a fixed documented order. The result is ledger entry #0. Tests: changing any single byte of any component changes the value; daemons refuse to start on mismatch with the expected manifest.
8. **Watchdog hardening:** gate keeps lanes open only while liveness answers; test killing/freezing (`SIGSTOP`) each daemon.
9. **Crypto depth:** HKDF key hierarchy with per-purpose labels (`vault/value/<placeholder>`, `frames`, `fingerprints`, `channels`); binding finalised; **key rotation** for frames/channels every few minutes (time-step labels, old keys wiped); **crypto-shredding** at session end; component identity complete; **vault on a dedicated physical core** (cpuset; `core` excluded from it and its SMT sibling). Tests: old ciphertexts undecryptable after shred; rotated keys can't decrypt new data and vice versa; cpusets verified.
10. **Merkle audit log:** RFC 6962-style tree over decision records, Ed25519-signed tree heads (key held only by the ledger), inclusion and consistency proofs, a `pl-audit verify` CLI. Tests against published CT test vectors, tampering/truncation detected, fuzz the segment reader.
11. **Policy signing library + CLI** (Ed25519) in plcommon/plpy, so WIN's policy engine can verify. Dev key under `~/.privacylens/keys/`, never in the repo.
12. Extend `make test-security` with everything above.

**Exit:** merged; independent review; tag `p2-lnx-done`.

---

## Phase 3: The independent gate, live view, signed approvals

**Preconditions:** `g2-lnx-verified`, `g2-win-verified`.
**Spec:** §8 (all), §3 (live view with hand-over), §9 (signed human approval), §6 (component identity for the dashboard).

Steps:
1. **Gate detectors** written from the spec, independent of WIN's (AD-11): normalisation, patterns + check digits for every type in spec §4's table, Tesseract OCR on outgoing images.
2. **Decode-before-scan:** iterative base64/base32/hex/URL/HTML-entity/Unicode-escape decoding + confusable folding, bounded depth and size, **block when the limit is hit**.
3. **Winnowing** fragment detection with keyed fingerprints: the vault computes keyed fingerprints for high-value secrets and sends them to the gate over the encrypted channel (low-entropy values like OTPs excluded). Prove the detection guarantee in tests (any shared substring ≥ the guarantee length is found).
4. **Near-copy detection:** q-gram lemma filter + exact edit-distance confirmation.
5. **Taint and format checks:** reject anything whose taint label isn't `public`; strict schema validation of outgoing requests; unknown shapes blocked.
6. **Local-only mode** switch (refuse every external endpoint; Ollama only) shown on the dashboard.
7. **Gate red-team unit corpus:** nested encodings, split values, confusables, partial fragments, one-digit-changed cards, secrets in image text. Report block rate per technique. Fuzz every decoder ≥ 30 min.
8. **Dashboard pairing and channel:** dashboard generates an Ed25519 + X25519 identity (stored in the OS keychain via Tauri later; in P3 the dev web build may use an in-memory key); pairing code shown by the appliance; pinned keys both ways; end-to-end encrypted streams through the UI relay that the gate cannot decrypt (test: gate memory/logs never contain stream plaintext).
9. **Live browser view with hand-over:** CDP screencast frames to the dashboard; user mouse/keyboard events back into Chrome; explicit "take control"/"hand back" states recorded in the ledger. While the user is in control, the agent is paused.
10. **Signed approvals:** for each `approval_request` (WIN schema), the dashboard signs an `approval_token` (action hash, nonce, expiry); `core` verifies before any irreversible action. Tests: forged, expired, replayed and mismatched-action tokens all rejected; timeout means deny.

**Exit:** merged; independent review; tag `p3-lnx-done`.

---

## Phase 4: The full dashboard

**Preconditions:** `g3-lnx-verified`, `g3-win-verified`.
**Spec:** §12 (everything except X-ray mode and confidence sequences, which are Phase 5).

UI quality bar: this is the demo. Load the `frontend-design` guidance if you have it. Make it look deliberate: a clear visual hierarchy, a consistent design system (tokens for colour, spacing, type), dark and light themes, real loading/empty/error states, keyboard shortcuts (kill switch has a global hotkey), and nothing that's decoration without data behind it.

Steps:
1. **Tauri v2 shell** around the React app; keys in the OS keychain; connects only to `127.0.0.1` UI relay; CSP locked down; no remote content.
2. **Operator view:** live browser view with hand-over, counters (detections, sent, blocked, latency), side-by-side "your screen" vs "what the AI sees" (exact `egress_record`), outgoing log with verdicts and rule IDs, signed approval prompts listing the risk factors, kill switch.
3. **Security posture panel** (green/amber with reasons from `capability_report`).
4. **Isolation panel** (live `isolation_counters`, per-daemon seccomp profile summary, runtime).
5. **Pipeline timing** waterfall per frame (`pipeline_timing`).
6. **Audit viewer:** browse decisions, attestation entry #0, verify inclusion and consistency proofs **in the dashboard** (client-side verification, not trusting the appliance).
7. **Policy editor:** view rules with IDs, edit, **sign** locally, send to the agent's policy API (WIN); "mark missed field" creates a U-rule via WIN's API.
8. **Results screen** reading WIN's `eval_results` (fixtures first, real data in Phase 6).
9. **Session privacy report** export (HTML and PDF): found / sent / blocked / why, attestation value, signed audit root.
10. **Packaging:** `.github/workflows/release.yml` builds Linux (AppImage + .deb) and Windows (MSI/NSIS) on GitHub Actions. File a request asking WIN to install the Windows build at Gate 4 and run its checklist.

Tests: vitest units, Playwright per screen against the mock relay plus one against the real stack, visual regression snapshots, axe accessibility, `cargo test` + `clippy -D warnings`.
**Exit:** merged; independent review; tag `p4-lnx-done`.

---

## Phase 5: X-ray mode, confidence sequences, performance

**Preconditions:** `g4-lnx-verified`, `g4-win-verified`.
**Spec:** §12 (X-ray mode, live confidence sequences), §3 (incremental processing, cache-aware performance), §6 (cache side-channel defenses).

Steps:
1. **X-ray mode**, all 12 visuals from the spec table, each driven by real data from the ledger stream (no decoration): 3D data-flow city, detection heatmap, 3D spectral embedding, GW matcher, phase-correlation spike, frequency spectrum, growing Merkle tree with clickable inclusion paths, narrowing confidence band, taint river (Sankey), risk gauge + SHAP waterfall, nearest-attack panel, evolution arena. react-three-fiber + D3, throttled to ~30 updates/s, must stay smooth on the GTX 1650 Ti. WIN emits the `xray_*` events; build against WIN's fixtures until the real stream exists.
2. **Live confidence sequences** in the dashboard (betting-style / martingale bounds valid at every time). Cross-check against WIN's Python reference vectors (request them); results must match to 1e-9.
3. **Incremental capture:** DOM change stream, tile-hash dirty detection, scroll tracking by calling WIN's phase-correlation function, so only changed tiles/nodes reach detection.
4. **Cache-aware performance** for your daemons: CPU pinning config in compose (cpusets), huge pages for large buffers where available (probe + fallback), `perf` cache-miss counters before/after, recorded in `docs/status/lnx.md`.
5. **Benchmarks:** end-to-end frame latency p50/p99, per-stage timings, memory per daemon, gVisor overhead on `core` (runsc vs runc build of the same image).

**Exit:** merged; independent review; tag `p5-lnx-done`.

---

## Phase 6: Proof support and optional extras

**Preconditions:** `g5-lnx-verified`, `g5-win-verified`.
**Spec:** §15 (network-level proof, performance, cross-OS results), §16.

Steps:
1. **pcap sidecar** sharing the gate's network namespace (`network_mode: service:gate`), started only by `make eval`; WIN's eval searches the captures for canaries. Plus a platform test that does the same.
2. **Cross-OS run:** run WIN's `make eval` on this machine and commit the results to the location WIN's eval defines, with this machine's capability report.
3. **Z3 proofs (optional extra):** model the gate's decision procedure and the watchdog; prove "any liveness miss ⇒ AI lane closed" and "a payload labelled non-public is never forwarded", or produce counterexamples. WIN does the policy-side proofs.
4. **Shamir secret sharing (optional extra):** 2-of-3 split of the master key across vault-controlled shares; tests for reconstruct/insufficient shares.
5. **Bit-budget oracle, vault side (optional extra):** vault answers WIN's allow-listed yes/no queries about bound values; WIN does the bit accounting.
6. **Firefox via WebDriver BiDi (optional extra):** a second browser option in `core`, same capture model.

**Exit:** merged; independent review; tag `p6-lnx-done`.

---

## Phase 7: Release

**Preconditions:** `g6-lnx-verified`, `g6-win-verified`.

Steps:
1. **README.md:** assemble from `docs/readme-parts/lnx.md` and WIN's `docs/readme-parts/win.md`: pitch, architecture diagram, one-command quickstart for Windows (WSL2) and Linux, demo walkthrough, results with confidence bounds, and **honest limits** = spec §17 + every entry in `docs/limits/skipped-*.md`.
2. **Images on GHCR** built by CI, pinned by digest; `make up` pulls and runs them with no local build. Test it on a fresh clone.
3. Install guides tested by following them literally on this machine.
4. Final `make ci && make e2e && make test-security && make eval` on a fresh clone.
5. Final independent security review of everything LNX owns, by a fresh subagent with the whole spec.
6. After both `g7-*-verified` tags exist (see Gate 7), tag `v1.0.0` on `main` and create the GitHub Release with the dashboard installers attached.

**Exit:** tag `p7-lnx-done`.

---

## Gate notes for LNX

At every gate, in addition to SHARED §8:
- `make doctor` and paste the capability report into the gate table.
- Gate 4 onwards: run the Linux dashboard build against the live stack and tick a manual checklist (every screen opens, side-by-side matches the egress record, kill switch works, approvals work).
- **Gate 7** = re-run everything from Phase 7 step 4 on `main` and push `g7-lnx-verified`.
