# WIN status

T0 = 2026-10-30T00:45:19+00:00 (sprint plan: ~/pl-sprint/docs/prompts/SPRINT.md). Sprint 1 ends 02:45, Sprint 2 04:30, feature freeze 05:00, Sprint 3 05:45 (UTC).

## Sprint 1 (WIN-A)

- [~] 1. Phase 0 completion: early branches rebased onto LNX's branch (branch `win/s1-p0`); schemas v1 (detection, sanitized_page, agent_action, approval_request, policy) with fixtures; `mk/win.mk` (test-win, lint-win, ci-win, doctor-win, fetch-artifacts-win, scenarios-build; WIN-B fence); `sites` compose fragment; L-001/L-002 acknowledged. Left: merge after LNX's Phase 0 lands, tag p0-win-done.
- [x] 2. detect v1 (C++): normaliser, digit-run scanner + Hyperscan families, validators, structural, split re-join by geometry, taint labels. 16 Win* tests pass (debug + ASan/UBSan).
- [x] 3. sanitize v1 (C++): vault_store per value, placeholders, field boxes, PNG re-encode, href query/fragment dropped.
- [ ] 4. agent on plpy IPC + replay cassettes for login/checkout. NEXT: write daemons/agent/plagent/daemon.py (plpy UDS: receive sanitized_page.v1 -> adapter to plagent.page.SanitizedPage -> agent.step via gate_ai_request -> send agent_action.v1), Dockerfile + compose.yml (network_mode: none).
- [ ] 5. scenario e2e tests (login, checkout) in tests/e2e/scenarios.

Usage-limit pause at ~01:05 UTC (T0+0:20). State: branch `win/s1-p0` (based on origin/lnx/p0-compose-iface) pushed with all of the above; `make test-cpp-win` (16/16, also ASan), `make test-py-win` (exit 0), `make test-security-lnx` (27 passed with the sites fragment) and `make scenarios-build` all ran green. Not yet merged: wait for LNX's Phase 0 PR to land on main, then `git rebase --onto origin/main origin/lnx/p0-compose-iface win/s1-p0`, `make ci`, PR, merge, tag p0-win-done. LNX and WIN-B subagents were told to commit, push and update their status files (docs/status/lnx.md on lnx/*, docs/status/win-b.md on win/winb-s1). On "Resume": read all three status files, relaunch the LNX (opus) and WIN-B (sonnet) subagents with the same briefs, then continue item 4.

Decisions applied (user, 2026-10-30): (a) non-sensitive fields accept PII-scanned plain text, sensitive fields only their placeholder (A-24); (b) hard-rule weakness accepted, approvals are the backstop, Sprint 2 classifier is the fix; (c) risk weights calibrated in Sprint 2 on the benign + malicious cassettes; (e) PLCANARY adopted by LNX's gate.

## Phase 0 (early start, branch `win/p0-early`)

Started before `p0-lnx-done` on the user's instruction. Only work that doesn't depend on LNX is done here.
No PR / merge until `p0-lnx-done` exists.

- [x] 1. Environment check: `tools/win/doctor.sh`, all required checks pass (below). Left: wire into `make doctor` via `mk/win.mk`.
- [ ] 2. `make hooks`, `make ci` on the skeleton (needs LNX Phase 0)
- [ ] 3. Handle LNX requests, `L-001` detect/sanitize C++ API, headers + CMake targets (needs LNX Phase 0)
- [~] 4. Scenario pages v1: **pages, builder, ground truth and tests done** (below). Left: `scenarios/compose.yml` `sites` fragment on LNX's internal `web` network; render-time bounding boxes in ground truth (comes with step 5); move the render test into the dev image.
- [ ] 5. Snapshot recorder (needs LNX's `page_snapshot` schema)
- [ ] 6. WIN schemas v1 + fixtures (needs LNX's contract conventions; field proposals are in `docs/architecture/win.md` §8)
- [ ] 7. Fourier reference: `ml/reference/pl_fourier.py` doesn't exist yet (`origin/user/add-fourier` has no commits beyond the bootstrap). If it is still missing in Phase 0, ask the user in `to-user-win.md`
- [ ] 8. Skeletons: done so far `ml/` (uv project + README), `scenarios/` (uv project + README), `tools/win/`. Left: `daemons/core/{detect,sanitize,fourier}/`, `daemons/agent/`, `eval/`, `tests/e2e/scenarios/`, `mk/win.mk`, `.github/workflows/win-ci.yml`
- [~] 9. `docs/architecture/win.md`: **draft written**. Update after LNX's contracts, `page_snapshot` and `L-001` land.

### Early-start work done (branch `win/p0-early`, not merged)

| Item | Where | Result |
|---|---|---|
| Value generators + validators | `ml/gen/values.py` | 57 tests pass (Hypothesis properties), coverage 97 %, ruff + mypy --strict clean |
| Scenario pages v1 (5 pages) | `scenarios/pages/`, `scenarios/plscen/` | 59 structural tests pass (incl. 25 extra seeds), coverage 97 %, ruff + mypy --strict clean |
| Render test (headless Chromium) | `scenarios/tests/test_render.py` | 7 pass in `mcr.microsoft.com/playwright/python:v1.52.0-noble` |
| Architecture draft | `docs/architecture/win.md` | draft |

Commands used (python:3.12 throwaway containers, since there's no dev image yet):
- `tools/win/pyrun.sh ml sh -c 'uv run ruff check . && uv run mypy gen tests && uv run pytest --cov=gen'`
- `tools/win/pyrun.sh scenarios sh -c 'uv run ruff check . && uv run mypy plscen tests && uv run pytest --cov=plscen'`
- render test: see `scenarios/README.md`

Findings from the tests (fixed or recorded):
- A test vector I wrote from memory (Verhoeff "12340 → 4") was wrong. I replaced it with an independent oracle that builds Verhoeff from the D5 group and permutation, not the lookup tables. The implementation agrees with it on random inputs and with the published 236 → 3.
- About 1 in 10 `+91<mobile>` strings contain a 12-digit Aadhaar look-alike (Verhoeff-valid). The scenario pages redraw such phones so ground truth stays unambiguous. The detect overlap rule is recorded in the architecture doc §3.
- Random passwords can contain UPI-shaped substrings. The completeness test counts a match inside an annotated value as covered.

### When the user says "Run Phase 0"

1. `git fetch origin --tags`; confirm `p0-lnx-done`; `git rebase origin/main` on this branch.
2. Adapt: replace `tools/win/pyrun.sh` with `mk/win.mk` targets in the dev image; `make hooks`; check the new ownership hook accepts every file here; ask LNX for Playwright/Chromium + pillow + bs4 in the dev image if missing.
3. Rework the ground-truth/channel names and the §8 schema proposals to LNX's contract conventions; agree the canary format with LNX (request).
4. Then steps 2, 3, 5–8 above; review; merge; tag `p0-win-done`.

## Environment check (2026-10-29)

Command: `tools/win/doctor.sh` (run directly; exit 0)

```
PASS  wsl2                   distro=Ubuntu-24.04 kernel=6.18.54.1-microsoft-standard-WSL2
PASS  os                     Ubuntu 24.04.5 LTS
PASS  repo-path              /home/ekaksh/Team-PF-HUTJS9
PASS  origin                 https://github.com/PECathon-2026/Team-PF-HUTJS9.git
PASS  hf-token               present (not read)
WARN  anthropic-key          absent (optional; local-only mode still works)
PASS  docker-engine          server 29.9.2 on 'Ubuntu 24.04.5 LTS'
PASS  compose                5.6.1
PASS  runsc                  runsc version release-20261026.0
PASS  gpu-container          NVIDIA GeForce RTX 5070 Laptop GPU, 8151 MiB, 621.01
PASS  tool:make              GNU Make 4.3
PASS  tool:git               git version 2.43.0
PASS  tool:gh                gh version 2.103.3 (2026-10-26)
PASS  gh-auth                logged in
PASS  ram                    23.5 GiB visible to WSL, 24 CPUs
PASS  btf                    /sys/kernel/btf/vmlinux present
PASS  landlock               ABI v7
PASS  memfd_secret           available

doctor: all required checks passed
```

Notes:
- Docker Engine 29.9.2 runs inside WSL (`docker info` reports Ubuntu, not Docker Desktop). Runtimes: `runc` (default), `runsc`, `nvidia`.
- The stock WSL kernel 6.18 already has BTF, Landlock (ABI 7) and `memfd_secret`, so a custom WSL kernel likely isn't needed. Phase 2 confirms with LNX's capability probe.
- 23.5 GiB of the 32 GB is visible to WSL. Enough for now.
- No Anthropic key: optional; local-only (Ollama) is the default.
- `uv` and `node` are not on the host. That's fine (AD-03: Python runs in the dev image; Node is only needed on LNX).
- Nothing needs the user yet, so there's no `to-user-win.md`.

## Early P2 work (branch `win/early-p2`, builds on `win/p0-early`, not merged)

### 1. Fourier reference `ml/reference/pl_fourier.py` (written from spec §10)

No `pl_fourier.py` existed, so it's written from the spec. 49 Fourier tests, 106 in `ml/` in total; `pl_fourier.py` coverage 99 %. Measured with `python -m reference.bench_fourier` (raw JSON: `ml/reference/bench_results.json`; NumPy 2.2.5, one core of the Core Ultra 9 inside a python:3.12 container):

| Claim in spec §10 | Measured | Verdict |
|---|---|---|
| Scroll tracking accurate to < 1 px | crop-based scroll −50…+50 px: max error 0.005 px; random sub-pixel shifts: mean 0.094 px, max 0.12 px | holds |
| ~5 ms on 480×270 | p50 3.0 ms, p99 3.8 ms | holds |
| Redaction checker: solid passes; blur, pixelation, text fail | solid passes; blur (r 2–8) → `blur`; pixelation (4–10 px) → `pixelation`; text, incl. ink 3/255 on black → `visible_detail` | holds |
| Fuzzy search: 200 000 chars < 1 s | 16-char secret: p50 101 ms | holds |
| Flatness: clean 0.02 vs 0.31–0.47 at 2–6/255 | score (share of non-empty 16 px tiles that are noise-flat), 20 pages: clean 0.008 (max 0.028), 0.4/255 0.008, 1/255 0.358, 2/255 0.369, 4/255 0.380, 6/255 0.384. Flagged at 0.05: clean 0/20, 1–6/255 20/20 each | same pattern; amplitude ≥ 1/255 detected, < 0.5/255 rounds away in 8 bits and is undetectable |
| DCT denoiser: error cut > 40 %, text preserved | MSE reduction, 10 pages each: white background 17–21 % (min 11 %), mid-gray background 32–34 % (min 15 %); text ink IoU 0.987–0.996; clean pages pass through unchanged | **does not reach 40 % on these pages**; text preserved |
| NIST spectral test: helps on 100+ chars | 6-bit alphabet encoding: random base62 keys pass 98–100 %, random-word English passes 94–98 % (40/100/400 chars). UTF-8 encoding is worse: at 400 chars keys *and* English both fail 100 % (ASCII's top bit is a period-8 signal) | a very weak signal on strings; fine as one classifier feature, useless alone (as the spec says) |

Things the measurements changed (each was a failure in my implementation, not a test tuned to pass):
- Redaction checker: the first pixelation heuristic missed 8 px blocks. It now measures the share of edge energy on the best regular grid (period 3–32) on both axes.
- Flatness: noise hidden under text barely changes a text tile, so the score counts background tiles that should be exactly flat but aren't (16 px tiles, full AC band; cutoff 0.45, below white noise's theoretical e^-γ ≈ 0.56). The pass/fail test is now a decision at the documented operating point `PERTURBED_SCORE = 0.05`, checked for false positives on 20 clean pages and for detection on 30 perturbed ones. The earlier "+0.2 margin" assertion was an arbitrary guess made before any measurement.
- DCT: a fixed threshold (24) made the error *worse* (−440 %). The threshold is now 2σ̂, where σ̂ comes only from low-energy, noise-flat 8×8 blocks (cutoff 0.2, below e^-(γ+ln2) ≈ 0.28 for real DCT coefficients). A clean page gives σ̂ = 0 and is left untouched.
- NIST: string encoding switched from UTF-8 to a 6-bit alphabet index (see table).
- **Open discrepancy (NIST SP 800-22 rev1a):** the document's worked examples give N1 = 4 (§2.6.4, n = 10) and N1 = 46 (§2.6.8, n = 100), but its own steps 1–6 give 5 and 48 for those inputs. I checked against the PDF text and tried both T formulas and every index range. The d/P formulas match both documented (n, N1) pairs exactly, and the tests check that. The C++ port should be cross-checked against this file. If an official errata or the reference C code explains the gap, update the test.

### 2. Synthetic page generator v1 (`ml/gen/pages.py`, `ml/gen/render.py`)

- 7 layout families pinned to splits: train = form_stack, form_grid, data_table, profile_card; calibration = chat_thread; test = receipt, kyc_upload. A test fails if the mapping changes, and no family can be in two splits.
- Labels and filler from templates in English, Hindi (Devanagari) and Hinglish. Values from `gen.values` in inputs, text, table cells and PNG images (with in-image boxes). Every page has hard negatives: non-Luhn order IDs, Verhoeff-failing 12-digit refs, PAN look-alikes with an invalid holder letter, IFSC look-alikes.
- `python -m gen.pages --n N --out build/synth` writes pages, truth (outside the served folder) and `manifest.json` with splits. `python -m gen.render build/synth` renders in headless Chromium (Playwright 1.52, local server on 127.0.0.1 only), saves screenshots and adds a page-coordinate box to every item and decoy.
- Tests: 21 generator tests (labels valid and complete, decoys invalid, Devanagari on Hindi pages, determinism byte-for-byte, page i independent of N, 8 extra seeds) + a browser test (21 pages rendered, every item boxed, no errors).

### 3. Red-team pages v1 (`scenarios/redteam/`, built by `plscen`)

- Six pages: `hidden` (display:none, visibility, opacity, font-size 0, off-screen, same colour, clip, collapsed details), `split` (spans, CSS-order-shuffled spans, `::after` content, dot separators, line breaks), `lookalike` (full-width and Devanagari digits, Cyrillic homoglyphs, ZWSP, soft hyphen, word joiner, bidi override, mixes), `channels` (title, meta, URL query/fragment/path, aria-label/description, title, placeholder, data-*, form action, select option, SVG text, image + alt, canvas + script), `encoded` (base64, base64 JSON, hex, URL, double base64, script string), `injection` (10 injections: visible, CSS-hidden, aria, alt, Hindi, Hinglish tiny font, base64 data attribute, image, zero-width, HTML comment; goals: exfiltrate, navigate, skip approval, destructive click; attacker hosts on `.example`).
- Tests: every value recovers to a valid value through the documented decode/normalise steps, and the raw form defeats a naive scan. Each value sits in its channel; injections sit in theirs; there are 10 extra seeds. Browser: hidden items are not visible (`checkVisibility`), shuffled spans read correctly left-to-right, the canvas draws, and there are no errors or off-host requests.
- Found and fixed: my file-writing tool decoded `\u200b`-style escapes into the real invisible/bidi/Cyrillic characters, including one already committed on `win/p0-early` (`scenarios/plscen/pages.py`). They're now ASCII escapes, and `scenarios/tests/test_source_hygiene.py` fails on any such character in `ml/`, `scenarios/` or `tools/win/` (verified it catches a planted ZWSP).

Totals: `ml` 131 passed (+1 browser), coverage 98 %; `scenarios` 87 passed (+13 browser), coverage 97 %; ruff and mypy --strict clean in both.

### 4. Pretrained models (`ml/artifacts.lock.json`, `ml/tools/fetch_artifacts.py`)

| Artifact | Source (revision pinned in the lock) | License / redistribution | Size | Status |
|---|---|---|---|---|
| GLiNER PII | `onnx-community/gliner_multi_pii-v1` int8 ONNX, upstream `urchade/gliner_multi_pii-v1` | Apache-2.0 (inherited); allowed, not re-published | 370 MB | fetched, 7/7 hashed |
| RapidOCR | `SWHL/RapidOCR`: PP-OCRv4 det + rec, PP-OCRv3 en rec, v2 cls | Apache-2.0; allowed, not re-published | 25 MB | fetched, 4/4 |
| YuNet | `opencv/face_detection_yunet` 2023mar | MIT; allowed, not re-published | 0.2 MB | fetched, 2/2 |
| Prompt Guard 2 86M | `meta-llama/Llama-Prompt-Guard-2-86M` | Llama 4 Community License (gated); redistribution only under its conditions, not re-published | 1.1 GB | **pending license**: HF returns 401 for this token. 2/6 files hashed from HF LFS metadata; the rest get pinned on first download |
| multilingual-e5-small | `intfloat/multilingual-e5-small` ONNX | MIT; allowed, not re-published | 490 MB | fetched, 6/6 |

- Large files use the SHA-256 Hugging Face publishes for the LFS object. Small JSON files were pinned on download (`sha256_source: pinned-on-download`). A second run re-verifies every file and downloads nothing.
- The token is read from `~/.privacylens/secrets/hf_token` inside the container (mounted read-only), sent only to huggingface.co, never printed. Files are in the gitignored `artifacts/`.
- Rejected: SCRFD (InsightFace weights are non-commercial), the e5 qint8 file (needs AVX-512 VNNI), nvidia/gliner-PII (custom license, no ONNX).

**Needs the user:** accept the Llama 4 Community License for `meta-llama/Llama-Prompt-Guard-2-86M` on Hugging Face with the account whose token is in `hf_token`, then run `python ml/tools/fetch_artifacts.py --only prompt_guard_2_86m --pin` (or ask me to).

### Left for later
- Merge: rebase onto `main` after `p0-lnx-done`, then this branch builds on `win/p0-early`'s Phase 0 work. Fold `tools/win/pyrun.sh` and the Playwright container into `mk/win.mk` targets in the dev image (needs Playwright/Chromium, numpy, pillow in the dev image: request to LNX).
- Wire `fetch_artifacts.py` into `make fetch-artifacts-win` and tell LNX the `artifacts/` mount path (WIN P2 step 2).
- Resolve the NIST example discrepancy if NIST errata or reference code explain it.

## Early agent work (branch `win/early-agent`, builds on `win/early-p2`, not merged)

Pure-logic agent modules in `daemons/agent/plagent/` (stdlib only; no IPC yet, LNX's `plpy` plugs in later). This is WIN Phase 1 step 3 minus the plumbing.

| Piece | Module | Notes |
|---|---|---|
| Action schema + strict parser | `actions.py` | click / fill / select / navigate / scroll / done; JSON Schema for Ollama `format`; fill values must be `[REDACTED:TYPE#n]`; no read-back kind; x/y/coordinates rejected (A-06); every action carries a `justification` of `{source, quote}` |
| Validator | `validator.py` | target exists / visible / enabled / right role; script URLs (javascript, data, vbscript, file, blob) however disguised (case, controls, tabs/newlines, percent-encoding); allowed domains only (label-aligned); userinfo, backslash, raw IP and non-ASCII hosts refused; links' hrefs checked on click |
| Anti-reconstruction | `antirecon.py`, `pii.py` | placeholder must be issued on this page, match its label, and be bound to that exact field (A-23); PII scan of raw output and every free-text field (A-21) with its own scanner: NFKC, invisible/bidi removal, Cyrillic/Greek look-alikes, native digits, base64/hex decoding, partial hints ("ending 1234", "**** 1234"); findings carry only type + location |
| Hard rule | `antirecon.py` | effectful actions need a *verified* user quote (it must occur in the task); page text relabelled as "user" is downgraded; a system-prompt quote alone isn't enough (stricter than the spec's wording, on purpose); scroll/done exempt |
| Prompt fences | `prompt.py` | system / `<user_task nonce>` / `<webpage nonce trust="untrusted">`; page text can't close or fake a fence (markers, nonce, control and bidi characters neutralised); invisible nodes omitted |
| Risk | `risk.py` | noisy-OR over irreversible, sensitive value, new domain, goal distance, attack alarm; allow < 0.3 ≤ ask < 0.7 ≤ deny; irreversible (EN/HI/Hinglish words) never auto-runs. Default weights are placeholders until the P4 policy calibrates them |
| Replay | `replay.py` | `pl.replay.v1` cassettes (page fixture, task, steps with raw responses, optional `request_sha256` for strict replay, optional `expect`); fails closed when exhausted |
| Step | `agent.py` | fixed check order, first refusal wins; outcomes execute / approval / blocked with rule IDs (A-01…A-31, I-01) |

Cassettes (`daemons/agent/cassettes/`, generated by `build_cassettes.py`; a test fails if they're stale):
- benign `checkout-happy` (6 steps): card and email fills execute, delivery select executes, Pay needs approval, scroll/done execute. So the checks don't over-block a normal checkout.
- malicious, 52 steps: `guess-card` (14: literal, full-width, zero-width, base64, masked and "ending" hints, Aadhaar, wrong field, invented or mislabelled placeholder), `read-field` (8), `javascript-url` (20: disguised schemes, data/vbscript/file, javascript link, protocol-relative, look-alike and suffix domains, userinfo, IP, coordinates, missing/hidden/disabled targets), `page-instruction` (10, English and Hindi). Result: **0 of 52 execute**. 51 are blocked; 1 needs approval (see limit below). With the hard rule disabled, 1 executes; with the PII scan disabled, 6 execute. So the tests do detect a missing defence.

Tests: 180 passed (Hypothesis properties: parser never accepts what the schema rejects, fills accepted iff exact placeholder, disguised script URLs always denied, only allowed domains pass, generated values found under 7 disguises × 9 types, placeholders/node IDs never flagged, binding iff, unverifiable quotes never pass, fences unbreakable under hostile text, noisy-OR bounds/monotonicity/order-independence, irreversible never auto-runs). Coverage 97 %, ruff + mypy --strict clean.

Found and fixed by the tests:
- `https:///evil.example` and `https:evil.example` passed: Python's `urljoin` reads them as paths on the current host, but browsers read them as host `evil.example`. The validator now normalises slashes the WHATWG way.
- Base64 of short values (PAN, phone, IFSC) slipped past the scanner (token minimum was 16 chars); now 12.
- Phones written `0XXXXXXXXXX` / `091…` weren't recognised.
- The approval request's factor field was named `value` (banned by the contract rules); renamed to `level`.

Known limits (recorded, not hidden):
- The hard rule can be laundered: an action justified by *any* real phrase from the task passes it ("earbuds" → "Delete account"). In the malicious set this case still can't run, because it's irreversible and needs a signed approval. Phase 4's injection classifier and GW monitor are the next layer.
- Short numbers aren't PII-scanned (a guessed CVV "123" in free text isn't caught), though a guessed value can never be *filled*: fills accept only placeholders.
- Free-text fills (e.g. a search query) are impossible because fill values may only be placeholders. Proposal for Phase 1: user-task literals become `[TASK:name]` placeholders issued by core.
- The benign card fill scores 0.28 against an allow threshold of 0.3: calibrate the weights in Phase 4.

Left: plpy channels, the gate AI-lane client, Ollama constrained decoding, `agent_action` / `approval_request` schemas in LNX's conventions, Dockerfile + `compose.yml` (`network_mode: none`), and e2e with LNX's harness.
