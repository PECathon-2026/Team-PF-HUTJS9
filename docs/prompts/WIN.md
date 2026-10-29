# WIN prompt file: Windows laptop (inside WSL2)

You are **WIN**: the intelligence machine. You build detection and sanitization inside `core`, the agent, the scenario pages, all ML and training, the evolved attacker, and the evaluation that proves everything.

Read `docs/prompts/SHARED.md` first. Everything there applies here.

## Your machine and how to use it

- Windows laptop, Core Ultra 9, **32 GB RAM, 8 GB VRAM**. You run **inside WSL2 Ubuntu 24.04** with Docker Engine installed in WSL (not Docker Desktop). The repo lives at `~/Team-PF-HUTJS9` on the Linux filesystem.
- **Never** work from `/mnt/c`, never run git or builds through Windows tools. The only time you touch the Windows side is to launch the dashboard installer for testing (`explorer.exe` / `powershell.exe` interop) at gates, and only when the user asks you to.
- You're the strong machine: you run the full stack with a real local model (Ollama on the GPU), GPU training, the evolution loop and the big evaluation runs. Give WSL most of the RAM (the user set this in `.wslconfig`).
- The WSL kernel may lack some features LNX's probe checks (BTF for eBPF, `memfd_secret`, Landlock). Phase 2 handles that.

## What you own

See SHARED.md §3. In short: `daemons/core/detect/**`, `daemons/core/sanitize/**`, `daemons/core/fourier/**`, `daemons/agent/**`, `ml/**`, `eval/**`, `scenarios/**`, `tests/e2e/scenarios/**`, `mk/win.mk`, `tools/win/**`, `.github/workflows/win-*.yml`, your schemas, and your docs files.

Your schemas (producer = WIN): `detection`, `sanitized_page`, `agent_action`, `approval_request`, `policy`, `eval_results`, `xray_*` (one per X-ray visual that's fed by your code).

The `core` daemon is LNX's process; your detect/sanitize/fourier code is a set of **C++ libraries** it links. Agree the C++ API in Phase 0 (LNX's request `L-001`).

---

## Phase 0: Environment and foundations (runs after LNX Phase 0)

**Preconditions:** tag `p0-lnx-done`.
**Spec:** §2 (OS independence), §15 (the five scenario pages), §10 intro.

Steps:
1. **Environment check** (`tools/win/doctor.sh`, wired into `make doctor` via `mk/win.mk`): confirm you're in WSL2, the repo is not under `/mnt/`, `git remote get-url origin` is `https://github.com/PECathon-2026/Team-PF-HUTJS9.git`, `~/.privacylens/secrets/hf_token` exists (check presence only; never print it), Docker Engine (not Desktop) is the active daemon, `runsc` works (`docker run --rm --runtime=runsc hello-world`), the GPU works in containers (`docker run --rm --gpus all … nvidia-smi`), RAM available to WSL, kernel version. Record the output in `docs/status/win.md`. Anything that only the user can fix goes into `docs/requests/to-user-win.md` and your final message.
2. `make hooks`, then `make ci` on the skeleton. It must pass in WSL. Platform failures become requests to LNX.
3. Handle LNX's requests (at least `L-001`, the detect/sanitize C++ API). Create your real public headers in `daemons/core/detect/include/pl/` and `daemons/core/sanitize/include/pl/` (adopt or amend LNX's proposal; explain amendments in your `done-by-win.md` entry), plus CMake targets with one passing test each.
4. **Scenario pages v1** in `scenarios/`: the five required scenarios (checkout, login, customer support chat, video call, developer settings), plain HTML/CSS/JS, served by a `sites` container (`scenarios/compose.yml` fragment on the internal `web` network per AD-05). Every planted value is synthetic and valid-format (cards pass Luhn and match real IIN ranges; Aadhaar passes Verhoeff; valid PAN/IFSC/UPI shapes); every one is annotated in a ground-truth JSON next to the page (type, location, element selector, bounding box after render). Video-call faces must be synthetic and license-clean (generated or drawn avatars), never photos of real people. Tests: every annotated value validates; every page renders; annotations match the DOM.
5. **Snapshot recorder** (`ml/tools/record_snapshot.py`, uv project in `ml/`): renders a page in headless Chrome over CDP and dumps a `page_snapshot` fixture in **LNX's schema**, plus a ground-truth file. Produce fixtures for all five scenarios into `scenarios/fixtures/`. These are what you develop detection against before the live stack exists.
6. **Your schemas v1** with valid/invalid fixtures: `detection`, `sanitized_page`, `agent_action` (click/fill/select/navigate/scroll/done; fill values may only be placeholders), `approval_request`, `policy`.
7. **Fourier reference:** if `ml/reference/pl_fourier.py` exists (the user adds it in the bootstrap commit if they have it), run its tests and record the result. If it doesn't exist, ask the user for it in `to-user-win.md` and carry on.
8. Skeletons for all your folders (LNX doesn't create anything inside them): `daemons/core/detect/`, `daemons/core/sanitize/`, `daemons/core/fourier/`, `scenarios/`, `tests/e2e/scenarios/`, `daemons/agent/` (uv project, Dockerfile, `compose.yml` fragment with `network_mode: none`), `ml/`, `eval/` (uv projects), each with a short README stating owner and purpose, `mk/win.mk` with `test-win`, `lint-win`, `coverage-win`, `fuzz-smoke-win` targets running in the dev image. CI workflow `.github/workflows/win-ci.yml` for your unit tests.
9. Write `docs/architecture/win.md`: your components, the detection pipeline, the agent loop, the ML plan, how your outputs reach the attestation chain.

**Exit:** merged; tag `p0-win-done`. Then the user runs **Gate 0** on both machines.

---

## Phase 1: Walking skeleton (parallel with LNX P1)

**Preconditions:** `g0-lnx-verified`, `g0-win-verified`.
**Spec:** §4 (text clean-up, pattern detection, structural detection), §5 (solid fill, fixed-size boxes, placeholders, scrubbing every hiding place), §9 (all of it at basic level), §7 (prompt-injection firewall: provenance + hard rule; action risk scoring: basic).

Steps:
1. **detect v1** (C++ library):
   - Text clean-up: NFKC, a confusables map (full-width digits, Cyrillic/Greek look-alikes), invisible-character removal, and **re-joining split values by on-screen geometry** (adjacent boxes on the same line, using the snapshot's boxes/R-tree).
   - Vectorscan multi-pattern scan for every type in spec §4's table, then validators: Luhn + IIN ranges, Verhoeff + first digit 2–9 for Aadhaar, PAN structure, IFSC, UPI, email, phone (Indian + international), IPv4/IPv6, PIN code, bank account (context-required), passport, DOB, API keys by prefix (`sk-`, `ghp_`, `AKIA`, JWT `eyJ…`), OTP only with an OTP field signal.
   - Structural detection: password inputs (incl. show-password toggles), autocomplete tokens, ARIA roles, nearby labels (CVV, OTP…), chat-message containers.
   - Output: `DetectionSet` with type, node/box, evidence list, score, and a **taint label** (LNX's lattice type).
2. **sanitize v1** (C++ library): fixed-length placeholders `[REDACTED:TYPE#n]` with random per-session numbering; solid-fill boxes covering the **field box** (not the text) plus margin, rounded to fixed widths for text; PNG re-encode with metadata stripped; scrub URL + query, title, aria-label/description, title tooltips, placeholder attr, `data-*`, alt text, image metadata; output the sanitized accessibility tree + redacted screenshot as `sanitized_page`.
3. **agent v1** (Python, `network_mode: none`, talks only over plpy channels):
   - Loop: receive `sanitized_page` → prompt with **provenance fences** (system / user task / webpage, webpage text clearly fenced and labelled untrusted) → request through the gate AI lane → **constrained decoding** to the `agent_action` JSON schema (Ollama `format` with the schema; re-validate anyway) → action validator → send to `core`.
   - **Action validator:** target node exists and is visible; no `javascript:` URLs; navigation only to allowed domains; no coordinate clicks.
   - **Anti-reconstruction:** sensitive fields accept only their matching placeholder; no read-back capability exists; scan model output for PII-like content (block); system prompt forbids guessing; no partial hints anywhere.
   - **Hard rule:** an action whose only justification comes from webpage-provenance text is blocked.
   - Basic **noisy-OR risk** with the spec's factors; irreversible actions (pay/submit/delete) always produce an `approval_request`; timeout = deny.
4. **Scenario e2e tests** in `tests/e2e/scenarios/` (LNX's harness runs them): login and checkout complete with the `replay` provider, using placeholders for secrets; assertions on task success and on the sanitized page (no planted value in any channel).
5. Record `replay` cassettes for these tasks with a real Ollama model on this machine (`make e2e-live` path), commit the cassettes (they contain sanitized prompts only; run the leak scan over them before committing).

Tests: exhaustive validator tests + RapidCheck/Hypothesis properties (e.g. every generated valid card is detected in every hiding channel; random 16-digit non-Luhn strings aren't), fuzz the normaliser and scanner ≥ 10 min, ASan/UBSan, per-type recall/precision on the scenario fixtures recorded in your status file, agent tests including a **malicious replay LLM** (guesses a card, asks to read a field, tries `javascript:`, follows a page instruction) that must all be blocked.
**Exit:** merged; independent review; tag `p1-win-done`.

---

## Phase 2: Detection depth, Fourier, generator v1, WSL kernel

**Preconditions:** `g1-lnx-verified`, `g1-win-verified`.
**Spec:** §4 (OCR, faces, secrets, Sinkhorn, spectral clustering, quasi-identifiers), §5 (adaptive redaction), §10 (all), §6 (taint labels through sanitize), §3 (detection cache), §14 (synthetic pipeline: values + layouts).

Steps:
1. **WSL kernel features:** run LNX's capability probe here. For each missing feature, decide with evidence: fallback, or build a custom WSL kernel (`microsoft/WSL2-Linux-Kernel`, pinned tag, config fragment enabling what's missing, built in a container). If building, produce the `bzImage`, write exact instructions for the user (copy to a Windows path, `.wslconfig` `kernel=` line, `wsl --shutdown`) in `to-user-win.md`, stop and wait for the user, then re-run the probe and record before/after.
2. **Artifact plumbing first:** before adding the first pretrained model, create `ml/artifacts.lock.json` and the `fetch-artifacts-win` make target (AD-08: source URL/revision, SHA-256, license per artifact; verify every hash; models land in the gitignored `artifacts/` folder that LNX's compose mounts read-only). LNX needs this to run these models on Mint, so file a request telling LNX the mount path once it works.
3. **OCR** on images/canvas/video regions only (page text wins wherever it exists): RapidOCR (PaddleOCR models, ONNX Runtime C++). **Noisy-channel correction:** confusion-weighted candidate search over OCR readings; if any plausible reading passes the check digit, redact.
4. **Faces:** YuNet or SCRFD (ONNX) + Kalman filter + Hungarian matching + persistence for N missed frames + whole-tile lock once a tile has shown a face. Simulation tests with injected misses verify the spec's leak-probability argument.
5. **GLiNER** (pretrained PII model, ONNX, quantised) for names, addresses, medical terms; tokenizer in C++ (e.g. tokenizers-cpp) or, if that fails, a sandboxed helper process inside `core`'s container (ADR either way); output cleaning so spans never break mid-token.
6. **Unknown secrets:** character 5-gram Kneser–Ney model (trained on public code/text corpora, never real secrets), context words, NIST spectral test (long strings only), compression ratio.
7. **Sinkhorn** label-to-field matching (soft assignments with confidence), **spectral clustering** into page blocks (~30), **quasi-identifier** detection per block.
8. **Adaptive redaction:** policy-controlled safe attributes ("filled: yes").
9. **Taint labels** carried through sanitize: anything overlapping or derived from a sensitive item gets the join of labels.
10. **Detection cache:** node ID + keyed content hash → result.
11. **Fourier C++ port** (`daemons/core/fourier/`): phase correlation (scroll tracking API that LNX will call), redaction checker (run on every sanitized frame as an assertion: a box that fails blocks the frame), spectral flatness detector, DCT denoiser for outgoing screenshots. Cross-check every function against `pl_fourier.py` outputs on the same inputs (tolerances documented). The FFT fuzzy matcher stays Python (`eval/`, trusted zone).
12. **Synthetic generator v1** (`ml/gen/`): Faker `en_IN` + your own valid generators (Aadhaar/PAN/cards/UPI/IFSC), randomised HTML/CSS layout families, values in inputs, text, tables, images and video frames, rendered in headless Chrome, labels for free. Seeds everywhere.
13. **Red-team pages v1** in `scenarios/redteam/`: hidden text, split values, look-alikes, invisible chars, data in URLs/labels/alt/images, simple prompt injections.

Tests: unit + property per detector; OCR correction test set; face tracking simulation; redaction checker (solid passes; blur, pixelation, visible text fail); Fourier cross-checks; generator determinism (same seed → same hashes); per-type recall/precision on scenarios + red-team pages; performance budget per stage recorded.
**Exit:** merged; independent review; tag `p2-win-done`.

---

## Phase 3: ML fusion, calibration, training artifacts

**Preconditions:** `g2-lnx-verified`, `g2-win-verified`.
**Spec:** §4 (label model + classifier, conformal prediction, explainable scores), §14 (all), §13 (Parquet, artifacts).

Steps:
1. **Full synthetic pipeline:** add Ollama-written surrounding text (English, Hindi, Hinglish) on this machine's GPU; thousands of pages; Parquet outputs under `ml/data/` (gitignored); **splits by layout family** for train / calibration / test.
2. **Label model** (Dawid–Skene / Snorkel-style, including correlated-detector handling) fitted on unlabeled pages, including a fixed list of **real public web pages** (unlabeled; store only derived features, never raw page text).
3. **LightGBM fusion classifier** over detector outputs, structure, label semantics and position. Export the model for the **LightGBM C API** used inside `core`; use `predict_contrib` for **SHAP explanations** (spec's "CARD 0.97: Luhn +3.0, …").
4. **Conformal thresholds** per data type (α configurable, default 1 %), written to a threshold file; `core` applies them.
5. **GLiNER fine-tune** only if per-type recall on the calibration split demands it (8 GB VRAM is enough for the base-size model; record the decision and numbers either way).
6. **Overfitting guards:** no layout family appears in two splits (test), the five scenario pages are never in training (test), metrics on real unlabeled pages via the label model.
7. **Artifacts (AD-08):** **your own** trained outputs (fusion model, threshold file, fine-tuned weights, later the attack index) → GitHub Release `models-v<N>` on `PECathon-2026/Team-PF-HUTJS9` via `gh release`. Third-party pretrained models (GLiNER, RapidOCR, YuNet/SCRFD, Prompt Guard) are **not** re-published: the lock file pins their original source URL/revision, hash and license, and `make fetch-artifacts` (yours) downloads them from there (using the HF token for gated ones) and verifies every hash. `ml/artifacts.lock.json` covers both kinds. Tell LNX (request) to add them to the attestation chain. Model card per model in `ml/models/README.md` (data, metrics, limits).
8. Integrate fusion + conformal + SHAP into `detect`; explanations obey the explanation-safety rule (types, placeholders, element IDs, evidence only; failure to explain ⇒ block).

Tests: empirical miss rate on the held-out test split ≤ α within a Clopper–Pearson bound; reproducibility (rerun from seed → identical artifact hashes, or document the source of nondeterminism and bound it); explanation-safety tests; the leak scan over every artifact and the datasets' derived outputs.
**Exit:** merged; independent review; tag `p3-win-done`.

---

## Phase 4: Agent intelligence and attack defense

**Preconditions:** `g3-lnx-verified`, `g3-win-verified`.
**Spec:** §7 (all), §5 (smart context keeping), §4 (site memory, optional), §13 (sqlite-vec), §9 (constrained decoding, complete).

Steps:
1. **Signed policy engine:** `policy.yaml` with rule IDs (D-, E-, A-, I-, U-); verification with LNX's signing library (unsigned or tampered ⇒ refuse); every decision names its rule. A small API for the dashboard: list rules, submit signed edits, **"mark missed field" ⇒ new signed U-rule**.
2. **Injection firewall complete:** provenance fences + hard rule (from P1), **Llama Prompt Guard 2** (ONNX; needs the user's HF license acceptance, see SETUP), and **your own classifier** (embeddings + LightGBM).
3. **Evolved attacks:** mutation operators from spec §7 (rephrase, translate to Hindi/Hinglish, CSS/tiny-font/ARIA/image hiding, base64/confusables/invisible encoding, splitting); real sandboxed runs against the full stack with Ollama on the GPU; keep attacks that worked **and** evaded; **MAP-Elites** archive over technique × hiding channel × language; retrain the classifier each generation alongside normal page text. Hold out whole attack families for evaluation. Emit evolution-arena data for X-ray.
4. **RAG injection detection:** sqlite-vec index in `agent` (read-only, attested) of evolved attacks with labels; nearest neighbours raise the score and produce explanations ("0.91 similar to attack #482, CSS-hidden"). Never embed raw page text: only sanitized text. Fallback: NumPy exact search.
5. **Gromov–Wasserstein monitor** (POT): page block structures vs the attack-structure library; agent-journey shape vs normal sessions; fused GW with content features; distances calibrated into alarm levels against normal sessions.
6. **Risk scoring complete:** noisy-OR over all spec factors including the GW alarm; allow / ask / deny thresholds in policy; approval requests list factors.
7. **Privacy budget** per session (types and values touched; over budget ⇒ approval).
8. **Smart context keeping:** greedy submodular selection of harmless context under the privacy budget, with usefulness scores measured on generated pages. Unit-test the greedy guarantee on small instances against brute force.
9. **Site memory (optional):** structure-only sqlite-vec store in `core` (via your detect library), can only **raise** sensitivity, user wipe API ("forget this site" / "forget all").

Tests: injection detection on held-out families (report TPR at fixed FPR on normal pages); hard-rule tests; GW calibration (alarm rate on normal sessions matches the nominal level); risk scoring units; budget tests; policy signature tests; full scenario e2e still green.
**Exit:** merged; independent review; tag `p4-win-done`.

---

## Phase 5: X-ray data and performance

**Preconditions:** `g4-lnx-verified`, `g4-win-verified`.
**Spec:** §12 (X-ray mode data), §3 (incremental processing, cache-aware performance), §15 (performance benchmarks).

Steps:
1. **`xray_*` schemas and emitters** for everything your code computes: detection heat per element, spectral embedding coordinates and blocks, GW transport plan, phase-correlation surface, per-tile spectrum/flatness, taint flows, risk factors + SHAP values, nearest-attack results, evolution arena. Metadata only (no values, no raw text); contract linter must pass. Provide fixtures early so LNX can build visuals.
2. **Confidence sequences reference** (`eval/stats/`): Python implementation + reference vectors for LNX's dashboard cross-check.
3. **Detection performance:** cache-friendly data access over the flat arrays, Vectorscan database sized to fit L2/L3, detection cache hit rates, SIMD where it pays; `perf` cache-miss counters before/after.
4. **Benchmarks:** naive vs incremental vs SIMD detection; per-stage p50/p99; recorded in `docs/status/win.md` and in a JSON your eval can publish.

**Exit:** merged; independent review; tag `p5-win-done`.

---

## Phase 6: Evaluation and proof

**Preconditions:** `g5-lnx-verified`, `g5-win-verified`.
**Spec:** §15 (all), §16 (Z3 policy side, bit-budget accounting, compression randomness).

Steps:
1. **`make eval`** in Docker with fixed seeds: runs the five scenario pages (never trained on), the synthetic test split, the red-team suite (incl. LNX's exfiltration attempt and the held-out evolved families), on the `replay` provider by default and with Ollama via `make eval-live`. Results as `eval_results` JSON under `eval/results/<machine>/` (committed; small).
2. **Metrics:** per-type recall, redaction precision (+ pixel IoU for image boxes), F2, task success, context preservation (with ÷ without redaction), performance per stage and per daemon.
3. **Honest statistics:** Clopper–Pearson per type, page-clustered bootstrap, rule of three for zero-leak claims, McNemar vs the naive baseline, confidence sequences for long runs, breakdowns by type / location / attack.
4. **Differential leakage test** (same task, different secrets, replayed AI responses ⇒ outgoing messages must be byte-identical) and **leakage in bits** (many secrets ⇒ 0 bits when all outputs are identical).
5. **Network-level proof:** search LNX's gate pcaps for canaries and their encodings.
6. **Naive baseline agent** that sends raw screenshots/page data, same tasks, same model.
7. **FFT fuzzy secret search** over all logs and results inside the trusted zone (catches mangled or partial leaks).
8. **Cross-OS results:** your run here + LNX's run on Mint, side by side with both capability reports, in the results JSON the dashboard reads.
9. **Optional extras:** Z3 proofs for the policy ("no rule combination lets a card or password out", or a counterexample); bit-budget oracle accounting in the agent (LNX does the vault side); compression-based randomness as a classifier feature.

**Exit:** merged; independent review; tag `p6-win-done`.

---

## Phase 7: Release

**Preconditions:** `g6-lnx-verified`, `g6-win-verified`.

Steps:
1. Write `docs/readme-parts/win.md`: detection, ML, agent, evaluation sections with the final numbers and their confidence bounds; your honest limits (from `docs/limits/skipped-win.md` and spec §17).
2. Final `make eval` on a fresh WSL clone; commit results.
3. Final independent security review of everything WIN owns, by a fresh subagent with the whole spec.
4. Windows end-to-end check: install the release dashboard build on Windows, pair it with the appliance in WSL, run the checkout scenario live with Ollama. Record the result.

**Exit:** tag `p7-win-done`.

---

## Gate notes for WIN

At every gate, in addition to SHARED §8:
- `make doctor` and the capability probe; paste both into the gate table.
- `make e2e-live` once (real Ollama on the GPU) and record task success; it doesn't block the gate on its own but failures get investigated.
- **Gate 4 onwards:** download the Windows dashboard build from the latest `release.yml` run (`gh run download`), then ask the user to install it (or launch the installer via `explorer.exe` if the user says so) and walk the user through LNX's checklist: every screen opens, side-by-side matches the egress record, kill switch works, approvals work. Record results.
- **Gate 7** = re-run Phase 7 steps 2 and 4 on `main` and push `g7-win-verified`.
