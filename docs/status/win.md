# WIN status

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
