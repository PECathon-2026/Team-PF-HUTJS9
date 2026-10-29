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
