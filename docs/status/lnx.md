# LNX status

Machine: Linux Mint laptop (8 GB RAM, 4 GB VRAM). Owner of this file: LNX.

## Phase 0: Bootstrap (in progress)

Branch prefix `lnx/p0-*`. Each step is merged to `main` via PR when done.

- [x] 1. Check starting state (origin, bootstrap-only `main`)
- [x] 2. Layout: LNX folders with owner/purpose READMEs
- [x] 3. Ownership enforcement: `tools/ownership.tsv`, pre-commit hook, `make hooks`, `ownership.yml`, hook tests
- [x] 4. Dev image `platform/images/dev.Dockerfile` + `lnx-dev-image.yml`, `make dev-image`, `make shell`
- [x] 5. Build glue: root `CMakeLists.txt`, `CMakePresets.json`, `Makefile`, `mk/lnx.mk`
- [x] 6. CI: `lnx-ci.yml` (merged early, with steps 2–5)
- [x] 7. Contracts: README, OWNERS.tsv, C++/Python validators, linter, LNX schemas v1 + fixtures
- [x] 8. plcommon / plpy v0: framing, UDS, validation hooks, logging + scrubber, taint lattice, IDs; tests; frame-decoder fuzz ≥ 10 min
- [x] 9. Compose skeleton + `tests/e2e/platform/test_compose_policy.py`
- [x] 10. `docs/architecture/lnx.md`
- [x] 11. `detect_api_proposal.hpp`, `NullDetector`, request `L-001`
- [ ] 12. Independent review, fixes, tag `p0-lnx-done`

PR 1 (`lnx/p0-bootstrap`) carries steps 1–8 together: CI (step 6) only means something once the
dev image, Makefile and the first tests exist, so they land in the same first merge.

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

## Notes for resuming

- In the current login session the user is in the `docker` group but the shell hasn't picked it up; run docker/make through `sg docker -c '...'` until the user logs out and back in.
