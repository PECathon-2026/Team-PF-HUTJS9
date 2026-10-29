# WIN status

## Phase 0 (early start, branch `win/p0-early`)

Started before `p0-lnx-done` on the user's instruction. Only work that doesn't depend on LNX is done here.
No PR / merge until `p0-lnx-done` exists.

- [x] 1. Environment check (`tools/win/doctor.sh`; `make doctor` wiring waits for LNX's Makefile)
- [ ] 2. `make hooks`, `make ci` on the skeleton (needs LNX Phase 0)
- [ ] 3. Handle LNX requests (`L-001` detect/sanitize C++ API) (needs LNX Phase 0)
- [ ] 4. Scenario pages v1 (early part in progress)
- [ ] 5. Snapshot recorder (needs LNX's `page_snapshot` schema)
- [ ] 6. WIN schemas v1 (needs LNX's contract conventions)
- [ ] 7. Fourier reference
- [ ] 8. Skeletons for all WIN folders, `mk/win.mk`, `win-ci.yml`
- [ ] 9. `docs/architecture/win.md`

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
