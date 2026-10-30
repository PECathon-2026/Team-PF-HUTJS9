# LNX architecture

Owner: LNX. What LNX builds, how the pieces talk, and where the boundaries with WIN sit. Binding decisions are in `docs/prompts/SHARED.md` §2 (AD-xx); this file explains how LNX implements them and records open questions.

## Components

| Component | Path | Language | Runtime | Network | Holds |
|---|---|---|---|---|---|
| core shell | `daemons/core/` (minus `detect/`, `sanitize/`, `fourier/`) | C++20 | gVisor (`runsc`) | none (loopback only) | Chrome, CDP client, capture model, actuator, live view, loopback forwarder |
| vault | `daemons/vault/` | C++20 | runc | none | session root key in `memfd_secret`, key hierarchy, all decryption |
| gate | `daemons/gate/` | C++20 | runc | **the only one**: `egress`, `llm` (internal), `web` (internal) | outgoing payloads only; LLM providers; independent detectors |
| ledger | `daemons/ledger/` | C++20 | runc | none | event bus, decision records, Merkle audit log, signing key |
| plcommon / plpy | `libs/` | C++ / Python | linked in | n/a | framing, UDS, validation hook, scrubbed logging, taint lattice, IDs (channels in P1) |
| contracts lib | `contracts/lib/` | C++ / Python | linked in | n/a | schema registry, fixture checks, contract linter |
| dashboard | `dashboard/` | TS/React, Tauri v2 | host app | `127.0.0.1` UI relay only | in-memory view of the ledger stream |
| platform | `platform/` | Compose, Dockerfiles, CMake | n/a | n/a | the walls: images, compose policy, (later) seccomp, AppArmor, probe, eBPF, attestation |

WIN's pieces LNX integrates with: `daemons/core/{detect,sanitize,fourier}` (C++ libraries linked into `core`), `daemons/agent` (Python, `network_mode: none`), `scenarios/` (web pages served by `sites` on the internal `web` network).

## Data flow (Phase 1 target)

```
            Chrome (in core, --headless=new, --remote-debugging-pipe)
               │ CDP over fd 3/4                      ▲ actuator (fill/click/...)
               ▼                                      │ plaintext only for the instant of typing
   capture model (flat nodes, string table, AX tree, tiles, 2–3 frame ring)
               │ by reference
               ▼
   WIN detect ──► WIN sanitize ──vault_store()──► vault (store → handle; AD-12)
               │                                      ▲ decrypt (binding-checked)
               ▼ sanitized_page                       │
             agent (WIN) ── gate_ai_request ──► gate AI lane ──► replay / ollama / anthropic
               ▲            gate_ai_response ◄──┘   │ egress_record
               │                                    ▼
          agent_action ──► validator ──► core     ledger (bus + Merkle log) ──► UI relay ──► dashboard
```

Chrome's own web traffic: `--proxy-server=127.0.0.1:<port>` → loopback forwarder in `core` → UDS → gate **browsing lane** (CONNECT, session's allowed domains only, metadata logged, TLS not inspected).

## IPC design (AD-04)

- **Transport:** Unix domain stream sockets under the shared volume `/run/pl/` (one listening socket per server daemon, e.g. `/run/pl/vault.sock`, `/run/pl/ledger.sock`, `/run/pl/gate-ai.sock`). Socket files `0660`. Peers are also checked with `SO_PEERCRED`.
- **Framing (P0, done):** 4-byte big-endian length, `1 ≤ L ≤ 16 MiB`, then L bytes. Zero or oversize length is a protocol error; the decoder stays failed and the connection is dropped (fail-closed). C++ `pl::FrameDecoder` and Python `plpy.frame.FrameDecoder` are wire-identical.
- **Payloads (P0, done):** UTF-8 JSON, nesting ≤ 64, validated against `contracts/` on receive always, on send in debug/test builds (`pl::MessageValidator` hook, implemented by `pl::contracts::Registry`; Python `plpy.validate` + `pl_contracts.Registry`). Each message names its schema in `"schema"`. Inside a channel every frame carries the `frame.v1` envelope (`channel`, `seq`, `sent_ns`, `payload_schema`, `payload`).
- **Encryption (P1):** each channel runs `crypto_kx` between pinned component keys (registered with the ledger at startup, signed registration), then `crypto_secretstream_xchacha20poly1305` in each direction. `seq` must increase by exactly one; replays, gaps and reordering abort the channel. Large image frames may go through shared memory, encrypted the same way, with only the descriptor on the socket.
- **Logging (P0, done):** JSON lines, identifier-only event/field names, banned field names dropped, every string scrubbed (Luhn cards, Verhoeff Aadhaar, PAN, emails, JWTs, key prefixes, any run of ≥ 8 digits) and truncated. Same behaviour in C++ and Python, checked against shared vectors.
- **Taint (P0, done):** label = (level, categories), levels `public < internal < personal < sensitive < secret`, categories = data types (`CARD`, `AADHAAR`, ... the placeholder types). `join` = (max, ∪). Only bottom may pass the gate. Wire form `taint_label.v1`.

## Gate lanes (AD-05)

| Lane | Clients | Inspection | Fail mode |
|---|---|---|---|
| **AI lane** | agent (`gate_ai_request`) | schema + taint must be `public` + allow-listed endpoint + liveness of core/vault/agent + independent re-check (own Luhn/Verhoeff/key-prefix scanner, later OCR, decode-before-scan, winnowing, q-gram) + canary check | closed on any error, timeout, missed liveness (2 s), kill switch |
| **Browsing lane** | Chrome in core via the loopback forwarder | domain/port allow-list from `browsing_policy`; no TLS inspection | closed for unlisted hosts; metadata-only `egress_record` |
| **UI relay** | dashboard (`127.0.0.1:7443`) ↔ core/ledger | none possible: end-to-end encrypted `ui_stream` frames | relay only; cannot decrypt |

Providers live in the gate (AD-06): `replay` (deterministic, used by every automated test), `ollama` (on the internal `llm` network), `anthropic` (key file mounted into the gate only).

## Vault API (`vault_api.v1`, P1)

| op | from → to | fields | notes |
|---|---|---|---|
| `store` | core → vault | `binding`, `plaintext` | core wipes its copy after sending (AD-12) |
| `store.ok` | vault → core | `handle` (`vh-<32 hex>`) | opaque, random |
| `decrypt` | actuator → vault | `handle`, `binding` | XChaCha20-Poly1305 with AD = canonical binding; exact match or `binding_mismatch` |
| `decrypt.ok` | vault → actuator | `plaintext` | typed immediately into locked memory, then wiped |
| `wipe` / `shred` | core → vault | `handle` / `session_id` | shred destroys the session key (crypto-shredding, P2) |
| `error` | vault → caller | `error_code` | never echoes inputs |

Binding = (`session_id`, `placeholder`, `field_type`, `site`, `element_id`). Master key in `memfd_secret` (fallback `mmap` + `mlock` + `MADV_DONTDUMP`), `PR_SET_DUMPABLE 0`, `RLIMIT_CORE 0`.

## core ↔ detect C++ boundary

LNX can't write in `daemons/core/detect/`, so the proposal is `daemons/core/shell/include/pl/detect_api_proposal.hpp` (request **L-001** to WIN):

- `Detector::detect(const PageSnapshot&, const DetectContext&) -> DetectionSet`, plus `on_navigation`, `on_session_end`.
- `Sanitizer::sanitize(const PageSnapshot&, const DetectionSet&, SanitizeContext&) -> SanitizedPage` (WIN's `sanitized_page` JSON + redacted PNG). `SanitizeContext::vault_store(detection, value) -> placeholder` is how values leave core.
- `phase_correlate(prev, cur) -> ScrollEstimate` for incremental capture (P5).
- `PageSnapshot` is a read-only view of the capture model: string table, flat nodes (text, live input value, attributes, AX role/name, bounds, flags), screenshot, dirty nodes/tiles.
- Factories `make_detector`, `make_sanitizer` from WIN's CMake targets `pl::detect`, `pl::sanitize` (and `pl::fourier`). The root CMake adds WIN's folders before `daemons/core`; when both targets exist the shell links them (`PL_HAVE_WIN_DETECT`), otherwise it uses `NullDetector`/`NullSanitizer`, which **fail closed**: every string on the page is treated as a SECRET detection and replaced, and no screenshot is passed on.

## Build, test and CI

- `make` is the only entry point; standard targets fan out to `-lnx` / `-win` (root `Makefile` header explains how WIN opts in). Builds run in the pinned dev image `ghcr.io/pecathon-2026/team-pf-hutjs9/dev:<sha256(Dockerfile)[:16]>`, pulled or built locally.
- CMake presets: `debug` (GCC 13), `release`, `clang-debug`, `asan` (ASan+UBSan), `tsan`, `fuzz` (libFuzzer), `coverage` (clang source-based). `pl_add_test`, `pl_add_fuzzer`, `pl_target_defaults` in `platform/cmake/PrivacyLens.cmake` (WIN may use them too).
- CI (`lnx-ci.yml`): dev image → `make ci-lnx` (lint, unit, ASan/UBSan, contracts, coverage gates, compose policy) → TSan → fuzz smoke 60 s/target. `ownership.yml` checks paths by branch prefix with the base branch's rules.

## Compose

`platform/compose/compose.yaml` (run via `tools/lnx/compose.sh`, which fills the `include:` slots for WIN's `daemons/agent/compose.yml` and `scenarios/compose.yml`, or points them at `empty.yml`). `tests/e2e/platform/test_compose_policy.py` checks the merged config: only `gate` (plus `ollama`/`sites` on internal networks) is networked, everything else `network_mode: none`; `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit`, `pids_limit`; no Docker socket, no privileged (except the future `monitor`), ports on `127.0.0.1` only, `core` on `runsc`. Memory on this 8 GB laptop: core 2 GiB, gate 512 MiB, ledger 256 MiB, vault 128 MiB.

## Open questions

1. **gVisor + Unix sockets on a shared volume.** `core` under `runsc` needs `--host-uds=open` (and maybe `create`) to reach `/run/pl/*.sock` on a volume shared with runc containers. To verify in P1 and record in an ADR; fallback per LNX P1 step 6.
2. **Field-type vocabulary.** LNX uses the 20 `taint_label.v1` categories as placeholder types and vault binding types. WIN's `detection` schema should use the same names (part of L-001); additions go through a request so both lattices stay identical.
3. **`sanitized_page` shape.** WIN owns it. The shell validates it before it leaves core; the Null fallback emits a minimal version with `fallback: "null_detector"` that WIN's schema should accept (or tell us its shape).
4. **TSan locally** needs `vm.mmap_rnd_bits=28` (see `docs/requests/to-user-lnx.md`); CI sets it.
5. **GHCR publishing** from Actions in the org works (first `lnx-dev-image` run, PR #1). Publishing is main-only.
6. **Per-daemon identities on the socket volume (P1).** Today every placeholder service mounts `/run/pl` read-write as root. Phase 1: distinct uids per daemon, one socket directory per server daemon writable only by it, `SO_PEERCRED` uid checks, and a `user:` assertion in the compose policy test.
