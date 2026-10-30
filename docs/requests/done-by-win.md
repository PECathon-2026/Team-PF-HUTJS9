# Requests handled by WIN

Owner: WIN. Acknowledgements of LNX's requests in `docs/requests/to-win.md`.

| ID | Status | Commit / note |
|---|---|---|
| L-001 | done | Adopted `daemons/core/shell/include/pl/detect_api_proposal.hpp` **unchanged**: WIN's libraries compile against it (include path to the shell's header; WIN's own headers `pl/detect/detect.hpp`, `pl/sanitize/sanitize.hpp`, `pl/fourier/fourier.hpp` only add helpers). CMake targets `pl::detect`, `pl::sanitize`, `pl::fourier` exist; CMake prints "core: linking WIN's pl::detect and pl::sanitize". Categories are the 20 `taint_label.v1` names. `sanitized_page.v1` (contracts/schemas/sanitized_page.v1.json) accepts the NullSanitizer output as is (`fallback: "null_detector"`, `element_id` = `n<node_id>`, integer `flags`, `placeholders`); WIN's sanitizer adds `snapshot_id`, `url`, per-element `role`, `name` (placeholders substituted), `data_type`, `filled`, `href` (path only), `bounds`, and a `redactions` list. `phase_correlate` returns `std::nullopt` in Sprint 1 (full rescan); the port lands in Sprint 2. |
| L-002 | done | `make doctor` output is in `docs/status/win.md` (WSL2 kernel 6.18 has BTF, Landlock ABI 7, `memfd_secret`; runsc and GPU work in containers). |

## Notes for LNX (no action unless you disagree)
- **Canary format (user decision e):** `PLCANARY-<16 Crockford base32>-<NN>`, NN = base-32 value mod 97, zero-padded. Detect's validator is `canary_ok` in `daemons/core/detect/src/scanner.cpp`; reference `ml/gen/values.py::is_canary_token`. Format-valued canaries per page are in `scenarios/build/truth/<page>.json` → `canaries`.
- **Scenario site:** `scenarios/compose.yml` adds service `sites` (nginx-unprivileged, pages baked into the image, no bind mounts; passes `test_compose_policy.py`). Pages are at `http://sites:8080/<page>/` (login, checkout, support, video, devsettings, redteam/*). Allowed domain for scenario tasks: `sites`. Build pages first with `make scenarios-build`.
- **Fills (user decision a):** `agent_action.v1` fill has either `placeholder` (sensitive fields; vault decrypt with binding check) or `text` (non-sensitive fields; type as-is). The agent refuses text on sensitive fields (A-24); the actuator should refuse it too.
