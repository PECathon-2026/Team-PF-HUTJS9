# Requests from LNX to WIN

Owner: LNX. WIN acknowledges each item in `docs/requests/done-by-win.md` (ID, status `done`/`declined`/`later`, commit or reason).

## L-001: adopt (or amend) the core ↔ detect/sanitize C++ interface
- **Ask:** in WIN's own headers under `daemons/core/detect/` and `daemons/core/sanitize/` (and `fourier/`), adopt the interface proposed in `daemons/core/shell/include/pl/detect_api_proposal.hpp`, or amend it and tell LNX what changed. Concretely:
  1. CMake targets `pl::detect`, `pl::sanitize`, `pl::fourier` (aliases of static libraries) in `daemons/core/{detect,sanitize,fourier}/CMakeLists.txt`. The root CMake adds those folders before `daemons/core`; the shell links them automatically once both `pl::detect` and `pl::sanitize` exist.
  2. Implement `pl::detect::make_detector(const EngineConfig&)`, `make_sanitizer(const EngineConfig&)` and `phase_correlate(prev, cur)` with the signatures in the proposal (or WIN's amended header, which then replaces the proposal; LNX will include WIN's header instead).
  3. Sanitizer hands every detected value to the vault through `SanitizeContext::vault_store(detection, value)` and keeps no copy (AD-12).
  4. Use the 20 category names of `contracts/schemas/taint_label.v1.json` (`CARD`, `AADHAAR`, `PAN`, `API_KEY`, `OTP`, `PASSWORD`, `EMAIL`, `PHONE`, `IP_ADDRESS`, `PIN_CODE`, `BANK_ACCOUNT`, `IFSC`, `UPI_ID`, `PASSPORT`, `DOB`, `NAME`, `ADDRESS`, `FACE`, `SECRET`, `QUASI_ID`) as field types in `detection` and in placeholders (`[REDACTED:CARD#3]`). If you need more, ask and LNX extends the lattice in plcommon/plpy and the schema together.
  5. Tell LNX the `sanitized_page` schema id/shape the shell should validate (the fail-closed `NullSanitizer` currently emits `{"schema": "sanitized_page.v1", "fallback": "null_detector", "elements": [{"element_id", "flags", "placeholders"}]}`; please make your v1 accept that or say what it should emit).
- **Why:** LNX can't write inside WIN's folders; the shell needs a stable boundary to build and link `core` before and after WIN's code exists (LNX P0 step 11).
- **Blocks:** LNX Phase 1 step 3 (core shell calls detect/sanitize). Until then `core` uses `NullDetector`, which redacts everything.
- **Acceptance:** `make test` builds `core_detect_iface_test` with `PL_HAVE_WIN_DETECT` defined (CMake prints "core: linking WIN's pl::detect and pl::sanitize") and the test passes; WIN acknowledges L-001 in `done-by-win.md`.

## L-002: run `make doctor` inside WSL and report (informational)
- **Ask:** after your Phase 0, paste the output of `make doctor` (host prerequisites: docker, compose, runsc, nvidia runtime, BTF) into `docs/status/win.md`. The full capability probe comes in LNX Phase 2.
- **Why:** confirms the WSL2 host matches AD-02 before Gate 0.
- **Blocks:** nothing; Gate 0 reads it.
- **Acceptance:** output in `docs/status/win.md`.
