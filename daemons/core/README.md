# core

**Owner: LNX**, except `detect/`, `sanitize/` and `fourier/`, which are WIN's libraries linked into `core`.

The `core` daemon (spec §1, §3): Chrome inside gVisor, the CDP client, the in-memory capture model, the actuator, the live view and the loopback forwarder to the gate's browsing lane. `shell/` holds the shell and the detect/sanitize interface proposal (`shell/include/pl/detect_api_proposal.hpp`) with a `NullDetector` fallback.
