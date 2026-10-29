# gate

**Owner: LNX.** The only container with network access (AD-05): the strict AI lane (independent re-check, canary check, fail-closed, spec §8), the browsing lane (CONNECT proxy, allowed domains only) and the UI relay. Its detectors are written independently of `daemons/core/detect/` (AD-11). LLM providers live here (AD-06).
