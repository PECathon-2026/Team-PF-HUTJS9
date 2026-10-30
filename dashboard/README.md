# dashboard

**Owner: WIN-B (moved from LNX for Sprint 1).** Web operator view (React + Vite + TypeScript), served by the gate on 127.0.0.1:8787. Tauri is not built this sprint.

Build: `make dashboard` (dev image, output `dashboard/dist`); unit tests: `make dashboard-test` (targets in dashboard/dashboard.mk).
Dev: `?mock=1` forces mock mode. Without it the app opens `api/stream` (SSE) and, if no relay answers, says so and offers an explicit, clearly labelled mock mode. API expected from the gate: see docs/requests/to-lnx.md WB-001.
Design: dark tokens in `src/styles.css` (one type scale, 4px spacing grid). Kill switch: button or Ctrl+Shift+K (acts at once). Approval prompt: no answer before the deadline sends deny.
