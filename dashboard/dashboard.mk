# WIN-B: dashboard make targets (owner: WIN-B). Included from the WIN-B fence in mk/win.mk
# once that file is on main; until then: make -f Makefile -f dashboard/dashboard.mk dashboard
# Runs in the pinned dev image (Node 22 + pnpm), never on the host.
.PHONY: dashboard dashboard-test
dashboard: dev-image
	$(IN_DEV) bash -c 'cd dashboard && export HOME=/tmp COREPACK_ENABLE_AUTO_PIN=0 && \
	  pnpm config set store-dir /cache/pnpm-store >/dev/null && \
	  (pnpm install --frozen-lockfile || pnpm install) && pnpm run build'
dashboard-test: dev-image
	$(IN_DEV) bash -c 'cd dashboard && export HOME=/tmp && pnpm config set store-dir /cache/pnpm-store >/dev/null && pnpm install --frozen-lockfile && pnpm test'
