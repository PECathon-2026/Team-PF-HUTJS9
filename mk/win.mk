# WIN make targets (owner: WIN). Included by the root Makefile.
# WIN-A owns everything outside the fenced WIN-B block; WIN-B owns only the lines
# between its markers (SPRINT.md section 2).

WIN_TARGETS += ci test lint doctor fetch-artifacts

WIN_PY_PROJECTS := ml scenarios daemons/agent
# One venv per project in the dev image's cache volume.
win_uv = env UV_PROJECT_ENVIRONMENT=/cache/venv/win-$(subst /,-,$(1)) UV_LINK_MODE=copy uv --project $(1)

.PHONY: ci-win test-win test-py-win test-cpp-win lint-win doctor-win fetch-artifacts-win py-sync-win scenarios-build

ci-win: lint-win test-win

py-sync-win: dev-image
	$(IN_DEV) bash -c '$(foreach p,$(WIN_PY_PROJECTS),$(call win_uv,$(p)) sync --frozen --quiet && ) true'

test-win: test-py-win test-cpp-win

# Python suites (browser-marked tests need Chromium + Playwright: run them with tools/win/browser-tests.sh).
test-py-win: py-sync-win
	$(IN_DEV) bash -c '$(foreach p,$(WIN_PY_PROJECTS),(cd $(p) && $(call win_uv,.) run --frozen pytest -q -p no:cacheprovider -m "not browser") && ) true'

# C++ libraries WIN owns (detect, sanitize, fourier): same presets as the rest of the tree; WIN suites are named Win*.
test-cpp-win: dev-image
	$(IN_DEV) bash -c 'cmake --preset debug >/dev/null && cmake --build --preset debug && ctest --preset debug -R "^Win" --output-on-failure'

lint-win: py-sync-win
	$(IN_DEV) bash -c '$(foreach p,$(WIN_PY_PROJECTS),(cd $(p) && $(call win_uv,.) run --frozen ruff check . && $(call win_uv,.) run --frozen ruff format --check .) && ) true'

doctor-win:
	@tools/win/doctor.sh

fetch-artifacts-win:
	python3 -I ml/tools/fetch_artifacts.py

# Render the scenario + red-team pages from the seed into scenarios/build/ (served by the `sites` container).
scenarios-build: py-sync-win
	$(IN_DEV) bash -c 'cd scenarios && $(call win_uv,.) run --frozen python -m plscen.build'

# Data pipeline demo: scenario pages -> Chromium capture -> detect -> sanitize -> vault -> leak check -> HTML + 3D report.
# Runs in the Playwright image (Chromium); report in scenarios/build/demo/index.html, publishable subset in scenarios/demo-output/.
.PHONY: demo-pipeline
demo-pipeline:
	tools/win/demo-pipeline.sh

# --- WIN-B ---
# (WIN-B: ledger + dashboard targets go here. WIN-A never edits inside this block.)
# --- /WIN-B ---
