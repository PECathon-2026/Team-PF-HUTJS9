# LNX make targets (owner: LNX). Included by the root Makefile; see its header.

LNX_TARGETS += ci test lint fuzz-smoke coverage test-contracts test-security clean doctor hooks

FUZZ_SECONDS ?= 60
PLPY := libs/plpy
# Python tooling for everything LNX owns lives in the plpy uv project (lockfile committed).
UVRUN := env UV_PROJECT_ENVIRONMENT=/cache/venv/plpy uv run --project $(PLPY) --frozen
PY_TEST_DIRS = $(wildcard tools/hooks/tests libs/plpy/tests contracts/lib/python/tests)
PY_LINT_DIRS = $(wildcard tools/hooks libs/plpy/src libs/plpy/tests contracts/lib/python) $(wildcard tests/e2e/platform/*.py)
PY_COV = --cov=plpy $(if $(wildcard contracts/lib/python/pl_contracts),--cov=pl_contracts)
HAVE_CONTRACTS = $(wildcard contracts/lib/python/pl_contracts)
CTEST_FLAGS := --output-on-failure

.PHONY: hooks-lnx ci-lnx test-lnx test-py-lnx test-cpp-lnx test-asan-lnx test-tsan-lnx lint-lnx \
        lint-py-lnx lint-cpp-lnx lint-contracts-lnx fuzz-smoke-lnx coverage-lnx test-contracts-lnx \
        test-security-lnx clean-lnx doctor-lnx py-sync-lnx

hooks-lnx:
	git config core.hooksPath tools/hooks
	@echo "hooks: core.hooksPath = tools/hooks (pre-commit active)"

ci-lnx: lint-lnx test-lnx test-asan-lnx test-contracts-lnx coverage-lnx test-security-lnx

py-sync-lnx: dev-image
	$(IN_DEV) env UV_PROJECT_ENVIRONMENT=/cache/venv/plpy uv sync --project $(PLPY) --frozen --quiet

# ---- tests -------------------------------------------------------------------
test-lnx: test-py-lnx test-cpp-lnx

test-py-lnx: py-sync-lnx
	$(IN_DEV) $(UVRUN) pytest -q -p no:cacheprovider $(PY_TEST_DIRS) \
	  $(PY_COV) --cov-report=term-missing:skip-covered --cov-fail-under=85

test-cpp-lnx: dev-image
	$(IN_DEV) bash -c 'cmake --preset debug >/dev/null && cmake --build --preset debug && ctest --preset debug $(CTEST_FLAGS)'

test-asan-lnx: dev-image
	$(IN_DEV) bash -c 'cmake --preset asan >/dev/null && cmake --build --preset asan && ctest --preset asan $(CTEST_FLAGS)'

# TSan needs vm.mmap_rnd_bits <= 28 on the host kernel (newer kernels default to
# 32 and TSan's re-exec fix is blocked by Docker's seccomp profile, which we keep).
# CI sets the sysctl on its runner; locally: sudo sysctl -w vm.mmap_rnd_bits=28
test-tsan-lnx: dev-image
	$(IN_DEV) bash -c 'cmake --preset tsan >/dev/null && cmake --build --preset tsan && ctest --preset tsan $(CTEST_FLAGS)' \
	  || { echo "test-tsan: failed. If the log shows 'ThreadSanitizer: CHECK failed ... personality', run: sudo sysctl -w vm.mmap_rnd_bits=28"; exit 1; }

test-contracts-lnx: py-sync-lnx
	$(if $(HAVE_CONTRACTS),$(IN_DEV) $(UVRUN) python -m pl_contracts.cli check contracts,@echo "test-contracts: nothing to run yet (python)")
	$(IN_DEV) bash -c 'cmake --preset debug >/dev/null && cmake --build --preset debug && ctest --preset debug -L contracts $(CTEST_FLAGS)'

test-security-lnx: py-sync-lnx
	$(if $(wildcard tests/e2e/platform/test_*.py),$(IN_DEV) $(UVRUN) pytest -q -p no:cacheprovider tests/e2e/platform -m "not e2e",@echo "test-security: nothing to run yet")

# ---- lint ----------------------------------------------------------------------
lint-lnx: lint-py-lnx lint-contracts-lnx lint-cpp-lnx

lint-py-lnx: py-sync-lnx
	$(IN_DEV) $(UVRUN) ruff check $(PY_LINT_DIRS)
	$(IN_DEV) $(UVRUN) ruff format --check $(PY_LINT_DIRS)
	$(IN_DEV) $(UVRUN) mypy --strict $(PY_LINT_DIRS)

lint-contracts-lnx: py-sync-lnx
	$(if $(HAVE_CONTRACTS),$(IN_DEV) $(UVRUN) python -m pl_contracts.cli lint contracts,@echo "lint-contracts: nothing to run yet")

lint-cpp-lnx: dev-image
	$(IN_DEV) tools/lnx/clang-tidy.sh

# ---- fuzzing and coverage ----------------------------------------------------------
fuzz-smoke-lnx: dev-image
	$(IN_DEV) tools/lnx/fuzz.sh $(FUZZ_SECONDS)

coverage-lnx: dev-image
	$(IN_DEV) tools/lnx/coverage.sh

# ---- housekeeping --------------------------------------------------------------
clean-lnx:
	rm -rf build

doctor-lnx:
	@tools/lnx/doctor.sh
