# PrivacyLens root Makefile (owner: LNX). `make` is the only build entry point (AD-03).
#
# Standard targets fan out to `<target>-lnx` (mk/lnx.mk) and `<target>-win`
# (mk/win.mk). A machine opts in by adding the target name to LNX_TARGETS or
# WIN_TARGETS and defining the `-lnx`/`-win` rule. A standard target nobody
# provides yet prints "nothing to run yet" and exits 0.
#
# Helpers for both .mk files:
#   $(IN_DEV) <cmd>     run <cmd> inside the pinned dev image (or directly when
#                       already inside it); depend on `dev-image` first.
#   $(DEV_IMAGE)        local tag of the dev image for this Dockerfile hash.
# Unit/lint targets run inside the dev image; compose targets run on the host.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

STANDARD_TARGETS := ci test lint fuzz-smoke coverage test-contracts test-security \
                    e2e e2e-live eval up down fetch-artifacts clean doctor hooks
LNX_TARGETS :=
WIN_TARGETS :=

# ---- dev image ---------------------------------------------------------------
DOCKER ?= docker
DEV_DOCKERFILE := platform/images/dev.Dockerfile
DEV_HASH := $(shell sha256sum $(DEV_DOCKERFILE) 2>/dev/null | cut -c1-16)
DEV_REGISTRY := ghcr.io/pecathon-2026/team-pf-hutjs9/dev
DEV_REMOTE := $(DEV_REGISTRY):$(DEV_HASH)
DEV_IMAGE := pl-dev:$(DEV_HASH)
DEV_CACHE_VOLUME ?= pl-cache

ifeq ($(PL_IN_DEV),1)
IN_DEV :=
else
IN_DEV = $(DOCKER) run --rm --init --user "$$(id -u):$$(id -g)" \
           -v "$(CURDIR)":/work -w /work -v $(DEV_CACHE_VOLUME):/cache \
           -e CI -e FUZZ_SECONDS -e PL_HOOK_GITLEAKS $(DEV_RUN_FLAGS) $(DEV_IMAGE)
endif

.PHONY: help dev-image shell
help:
	@echo "PrivacyLens. Standard targets: $(STANDARD_TARGETS)"
	@echo "Dev image: make dev-image | make shell   (image $(DEV_IMAGE))"
	@echo "Provided by LNX: $(sort $(LNX_TARGETS))"
	@echo "Provided by WIN: $(sort $(WIN_TARGETS))"

# Pull the CI-built image for this Dockerfile hash; build locally only if the pull fails (AD-15).
dev-image:
ifeq ($(PL_IN_DEV),1)
	@true
else
	@if $(DOCKER) image inspect $(DEV_IMAGE) >/dev/null 2>&1; then :; \
	elif $(DOCKER) pull -q $(DEV_REMOTE) >/dev/null 2>&1; then \
	  $(DOCKER) tag $(DEV_REMOTE) $(DEV_IMAGE); echo "dev-image: pulled $(DEV_REMOTE)"; \
	else \
	  echo "dev-image: pull of $(DEV_REMOTE) failed; building locally"; \
	  $(DOCKER) build -f $(DEV_DOCKERFILE) -t $(DEV_IMAGE) platform/images; \
	fi
	@$(DOCKER) tag $(DEV_IMAGE) pl-dev:current
endif

shell: DEV_RUN_FLAGS = -it
shell: dev-image
	$(IN_DEV) bash

-include mk/lnx.mk mk/win.mk

# ---- fan-out -----------------------------------------------------------------
define fanout
.PHONY: $(1)
$(1): $(if $(filter $(1),$(LNX_TARGETS)),$(1)-lnx) $(if $(filter $(1),$(WIN_TARGETS)),$(1)-win)
	@$(if $(filter $(1),$(LNX_TARGETS) $(WIN_TARGETS)),true,echo "$(1): nothing to run yet")
endef
$(foreach t,$(STANDARD_TARGETS),$(eval $(call fanout,$(t))))
