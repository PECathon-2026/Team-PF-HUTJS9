#!/usr/bin/env bash
# `make demo-pipeline`: run the data pipeline demo in the Playwright image (needs Chromium). Owner: WIN.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
IMG=mcr.microsoft.com/playwright/python:v1.52.0-noble
docker volume create pl-win-uvcache >/dev/null
docker run --rm --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp -e UV_CACHE_DIR=/uvcache -e UV_LINK_MODE=copy \
  -e UV_PROJECT_ENVIRONMENT=/tmp/venv-demo -v pl-win-uvcache:/uvcache -v "$REPO":/src -w /src/scenarios "$IMG" sh -c '
  pip -q install --user --break-system-packages --no-warn-script-location uv==0.7.3 >/dev/null 2>&1
  export PATH=/tmp/.local/bin:$PATH
  uv sync -q --frozen --python /usr/bin/python3
  uv run python -m pldemo.pipeline --commit-dir demo-output "$@"' _ "$@"
