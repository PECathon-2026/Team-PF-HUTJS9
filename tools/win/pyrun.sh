#!/usr/bin/env bash
# Run a command in a uv project inside a throwaway python:3.12 container.
# Stopgap until LNX's dev image exists (then `make test-win` replaces this).
# Usage: tools/win/pyrun.sh <project-dir> <command...>
#   e.g. tools/win/pyrun.sh ml uv run pytest
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
proj="$1"; shift
docker volume create pl-win-uvcache >/dev/null
exec docker run --rm --network bridge \
  -u "$(id -u):$(id -g)" -e HOME=/tmp -e UV_CACHE_DIR=/uvcache \
  -e UV_PROJECT_ENVIRONMENT=/tmp/venv -e UV_LINK_MODE=copy \
  -v pl-win-uvcache:/uvcache -v "$REPO":/src -w "/src/$proj" \
  python:3.12 sh -c 'pip -q install --user --no-warn-script-location uv==0.7.3 >/dev/null && export PATH=/tmp/.local/bin:$PATH && uv sync -q --frozen && "$@"' _ "$@"
