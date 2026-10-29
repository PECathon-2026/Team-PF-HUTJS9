#!/usr/bin/env bash
# docker compose for the appliance, with fragment slots filled (owner: LNX).
# Usage: tools/lnx/compose.sh <compose args>   e.g. config --format json | up -d | down
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
slot() { if [[ -f "$root/$1" ]]; then echo "../../$1"; else echo "./empty.yml"; fi; }
export PL_AGENT_COMPOSE="$(slot daemons/agent/compose.yml)"
export PL_SCENARIOS_COMPOSE="$(slot scenarios/compose.yml)"
if docker compose version >/dev/null 2>&1; then compose=(docker compose); else compose=(docker-compose); fi
exec "${compose[@]}" -f "$root/platform/compose/compose.yaml" "$@"
