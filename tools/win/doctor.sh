#!/usr/bin/env bash
# WIN environment check (WIN Phase 0 step 1). Owner: WIN.
# Prints one line per check: PASS / WARN / FAIL. Exits 1 if any FAIL.
# Never prints secret contents; only checks that secret files exist.
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
EXPECTED_ORIGIN="https://github.com/PECathon-2026/Team-PF-HUTJS9.git"
SECRETS="${HOME}/.privacylens/secrets"
CUDA_IMAGE="nvidia/cuda:12.6.3-base-ubuntu24.04"
fails=0

pass() { printf 'PASS  %-22s %s\n' "$1" "$2"; }
warn() { printf 'WARN  %-22s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-22s %s\n' "$1" "$2"; fails=$((fails + 1)); }

# WSL2
if grep -qi microsoft /proc/version && [ -n "${WSL_DISTRO_NAME:-}" ]; then
  pass wsl2 "distro=${WSL_DISTRO_NAME} kernel=$(uname -r)"
else
  fail wsl2 "not running inside WSL2 (kernel=$(uname -r))"
fi

# OS
# shellcheck disable=SC1091
. /etc/os-release
case "${VERSION_ID:-}" in
  24.04) pass os "${PRETTY_NAME}" ;;
  *) warn os "${PRETTY_NAME} (expected Ubuntu 24.04)" ;;
esac

# Repo location
real="$(realpath "$REPO")"
case "$real" in
  /mnt/*) fail repo-path "$real is on the Windows filesystem" ;;
  *) pass repo-path "$real" ;;
esac

# Origin
origin="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
if [ "$origin" = "$EXPECTED_ORIGIN" ]; then pass origin "$origin"; else fail origin "got '$origin'"; fi

# Secrets: presence only
if [ -s "$SECRETS/hf_token" ]; then pass hf-token "present (not read)"; else fail hf-token "missing: $SECRETS/hf_token"; fi
if [ -s "$SECRETS/anthropic_api_key" ]; then pass anthropic-key "present (optional)"; else warn anthropic-key "absent (optional; local-only mode still works)"; fi

# Docker Engine, not Desktop
if ! docker info >/dev/null 2>&1; then
  fail docker "daemon not reachable"
else
  osname="$(docker info --format '{{.OperatingSystem}}')"
  ver="$(docker version --format '{{.Server.Version}}')"
  case "$osname" in
    *"Docker Desktop"*) fail docker-engine "Docker Desktop is active ($osname)" ;;
    *) pass docker-engine "server $ver on '$osname'" ;;
  esac
  if docker compose version >/dev/null 2>&1; then
    pass compose "$(docker compose version --short)"
  else
    fail compose "docker compose v2 missing"
  fi
  # gVisor
  if docker run --rm --runtime=runsc hello-world 2>/dev/null | grep -q 'Hello from Docker'; then
    pass runsc "$(runsc --version 2>/dev/null | head -1)"
  else
    fail runsc "docker run --runtime=runsc hello-world failed"
  fi
  # GPU in containers
  gpu="$(docker run --rm --gpus all "$CUDA_IMAGE" nvidia-smi \
          --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null)"
  if [ -n "$gpu" ]; then pass gpu-container "$gpu"; else fail gpu-container "nvidia-smi in container failed"; fi
fi

# Host tools (AD-03: docker, make, git, gh)
for t in make git gh; do
  if command -v "$t" >/dev/null; then pass "tool:$t" "$("$t" --version 2>&1 | head -1)"; else fail "tool:$t" missing; fi
done
if gh auth status >/dev/null 2>&1; then pass gh-auth "logged in"; else fail gh-auth "run: gh auth login"; fi

# Resources
mem_gb="$(awk '/MemTotal/ {printf "%.1f", $2/1048576}' /proc/meminfo)"
if awk -v m="$mem_gb" 'BEGIN{exit !(m >= 20)}'; then pass ram "${mem_gb} GiB visible to WSL, $(nproc) CPUs"
else warn ram "${mem_gb} GiB visible to WSL (raise memory= in .wslconfig)"; fi

# Kernel features (Phase 2 runs LNX's full probe; this is a quick look)
[ -e /sys/kernel/btf/vmlinux ] && pass btf "/sys/kernel/btf/vmlinux present" || warn btf "no BTF (eBPF monitor needs fallback or custom kernel)"
kprobe="$(python3 - <<'EOF' 2>/dev/null
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
ll = libc.syscall(444, None, 0, 1)        # landlock_create_ruleset(..., VERSION)
ms = libc.syscall(447, 0)                 # memfd_secret(0)
print(f"{ll} {ms}")
EOF
)"
ll="${kprobe%% *}"; ms="${kprobe##* }"
if [ "${ll:--1}" -gt 0 ] 2>/dev/null; then pass landlock "ABI v$ll"; else warn landlock "unavailable"; fi
if [ "${ms:--1}" -ge 0 ] 2>/dev/null; then pass memfd_secret "available"; else warn memfd_secret "unavailable"; fi

echo
if [ "$fails" -eq 0 ]; then echo "doctor: all required checks passed"; else echo "doctor: $fails check(s) failed"; fi
[ "$fails" -eq 0 ]
