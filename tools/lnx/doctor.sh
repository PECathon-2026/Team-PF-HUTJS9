#!/usr/bin/env bash
# Host prerequisite check (owner: LNX). Runs on the host, never fails the build:
# it reports what is present. The full capability probe (platform/probe) lands in Phase 2.
set -uo pipefail
ok() { printf '  [ok]   %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
echo "PrivacyLens doctor (host)"
m=$(cat .pl-machine 2>/dev/null || true)
[[ "$m" == LNX || "$m" == WIN ]] && ok ".pl-machine = $m" || warn ".pl-machine missing or invalid ('$m')"
[[ "$(git config core.hooksPath)" == tools/hooks ]] && ok "pre-commit hook active" || warn "hooks not installed: run 'make hooks'"
for t in docker make git gh python3; do
  command -v "$t" >/dev/null && ok "$t: $("$t" --version 2>&1 | head -n1)" || warn "$t missing"
done
if docker info >/dev/null 2>&1; then
  ok "docker daemon reachable ($(docker version --format '{{.Server.Version}}'))"
  docker compose version >/dev/null 2>&1 && ok "$(docker compose version)" || warn "docker compose v2 plugin missing"
  rts=$(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}')
  [[ " $rts " == *" runsc "* ]] && ok "gVisor runtime registered (runsc)" || warn "gVisor runtime 'runsc' not registered (AD-02)"
  [[ " $rts " == *" nvidia "* ]] && ok "NVIDIA container runtime registered" || warn "nvidia runtime not registered"
  [[ "$(docker info --format '{{.OperatingSystem}}')" == *"Docker Desktop"* ]] && warn "Docker Desktop detected (AD-02 wants Docker Engine)"
else
  warn "docker daemon not reachable by $(id -un) (in group docker? log out and back in after adding)"
fi
command -v nvidia-smi >/dev/null && ok "GPU: $(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | head -n1)" || warn "nvidia-smi not found"
ok "kernel $(uname -r), $(nproc) CPUs, $(awk '/MemTotal/ {printf "%.1f GiB RAM", $2/1048576}' /proc/meminfo)"
[[ -d "$HOME/.privacylens/secrets" ]] && ok "~/.privacylens/secrets exists" || warn "~/.privacylens/secrets missing (docs/SETUP.md Part D)"
[[ -r /sys/kernel/btf/vmlinux ]] && ok "BTF available (/sys/kernel/btf/vmlinux)" || warn "no kernel BTF (eBPF CO-RE fallback needed)"
exit 0
