"""Compose security policy (AD-05, spec §2), asserted on the MERGED `docker compose config`.

Fragments from either machine are included, so the invariants hold whoever wrote a service.
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "tools" / "lnx" / "compose.sh"

# Services allowed on networks, and which networks each may join.
NETWORKED = {"gate": {"egress", "llm", "web"}, "ollama": {"llm"}, "sites": {"web"}}
INTERNAL_NETWORKS = {"llm", "web"}
PRIVILEGED_ALLOWED = {"monitor"}  # the eBPF monitor (Phase 2): privileged, but no network
GVISOR_SERVICES = {"core"}
CAP_ADD_ALLOWED: dict[str, set[str]] = {"vault": {"IPC_LOCK"}, "monitor": {"BPF", "PERFMON", "SYS_RESOURCE"}}
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "docker.sock")


def merged_config() -> dict[str, Any]:
    out = subprocess.run([str(COMPOSE), "config", "--format", "json"], check=True, capture_output=True, text=True, cwd=REPO)
    config: dict[str, Any] = json.loads(out.stdout)
    return config


def check_policy(config: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    networks: dict[str, Any] = config.get("networks") or {}
    for name in INTERNAL_NETWORKS & networks.keys():
        if networks[name].get("internal") is not True:
            errs.append(f"network {name}: must be internal (no route out)")
    for name, svc in (config.get("services") or {}).items():

        def err(msg: str, service: str = name) -> None:
            errs.append(f"{service}: {msg}")

        mode = svc.get("network_mode")
        joined = set(svc.get("networks") or {})
        if name in NETWORKED:
            if mode is not None:
                err(f"network_mode {mode!r} not allowed; join only {sorted(NETWORKED[name])}")
            if not joined <= NETWORKED[name]:
                err(f"joins {sorted(joined - NETWORKED[name])}, allowed only {sorted(NETWORKED[name])}")
        elif mode != "none" or joined:
            err("must have network_mode: none and no networks")
        if mode in ("host",) or (isinstance(mode, str) and mode.startswith(("container:", "service:"))):
            err(f"network_mode {mode!r} shares another namespace")
        for ns in ("pid", "ipc", "uts", "userns_mode", "cgroup"):
            if svc.get(ns) == "host":
                err(f"{ns}: host is not allowed")
        if svc.get("read_only") is not True:
            err("read_only must be true")
        if "ALL" not in (svc.get("cap_drop") or []):
            err("cap_drop must include ALL")
        extra_caps = {c.removeprefix("CAP_") for c in svc.get("cap_add") or []} - CAP_ADD_ALLOWED.get(name, set())
        if extra_caps:
            err(f"cap_add {sorted(extra_caps)} not allowed")
        if "no-new-privileges:true" not in (svc.get("security_opt") or []):
            err("security_opt must include no-new-privileges:true")
        if any(str(o).startswith(("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined"))
               for o in svc.get("security_opt") or []):  # fmt: skip
            err("seccomp/apparmor must not be unconfined")
        if svc.get("privileged") and name not in PRIVILEGED_ALLOWED:
            err("privileged is not allowed")
        if name in PRIVILEGED_ALLOWED and svc.get("privileged") and (mode != "none" or joined):
            err("the privileged monitor must have no network")
        if not svc.get("mem_limit"):
            err("mem_limit is required")
        if not svc.get("pids_limit"):
            err("pids_limit is required")
        if svc.get("devices"):
            err("devices are not allowed")
        for vol in svc.get("volumes") or []:
            src = str(vol.get("source", "")) if isinstance(vol, dict) else str(vol)
            if src.endswith(DOCKER_SOCKETS):
                err("mounts the Docker socket")
            if isinstance(vol, dict) and vol.get("type") == "bind" and src in ("/", "/proc", "/sys", "/dev", "/var/run", "/run"):
                err(f"bind-mounts host {src}")
        for port in svc.get("ports") or []:
            if not isinstance(port, dict) or port.get("host_ip") != "127.0.0.1":
                err("published ports must bind to 127.0.0.1 only")
        if name in GVISOR_SERVICES and svc.get("runtime") != "runsc":
            err("must run on gVisor (runtime: runsc)")
    for required in ("core", "vault", "gate", "ledger"):
        if required not in (config.get("services") or {}):
            errs.append(f"{required}: service missing")
    return errs


@pytest.fixture(scope="module")
def config() -> dict[str, Any]:
    return merged_config()


def test_merged_config_satisfies_policy(config: dict[str, Any]) -> None:
    assert check_policy(config) == []


def test_only_gate_is_on_the_egress_network(config: dict[str, Any]) -> None:
    on_egress = [n for n, s in config["services"].items() if "egress" in (s.get("networks") or {})]
    assert on_egress == ["gate"]


def test_core_runs_on_gvisor_without_network(config: dict[str, Any]) -> None:
    core = config["services"]["core"]
    assert core["runtime"] == "runsc"
    assert core["network_mode"] == "none"


# ---- the checker itself catches each violation ----------------------------------


def _mutated(config: dict[str, Any], service: str, **changes: Any) -> dict[str, Any]:
    c = copy.deepcopy(config)
    for k, v in changes.items():
        if v is None:
            c["services"][service].pop(k, None)
        else:
            c["services"][service][k] = v
    return c


@pytest.mark.parametrize(
    ("service", "changes", "message"),
    [
        ("vault", {"network_mode": None, "networks": {"egress": {}}}, "network_mode: none"),
        ("core", {"network_mode": "host"}, "network_mode: none"),
        ("ledger", {"read_only": False}, "read_only"),
        ("vault", {"cap_drop": []}, "cap_drop"),
        ("vault", {"cap_add": ["SYS_ADMIN"]}, "cap_add"),
        ("gate", {"privileged": True}, "privileged"),
        ("ledger", {"mem_limit": None}, "mem_limit"),
        ("ledger", {"pids_limit": None}, "pids_limit"),
        ("core", {"runtime": "runc"}, "gVisor"),
        ("core", {"pid": "host"}, "pid: host"),
        ("gate", {"security_opt": ["no-new-privileges:true", "seccomp=unconfined"]}, "unconfined"),
        ("gate", {"security_opt": []}, "no-new-privileges"),
        ("gate", {"network_mode": "host"}, "not allowed"),
        ("gate", {"networks": {"egress": {}, "other": {}}}, "joins"),
        ("gate", {"ports": [{"host_ip": "0.0.0.0", "target": 7443, "published": "7443"}]}, "127.0.0.1"),  # noqa: S104
        ("ledger", {"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]}, "Docker socket"),
        ("ledger", {"devices": ["/dev/kvm"]}, "devices"),
    ],
)
def test_checker_catches(config: dict[str, Any], service: str, changes: dict[str, Any], message: str) -> None:
    errs = check_policy(_mutated(config, service, **changes))
    assert any(message in e for e in errs), errs


def test_checker_catches_non_internal_llm_network_and_missing_service(config: dict[str, Any]) -> None:
    c = copy.deepcopy(config)
    c["networks"]["llm"]["internal"] = False
    del c["services"]["vault"]
    errs = check_policy(c)
    assert any("must be internal" in e for e in errs)
    assert any("vault: service missing" in e for e in errs)


def test_checker_handles_monitor_and_fragment_services(config: dict[str, Any]) -> None:
    c = copy.deepcopy(config)
    base = copy.deepcopy(c["services"]["ledger"])
    c["services"]["monitor"] = dict(base, privileged=True, cap_add=["BPF", "PERFMON"])
    c["services"]["agent"] = copy.deepcopy(base)  # e.g. WIN's fragment
    assert check_policy(c) == []
    c["services"]["monitor"]["network_mode"] = None
    c["services"]["monitor"]["networks"] = {"egress": {}}
    assert any("monitor" in e for e in check_policy(c))
