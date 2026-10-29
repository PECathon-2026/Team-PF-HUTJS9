#!/usr/bin/env python3
"""PrivacyLens repo guard (owner: LNX).

Checks every changed path for: ownership (tools/ownership.tsv), size, CRLF,
model/data/secret file types and likely secrets. Used by the pre-commit hook
and by the ownership CI workflow. Standard library only, so it runs on any
host with python3.

    pl_hook.py pre-commit
    pl_hook.py ci --base <rev> --head <rev> --branch <name>
    pl_hook.py owner <path>...
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MACHINES = ("LNX", "WIN")
OWNERS = ("USER", "LNX", "WIN", "PRODUCER")
RULES_PATH = "tools/ownership.tsv"
PRODUCERS_PATH = "contracts/OWNERS.tsv"
MAX_BYTES = 5 * 1024 * 1024
CRLF_ALLOWED_SUFFIXES = (".ps1", ".bat", ".cmd")

# Model weights, datasets, captures, archives and key material never go in git.
BLOCKED_SUFFIXES = (
    ".onnx",
    ".pt",
    ".pth",
    ".safetensors",
    ".gguf",
    ".ggml",
    ".ckpt",
    ".h5",
    ".hdf5",
    ".pb",
    ".tflite",
    ".bin",
    ".npy",
    ".npz",
    ".pkl",
    ".pickle",
    ".joblib",
    ".parquet",
    ".feather",
    ".arrow",
    ".tfrecord",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".pcap",
    ".pcapng",
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
    ".xz",
    ".7z",
    ".zst",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
)
BLOCKED_NAMES = re.compile(
    r"^(\.pl-machine|\.env(\..*)?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|hf_token|.*_api_key)$"
)

# Built-in secret patterns. Always run, so the hook never passes silently when
# gitleaks is unavailable.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----")),
    ("aws-access-key", re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github-token",
        re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    ),
    ("anthropic-key", re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(rb"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
    ("huggingface-token", re.compile(rb"\bhf_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(rb"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    (
        "jwt",
        re.compile(
            rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        ),
    ),
)


# ---------------------------------------------------------------- ownership


def glob_to_regex(glob: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


@dataclass(frozen=True)
class Rule:
    glob: str
    owner: str
    regex: re.Pattern[str]


def parse_tsv(text: str, valid_owners: tuple[str, ...], source: str) -> list[Rule]:
    rules = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[1].strip() not in valid_owners:
            raise ValueError(
                f"{source}:{n}: expected '<glob><TAB><{'|'.join(valid_owners)}>', got {line!r}"
            )
        glob, owner = parts[0].strip(), parts[1].strip()
        rules.append(Rule(glob, owner, glob_to_regex(glob)))
    return rules


_SCHEMA_RE = re.compile(r"^contracts/schemas/([a-z0-9_]+)\.v[0-9]+\.json$")
_FIXTURE_RE = re.compile(r"^contracts/fixtures/([a-z0-9_]+)\.v[0-9]+/")


def schema_name(path: str) -> str | None:
    m = _SCHEMA_RE.match(path) or _FIXTURE_RE.match(path)
    return m.group(1) if m else None


@dataclass(frozen=True)
class Ownership:
    rules: list[Rule]
    producers: list[Rule]

    def owner_of(self, path: str) -> str | None:
        for rule in self.rules:
            if rule.regex.match(path):
                if rule.owner != "PRODUCER":
                    return rule.owner
                name = schema_name(path)
                if name is None:
                    return None
                for prod in self.producers:
                    if prod.regex.match(name):
                        return prod.owner
                return None
        return None


# ---------------------------------------------------------------- git helpers


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], capture_output=True, check=check)


def git_show(spec: str) -> bytes | None:
    r = git("cat-file", "blob", spec, check=False)
    return r.stdout if r.returncode == 0 else None


def blob_size(spec: str) -> int:
    return int(git("cat-file", "-s", spec).stdout.strip())


@dataclass(frozen=True)
class Change:
    status: str  # A, M, D, T, R, C
    path: str  # new path (or the deleted path)
    old_path: str | None = None


def parse_name_status(raw: bytes) -> list[Change]:
    fields = raw.decode("utf-8", "surrogateescape").split("\0")
    changes: list[Change] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i][0]
        if status in "RC":
            changes.append(Change(status, fields[i + 2], fields[i + 1]))
            i += 3
        else:
            changes.append(Change(status, fields[i + 1]))
            i += 2
    return changes


def load_ownership(old_spec: str | None, new_spec: str, machine: str) -> Ownership:
    """Rules come from the old revision; the new revision's rules are used only
    when this machine owns the rules files (so nobody can grant themselves paths)."""

    def read(path: str, rev: str | None) -> str | None:
        if rev is None:
            return None
        data = git_show(f"{rev}:{path}") if rev != ":" else git_show(f":{path}")
        return data.decode() if data is not None else None

    def build(rev: str | None) -> Ownership | None:
        rules_text = read(RULES_PATH, rev)
        if rules_text is None:
            return None
        rules = parse_tsv(rules_text, OWNERS, RULES_PATH)
        prod_text = read(PRODUCERS_PATH, rev) or ""
        producers = parse_tsv(prod_text, ("LNX", "WIN"), PRODUCERS_PATH)
        return Ownership(rules, producers)

    old = build(old_spec)
    if old is None:
        new = build(new_spec)
        if new is None:
            raise SystemExit(f"pl-hook: cannot read {RULES_PATH}")
        return new
    if old.owner_of(RULES_PATH) == machine and old.owner_of(PRODUCERS_PATH) == machine:
        return build(new_spec) or old
    return old


# ---------------------------------------------------------------- checks


def check_ownership(
    changes: list[Change], own: Ownership, allowed: set[str]
) -> list[str]:
    errors = []
    for ch in changes:
        for p in filter(None, (ch.path, ch.old_path)):
            owner = own.owner_of(p)
            if owner is None:
                errors.append(
                    f"{p}: no owner in {RULES_PATH} (unknown paths are blocked; add a line there)"
                )
            elif owner not in allowed:
                hint = (
                    " (USER path: only the human may change it, with PL_USER_COMMIT=1)"
                    if owner == "USER"
                    else ""
                )
                errors.append(
                    f"{p}: owned by {owner}, not {'/'.join(sorted(allowed))}{hint}"
                )
    return errors


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8000]


def scan_secrets(data: bytes) -> list[str]:
    return [name for name, rx in SECRET_PATTERNS if rx.search(data)]


def check_content(
    path: str, size: int, data: bytes | None, worktree: bytes | None = None
) -> list[str]:
    errors = []
    base = path.rsplit("/", 1)[-1]
    lower = base.lower()
    if BLOCKED_NAMES.match(base):
        errors.append(
            f"{path}: file name is never committed (machine identity, env or key file)"
        )
    if lower.endswith(BLOCKED_SUFFIXES):
        errors.append(
            f"{path}: model/data/archive/key file type is blocked (publish it as a release asset, AD-08)"
        )
    if size > MAX_BYTES:
        errors.append(f"{path}: {size} bytes is over the 5 MB limit")
    if data is not None and not is_binary(data):
        crlf = b"\r\n" in data or (
            worktree is not None and not is_binary(worktree) and b"\r\n" in worktree
        )
        if crlf and not lower.endswith(CRLF_ALLOWED_SUFFIXES):
            errors.append(f"{path}: CRLF line endings; convert to LF")
        for name in scan_secrets(data):
            errors.append(f"{path}: looks like a secret ({name})")
    return errors


def run_gitleaks(repo: Path) -> list[str]:
    """Run gitleaks on the staged diff: host binary, else the dev image if present."""
    if os.environ.get("PL_HOOK_GITLEAKS", "1") == "0":
        return []
    args = [
        "git",
        "--pre-commit",
        "--staged",
        "--redact",
        "--no-banner",
        "--exit-code",
        "3",
    ]
    cmd: list[str] | None = None
    if shutil.which("gitleaks"):
        cmd = ["gitleaks", *args]
    elif shutil.which("docker"):
        probe = subprocess.run(
            ["docker", "image", "inspect", "pl-dev:current"],
            check=False,
            capture_output=True,
        )
        if probe.returncode == 0:
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "-e",
                "GIT_CONFIG_COUNT=1",
                "-e",
                "GIT_CONFIG_KEY_0=safe.directory",
                "-e",
                "GIT_CONFIG_VALUE_0=*",
                "-v",
                f"{repo}:/work:ro",
                "-w",
                "/work",
                "pl-dev:current",
                "gitleaks",
                *args,
            ]
    if cmd is None:
        print(
            "pl-hook: gitleaks not available (no binary, no pl-dev:current image); built-in secret scan only",
            file=sys.stderr,
        )
        return []
    r = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if r.returncode == 3:
        return ["gitleaks found likely secrets:\n" + (r.stdout + r.stderr).strip()]
    if r.returncode != 0:
        print(
            f"pl-hook: gitleaks did not run cleanly (exit {r.returncode}); built-in scan still applied",
            file=sys.stderr,
        )
    return []


# ---------------------------------------------------------------- modes


def report(errors: list[str], what: str) -> int:
    if not errors:
        return 0
    print(f"pl-hook: {what} rejected:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    return 1


def pre_commit() -> int:
    repo = Path(git("rev-parse", "--show-toplevel").stdout.decode().strip())
    marker = repo / ".pl-machine"
    machine = marker.read_text().strip() if marker.is_file() else ""
    if machine not in MACHINES:
        return report(
            [
                f".pl-machine must contain LNX or WIN (got {machine!r}); never guess the role"
            ],
            "commit",
        )
    allowed = {machine}
    if os.environ.get("PL_USER_COMMIT") == "1":
        allowed.add("USER")

    has_head = git("rev-parse", "--verify", "-q", "HEAD", check=False).returncode == 0
    own = load_ownership("HEAD" if has_head else None, ":", machine)
    changes = parse_name_status(
        git("diff", "--cached", "--name-status", "-z", "-M").stdout
    )

    errors = check_ownership(changes, own, allowed)
    for ch in changes:
        if ch.status == "D":
            continue
        data = git_show(f":{ch.path}")
        size = blob_size(f":{ch.path}")
        wt_file = repo / ch.path
        worktree = (
            wt_file.read_bytes()
            if wt_file.is_file() and wt_file.stat().st_size <= MAX_BYTES
            else None
        )
        errors += check_content(ch.path, size, data, worktree)
    errors += run_gitleaks(repo)
    return report(errors, "commit")


def branch_machine(branch: str) -> str | None:
    for prefix, owner in (("lnx/", "LNX"), ("win/", "WIN"), ("user/", "USER")):
        if branch.startswith(prefix):
            return owner
    return None


def ci(base: str, head: str, branch: str) -> int:
    machine = branch_machine(branch)
    if machine is None:
        return report(
            [f"branch {branch!r} must start with lnx/, win/ or user/"], "branch"
        )
    merge_base = git("merge-base", base, head).stdout.decode().strip()
    own = load_ownership(merge_base, head, machine)
    changes = parse_name_status(
        git("diff", "--name-status", "-z", "-M", merge_base, head).stdout
    )
    errors = check_ownership(changes, own, {machine})
    for ch in changes:
        if ch.status == "D":
            continue
        spec = f"{head}:{ch.path}"
        errors += check_content(ch.path, blob_size(spec), git_show(spec))
    if not errors:
        print(
            f"pl-hook: {len(changes)} changed path(s) on {branch} are all owned by {machine} and pass content checks"
        )
    return report(errors, f"branch {branch}")


def owner_cmd(paths: list[str]) -> int:
    """Print the owner of each path, using the rules files in the working tree."""
    prod = Path(PRODUCERS_PATH)
    own = Ownership(
        parse_tsv(Path(RULES_PATH).read_text(), OWNERS, RULES_PATH),
        parse_tsv(prod.read_text(), ("LNX", "WIN"), PRODUCERS_PATH)
        if prod.exists()
        else [],
    )
    for p in paths:
        print(f"{own.owner_of(p) or 'BLOCKED'}\t{p}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="pl_hook.py")
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("pre-commit")
    c = sub.add_parser("ci")
    c.add_argument("--base", required=True)
    c.add_argument("--head", required=True)
    c.add_argument("--branch", required=True)
    o = sub.add_parser("owner")
    o.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    if a.mode == "pre-commit":
        return pre_commit()
    if a.mode == "ci":
        return ci(a.base, a.head, a.branch)
    return owner_cmd(a.paths)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
