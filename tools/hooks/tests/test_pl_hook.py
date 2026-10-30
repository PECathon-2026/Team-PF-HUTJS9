"""Tests for the pre-commit hook and the CI branch check, driving real git repos."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "hooks"))

import pl_hook  # noqa: E402  (path set up above)


def run(cwd: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, cwd=cwd, capture_output=True, text=True, env=env)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A fresh repo with the real rules files and hook, bootstrapped by the USER."""
    r = tmp_path / "repo"
    r.mkdir()
    run(r, "git", "init", "-q", "-b", "main")
    run(r, "git", "config", "user.email", "test@example.invalid")
    run(r, "git", "config", "user.name", "Hook Test")
    (r / "tools" / "hooks").mkdir(parents=True)
    (r / "contracts").mkdir()
    for rel in (
        "tools/ownership.tsv",
        "tools/hooks/pre-commit",
        "tools/hooks/pl_hook.py",
        "contracts/OWNERS.tsv",
        ".gitattributes",
    ):
        shutil.copy2(REPO / rel, r / rel)
    (r / "CLAUDE.md").write_text("bootstrap\n")
    run(r, "git", "add", "-A")
    assert run(r, "git", "commit", "-q", "-m", "bootstrap").returncode == 0  # no hook yet
    run(r, "git", "config", "core.hooksPath", "tools/hooks")
    (r / ".pl-machine").write_text("LNX\n")
    return r


def commit(
    repo: Path,
    rel: str,
    content: bytes | str = "hello\n",
    user: bool = False,
    gitleaks: bool = False,
) -> subprocess.CompletedProcess[str]:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_bytes(content)
    run(repo, "git", "add", "--", rel)
    env = {k: v for k, v in os.environ.items() if k != "PL_USER_COMMIT"}
    env["PL_HOOK_GITLEAKS"] = "1" if gitleaks else "0"
    if user:
        env["PL_USER_COMMIT"] = "1"
    return run(repo, "git", "commit", "-q", "-m", f"change {rel}", env=env)


def test_allowed_edit_passes(repo: Path) -> None:
    r = commit(repo, "libs/plcommon/src/frame.cpp", "int x;\n")
    assert r.returncode == 0, r.stderr


def test_foreign_edit_blocked(repo: Path) -> None:
    r = commit(repo, "daemons/core/detect/luhn.cpp", "int y;\n")
    assert r.returncode != 0
    assert "owned by WIN" in r.stderr


def test_win_machine_can_edit_win_paths_only(repo: Path) -> None:
    (repo / ".pl-machine").write_text("WIN\n")
    assert commit(repo, "ml/train.py", "x = 1\n").returncode == 0
    r = commit(repo, "daemons/vault/main.cpp", "int z;\n")
    assert r.returncode != 0 and "owned by LNX" in r.stderr


def test_user_path_blocked_without_override(repo: Path) -> None:
    r = commit(repo, "docs/prompts/LNX.md", "changed\n")
    assert r.returncode != 0
    assert "USER path" in r.stderr


def test_user_path_allowed_with_override(repo: Path) -> None:
    r = commit(repo, "docs/prompts/LNX.md", "changed\n", user=True)
    assert r.returncode == 0, r.stderr


def test_unknown_path_blocked(repo: Path) -> None:
    r = commit(repo, "random_folder/file.txt", "x\n")
    assert r.returncode != 0
    assert "no owner" in r.stderr


def test_crlf_blocked(repo: Path) -> None:
    r = commit(repo, "libs/plpy/a.py", b"x = 1\r\ny = 2\r\n")
    assert r.returncode != 0
    assert "CRLF" in r.stderr


def test_crlf_allowed_for_windows_scripts(repo: Path) -> None:
    (repo / ".pl-machine").write_text("WIN\n")
    r = commit(repo, "tools/win/setup.ps1", b"Write-Host hi\r\n")
    assert r.returncode == 0, r.stderr


def test_big_file_blocked(repo: Path) -> None:
    r = commit(repo, "platform/big.txt", "a" * (5 * 1024 * 1024 + 1))
    assert r.returncode != 0
    assert "5 MB" in r.stderr


def test_model_extension_blocked(repo: Path) -> None:
    r = commit(repo, "platform/model.onnx", b"\x08\x01\x12\x00")
    assert r.returncode != 0
    assert "blocked" in r.stderr


def test_pl_machine_never_committed(repo: Path) -> None:
    run(repo, "git", "add", "-f", ".pl-machine")
    r = commit(repo, "platform/ok.txt", "ok\n")
    assert r.returncode != 0
    assert ".pl-machine" in r.stderr


# Fake secrets are assembled at runtime so this file never contains one.
FAKE_SECRETS = {
    "aws-access-key": "AKIA" + "Q7XZ3TEST" + "EXAMPLE",
    "github-token": "ghp_" + "a1B2c3D4e5" * 4,
    "anthropic-key": "sk-" + "ant-" + "api03-" + "x" * 40,
    "private-key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n",
}


@pytest.mark.parametrize("kind", sorted(FAKE_SECRETS))
def test_fake_secret_blocked(repo: Path, kind: str) -> None:
    r = commit(repo, "platform/config.txt", f"token = {FAKE_SECRETS[kind]}\n")
    assert r.returncode != 0
    assert kind in r.stderr


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks binary only in the dev image")
def test_gitleaks_runs_and_blocks(repo: Path) -> None:
    r = commit(
        repo,
        "platform/config.txt",
        f"aws_access_key_id = {FAKE_SECRETS['aws-access-key']}\n",
        gitleaks=True,
    )
    assert r.returncode != 0


def test_missing_machine_file_blocks(repo: Path) -> None:
    (repo / ".pl-machine").unlink()
    r = commit(repo, "platform/ok.txt", "ok\n")
    assert r.returncode != 0
    assert "never guess" in r.stderr


def test_producer_schema_resolution(repo: Path) -> None:
    assert commit(repo, "contracts/schemas/event.v1.json", "{}\n").returncode == 0
    r = commit(repo, "contracts/schemas/detection.v1.json", "{}\n")
    assert r.returncode != 0 and "owned by WIN" in r.stderr
    r = commit(repo, "contracts/schemas/unlisted.v1.json", "{}\n")
    assert r.returncode != 0 and "no owner" in r.stderr


def test_foreign_delete_blocked(repo: Path) -> None:
    run(repo, "git", "rm", "-q", "CLAUDE.md")
    env = dict(os.environ, PL_HOOK_GITLEAKS="0")
    env.pop("PL_USER_COMMIT", None)
    r = run(repo, "git", "commit", "-q", "-m", "rm", env=env)
    assert r.returncode != 0 and "owned by USER" in r.stderr


def test_rules_from_head_when_not_owner(repo: Path) -> None:
    """WIN can't grant itself a path by staging an edited ownership.tsv."""
    (repo / ".pl-machine").write_text("WIN\n")
    rules = repo / "tools" / "ownership.tsv"
    rules.write_text("**\tWIN\n")
    run(repo, "git", "add", "tools/ownership.tsv")
    r = commit(repo, "daemons/vault/x.cpp", "int a;\n")
    assert r.returncode != 0 and "owned by LNX" in r.stderr


def test_lnx_cannot_self_grant_in_same_commit(repo: Path) -> None:
    """Regression (Phase 0 review): LNX owns the rules files, but a rules change
    only applies after it is committed, so it can't unlock paths in the same commit."""
    rules = repo / "tools" / "ownership.tsv"
    rules.write_text("docs/prompts/**\tLNX\n" + rules.read_text())
    run(repo, "git", "add", "tools/ownership.tsv")
    r = commit(repo, "docs/prompts/LNX.md", "self-granted\n")
    assert r.returncode != 0 and "owned by USER" in r.stderr
    r = commit(repo, "daemons/core/detect/x.cpp", "int a;\n")
    assert r.returncode != 0 and "owned by WIN" in r.stderr


def test_secret_in_binary_file_blocked(repo: Path) -> None:
    r = commit(repo, "platform/blob.dat", b"\x00\x01" + FAKE_SECRETS["github-token"].encode() + b"\x00")
    assert r.returncode != 0 and "github-token" in r.stderr


# ---------------------------------------------------------------- unit level


@pytest.mark.parametrize(
    ("glob", "path", "hit"),
    [
        ("daemons/core/**", "daemons/core/a/b.cpp", True),
        ("daemons/core/**", "daemons/corex/a.cpp", False),
        ("docs/adr/*-lnx-*.md", "docs/adr/0001-lnx-ipc.md", True),
        ("docs/adr/*-lnx-*.md", "docs/adr/x/0001-lnx-ipc.md", False),
        ("Makefile", "sub/Makefile", False),
        ("**/x", "x", True),
        ("**/x", "a/b/x", True),
    ],
)
def test_glob(glob: str, path: str, hit: bool) -> None:
    assert bool(pl_hook.glob_to_regex(glob).match(path)) is hit


def test_every_shared_md_path_has_expected_owner() -> None:
    own = pl_hook.Ownership(
        pl_hook.parse_tsv((REPO / "tools/ownership.tsv").read_text(), pl_hook.OWNERS, "t"),
        pl_hook.parse_tsv((REPO / "contracts/OWNERS.tsv").read_text(), ("LNX", "WIN"), "o"),
    )
    expect = {
        "CLAUDE.md": "USER",
        ".claude/settings.json": "USER",
        "docs/SETUP.md": "USER",
        "Makefile": "LNX",
        "mk/win.mk": "WIN",
        "mk/lnx.mk": "LNX",
        "daemons/core/fourier/a.cpp": "WIN",
        "daemons/core/actuator/a.cpp": "LNX",
        "daemons/agent/compose.yml": "WIN",
        "dashboard/src/App.tsx": "WIN",
        "daemons/ledger/src/main.cpp": "WIN",
        "daemons/gate/src/main.cpp": "LNX",
        "docs/status/win-b.md": "WIN",
        "EVALUATION.md": "WIN",
        "RESULTS.md": "WIN",
        "DEMO.md": "WIN",
        "ml/reference/pl_fourier.py": "WIN",
        "tests/e2e/scenarios/t.py": "WIN",
        "contracts/fixtures/frame.v1/valid/a.json": "LNX",
        "contracts/schemas/policy.v1.json": "WIN",
        ".github/workflows/win-ci.yml": "WIN",
        ".github/workflows/ownership.yml": "LNX",
        "docs/requests/to-lnx.md": "WIN",
        "docs/requests/to-win.md": "LNX",
        "README.md": "LNX",
        "docs/readme-parts/win.md": "WIN",
    }
    for path, owner in expect.items():
        assert own.owner_of(path) == owner, path
    assert own.owner_of(".github/workflows/other.yml") is None


def test_parse_tsv_rejects_bad_owner() -> None:
    with pytest.raises(ValueError):
        pl_hook.parse_tsv("foo\tNOBODY\n", pl_hook.OWNERS, "t")


@pytest.mark.parametrize(
    ("branch", "machine"),
    [
        ("lnx/p0-x", "LNX"),
        ("win/p1-y", "WIN"),
        ("user/fix", "USER"),
        ("feature/z", None),
        ("main", None),
    ],
)
def test_branch_machine(branch: str, machine: str | None) -> None:
    assert pl_hook.branch_machine(branch) == machine


def test_ci_mode(repo: Path) -> None:
    env = dict(os.environ, PL_HOOK_GITLEAKS="0")
    run(repo, "git", "switch", "-q", "-c", "lnx/p0-test")
    assert commit(repo, "platform/a.txt", "a\n").returncode == 0
    hook = str(repo / "tools/hooks/pl_hook.py")
    ok = run(
        repo,
        sys.executable,
        hook,
        "ci",
        "--base",
        "main",
        "--head",
        "HEAD",
        "--branch",
        "lnx/p0-test",
        env=env,
    )
    assert ok.returncode == 0, ok.stderr
    bad = run(
        repo,
        sys.executable,
        hook,
        "ci",
        "--base",
        "main",
        "--head",
        "HEAD",
        "--branch",
        "win/p0-test",
        env=env,
    )
    assert bad.returncode != 0 and "owned by LNX" in bad.stderr
    odd = run(
        repo,
        sys.executable,
        hook,
        "ci",
        "--base",
        "main",
        "--head",
        "HEAD",
        "--branch",
        "feature/x",
        env=env,
    )
    assert odd.returncode != 0


def test_ci_judges_pr_by_base_rules(repo: Path) -> None:
    """Regression (Phase 0 review): a PR that edits the rules is still judged by the base rules,
    even if the local hook was bypassed."""
    env = dict(os.environ, PL_HOOK_GITLEAKS="0")
    hook = str(repo / "tools/hooks/pl_hook.py")
    run(repo, "git", "switch", "-q", "-c", "lnx/p0-grant")
    rules = repo / "tools" / "ownership.tsv"
    rules.write_text("CLAUDE.md\tLNX\n" + rules.read_text())
    (repo / "CLAUDE.md").write_text("edited\n")
    run(repo, "git", "add", "-A")
    # Simulates a commit made without the hook; CI is the backstop.
    run(repo, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "grant", env=env)
    r = run(repo, sys.executable, hook, "ci", "--base", "main", "--head", "HEAD", "--branch", "lnx/p0-grant", env=env)
    assert r.returncode != 0 and "CLAUDE.md: owned by USER" in r.stderr
