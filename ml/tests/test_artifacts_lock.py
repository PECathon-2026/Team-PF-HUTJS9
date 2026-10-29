"""ml/artifacts.lock.json: every artifact pinned, licensed and hashed (AD-08)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path
from typing import Any

LOCK = Path(__file__).resolve().parents[1] / "artifacts.lock.json"


def lock() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(LOCK.read_text("utf-8"))
    return data


def test_every_artifact_is_pinned_and_licensed() -> None:
    arts = lock()["artifacts"]
    assert {a["name"] for a in arts} >= {
        "gliner_multi_pii", "rapidocr_ppocr", "yunet_face", "prompt_guard_2_86m", "multilingual_e5_small",
    }  # fmt: skip
    for a in arts:
        assert re.fullmatch(r"[0-9a-f]{40}", a["source"]["revision"]), a["name"]  # a commit, never "main"
        assert a["license"] and a["redistribution"] and a["purpose"], a["name"]
        assert a["kind"] in ("third_party", "own")
        assert a["status"] in ("fetched", "pending-license", "not-fetched", "failed")
        for f in a["files"]:
            assert isinstance(f["size"], int) and f["size"] > 0, (a["name"], f["path"])
            if "sha256" in f:
                assert re.fullmatch(r"[0-9a-f]{64}", f["sha256"]), (a["name"], f["path"])


def test_fetched_artifacts_are_fully_hashed() -> None:
    for a in lock()["artifacts"]:
        if a["status"] == "fetched":
            assert all("sha256" in f for f in a["files"]), a["name"]
        if a["status"] == "pending-license":
            assert a["gated"], a["name"]


def test_no_artifact_is_republished_third_party() -> None:
    for a in lock()["artifacts"]:
        if a["kind"] == "third_party":
            assert "github.com/PECathon-2026" not in json.dumps(a["source"]), a["name"]
            assert "Not re-published" in a["redistribution"], a["name"]


def test_fetcher_sha256(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "fetch", Path(__file__).resolve().parents[1] / "tools/fetch_artifacts.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    p = tmp_path / "x.bin"
    p.write_bytes(b"privacylens" * 100_000)
    assert mod._sha256(p) == hashlib.sha256(p.read_bytes()).hexdigest()
    assert mod._url({"type": "huggingface", "repo": "a/b", "revision": "c" * 40}, "d/e.onnx") == (
        "https://huggingface.co/a/b/resolve/" + "c" * 40 + "/d/e.onnx"
    )
