"""Download and verify every artifact listed in ml/artifacts.lock.json (AD-08).

    python ml/tools/fetch_artifacts.py [--lock ml/artifacts.lock.json] [--dest artifacts] [--pin] [--only NAME]

- Files land in ``<dest>/<artifact name>/<path>`` (``artifacts/`` is gitignored).
- Every file is verified against its SHA-256; a mismatch deletes the file and fails.
- Hugging Face downloads use the token in ``$PL_HF_TOKEN_FILE`` (default
  ``~/.privacylens/secrets/hf_token``) if it exists. The token is sent only to
  huggingface.co and never printed or logged.
- ``--pin`` (drafting the lock only): files with no hash yet get the hash of
  what was downloaded, recorded as ``sha256_source: "pinned-on-download"``.
  Large files carry the hash Hugging Face publishes for their LFS object.
- Gated artifacts whose license hasn't been accepted are reported as
  ``pending-license`` and skipped; they don't fail the run (status stays visible).
Standard library only, so it runs before any project environment exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
CHUNK = 1 << 20


def _token() -> str | None:
    p = Path(os.environ.get("PL_HF_TOKEN_FILE", Path.home() / ".privacylens/secrets/hf_token"))
    try:
        t = p.read_text().strip()
    except OSError:
        return None
    return t or None


def _url(src: dict[str, Any], path: str) -> str:
    if src["type"] != "huggingface":
        raise ValueError(f"unsupported source type {src['type']!r}")
    return f"https://huggingface.co/{src['repo']}/resolve/{src['revision']}/{path}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, token: str | None) -> None:
    headers = {"User-Agent": "privacylens-fetch/1"}
    if token and url.startswith("https://huggingface.co/"):
        headers["Authorization"] = f"Bearer {token}"
    tmp = dest.with_suffix(dest.suffix + ".part")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r, tmp.open("wb") as f:
        while chunk := r.read(CHUNK):
            f.write(chunk)
    tmp.replace(dest)


def fetch(lock_path: Path, dest: Path, pin: bool, only: str | None) -> int:
    lock = json.loads(lock_path.read_text("utf-8"))
    token = _token()
    failures = 0
    for art in lock["artifacts"]:
        if only and art["name"] != only:
            continue
        status = "fetched"
        for f in art["files"]:
            target = dest / art["name"] / f["path"]
            want = f.get("sha256")
            if target.exists() and want and _sha256(target) == want:
                continue
            try:
                _download(_url(art["source"], f["path"]), target, token)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403) and art.get("gated"):
                    status = "pending-license"
                    print(f"[pending] {art['name']}: gated ({e.code}); accept the license on Hugging Face", flush=True)
                    break
                print(f"[fail] {art['name']}/{f['path']}: HTTP {e.code}", flush=True)
                failures += 1
                status = "failed"
                break
            got = _sha256(target)
            if want is None and pin:
                f["sha256"], f["sha256_source"] = got, "pinned-on-download"
            elif got != want:
                target.unlink()
                print(f"[fail] {art['name']}/{f['path']}: sha256 mismatch", flush=True)
                failures += 1
                status = "failed"
                break
            if f.get("size") is not None and target.stat().st_size != f["size"]:
                print(f"[fail] {art['name']}/{f['path']}: size mismatch", flush=True)
                failures += 1
                status = "failed"
                break
        art["status"] = status
        print(f"[{status}] {art['name']}", flush=True)
    if pin:
        lock_path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return failures


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lock", type=Path, default=REPO / "ml" / "artifacts.lock.json")
    ap.add_argument("--dest", type=Path, default=REPO / "artifacts")
    ap.add_argument("--pin", action="store_true")
    ap.add_argument("--only")
    a = ap.parse_args()
    sys.exit(1 if fetch(a.lock, a.dest, a.pin, a.only) else 0)


if __name__ == "__main__":
    main()
