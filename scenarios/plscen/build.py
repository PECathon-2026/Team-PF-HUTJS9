"""Render the scenario pages with synthetic values.

    python -m plscen.build [--seed N] [--out DIR]

Writes:
    DIR/site/<page>/...      what the `sites` container serves
    DIR/truth/<page>.json    ground truth (never served: it holds the answers)

Rendered output is gitignored: it contains key-shaped strings and canaries and
is reproducible from the seed (AD-08).
"""

from __future__ import annotations

import argparse
import json
import shutil
import zlib
from pathlib import Path

from gen.values import Gen

from .builder import PageBuilder
from .pages import PAGES
from .redteam import REDTEAM

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "pages"
REDTEAM_TEMPLATES = ROOT / "redteam"
DEFAULT_OUT = ROOT / "build"
DEFAULT_SEED = 20261029


def page_seed(seed: int, page: str) -> int:
    """Each page gets its own stream, so editing one page doesn't change the others."""
    return zlib.crc32(f"{seed}:{page}".encode())


def build(out: Path = DEFAULT_OUT, seed: int = DEFAULT_SEED) -> dict[str, dict[str, object]]:
    site, truth_dir = out / "site", out / "truth"
    for d in (site, truth_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    shutil.copytree(TEMPLATES / "common", site / "common")
    shutil.copy(TEMPLATES / "index.html", site / "index.html")

    truths: dict[str, dict[str, object]] = {}
    groups = [("", TEMPLATES, PAGES), ("redteam/", REDTEAM_TEMPLATES, REDTEAM)]
    for prefix, root, registry in groups:
        (truth_dir / prefix).mkdir(parents=True, exist_ok=True)
        for name, fill in registry.items():
            src, dst = root / name, site / prefix / name
            dst.mkdir(parents=True)
            builder = PageBuilder(name)
            fill(Gen(page_seed(seed, prefix + name)), builder)
            for f in sorted(src.iterdir()):
                if f.name == "index.html":
                    rendered = builder.render(f.read_text(encoding="utf-8"))
                    (dst / "index.html").write_text(rendered, encoding="utf-8")
                else:
                    shutil.copy(f, dst / f.name)
            for fname, data in builder.assets.items():
                (dst / fname).write_bytes(data)
            truth = builder.truth(seed, f"/{prefix}{name}/")
            out_file = truth_dir / prefix / f"{name}.json"
            out_file.write_text(json.dumps(truth, indent=2, ensure_ascii=False) + "\n", "utf-8")
            truths[prefix + name] = truth
    return truths


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    truths = build(args.out, args.seed)
    for name, t in truths.items():
        n_inj = len(t["injections"])  # type: ignore[arg-type]
        print(f"{name:20s} {len(t['items']):3d} planted  {len(t['decoys']):2d} decoys  {n_inj:2d} injections")  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
