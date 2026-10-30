"""Seeded random scrubber corpus shared with the C++ tests (libs/plcommon/testdata/scrubber_random.json).

Regenerate with: python libs/plpy/tests/gen_scrub_corpus.py (inside `make shell`). test_scrub.py
checks the committed file matches what plpy produces now, and plcommon's scrub_test checks C++
produces the same outputs, so the two scrubbers can't drift apart.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from plpy.scrub import scrub

OUT = Path(__file__).resolve().parents[2] / "plcommon" / "testdata" / "scrubber_random.json"
ALPHABET = "0123456789" * 4 + " -./_\t@:+" + "abcdeXYZ" + "AKIAsk-hf_ghp_eyJ." + "é東"
SEED = 20261030
COUNT = 600


def corpus() -> list[dict[str, str]]:
    rng = random.Random(SEED)
    out = []
    for _ in range(COUNT):
        s = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 60)))
        out.append({"input": s, "expected": scrub(s)})
    return out


if __name__ == "__main__":
    OUT.write_text(json.dumps({"seed": SEED, "cases": corpus()}, ensure_ascii=False, indent=0) + "\n")
