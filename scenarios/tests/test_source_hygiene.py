"""No invisible, bidi-control or Cyrillic characters in WIN source files ("Trojan Source").

Pages and generators need such characters at *runtime*; the source must spell
them as escapes so a reviewer can see them. Devanagari (Hindi labels) is fine.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RANGES = [(0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2069), (0x00AD, 0x00AD), (0xFEFF, 0xFEFF), (0x0400, 0x04FF)]
BAD = re.compile("[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in RANGES) + "]")
SUFFIXES = {".py", ".html", ".js", ".css", ".toml", ".md", ".sh", ".json"}


def test_no_hidden_characters_in_source() -> None:
    offenders = []
    for top in ("ml", "scenarios", "tools/win"):
        for f in (REPO / top).rglob("*"):
            if f.suffix not in SUFFIXES or not f.is_file() or {"build", ".venv"} & set(f.parts):
                continue
            for n, line in enumerate(f.read_text("utf-8", errors="replace").splitlines(), 1):
                for m in BAD.finditer(line):
                    offenders.append(f"{f.relative_to(REPO)}:{n}: U+{ord(m.group(0)):04X}")
    assert not offenders, offenders
