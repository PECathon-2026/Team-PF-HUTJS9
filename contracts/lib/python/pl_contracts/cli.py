"""python -m pl_contracts.cli {lint,check,validate} ..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pl_contracts.lint import lint_contracts
from pl_contracts.registry import load_registry


def check_fixtures(contracts: Path) -> list[str]:
    """Every valid fixture validates and every invalid one fails."""
    reg = load_registry(contracts / "schemas")
    errs = []
    count = 0
    for sid in sorted(reg.schemas):
        for kind in ("valid", "invalid"):
            for f in sorted((contracts / "fixtures" / sid / kind).glob("*.json")):
                count += 1
                problems = reg.errors(sid, json.loads(f.read_text()))
                if kind == "valid" and problems:
                    errs.append(
                        f"{f.relative_to(contracts)}: should validate but {problems}"
                    )
                if kind == "invalid" and not problems:
                    errs.append(
                        f"{f.relative_to(contracts)}: should fail but validates"
                    )
    print(f"pl_contracts: {len(reg.schemas)} schemas, {count} fixtures checked")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pl_contracts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("lint", "check"):
        sub.add_parser(c).add_argument("contracts", type=Path)
    v = sub.add_parser("validate")
    v.add_argument("schema", type=Path)
    v.add_argument("instance", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "validate":
        reg = load_registry(a.schema.parent)
        errs = reg.errors(
            a.schema.name.removesuffix(".json"), json.loads(a.instance.read_text())
        )
    elif a.cmd == "lint":
        errs = lint_contracts(a.contracts)
        if not errs:
            print(
                f"pl_contracts: lint clean ({len(list((a.contracts / 'schemas').glob('*.json')))} schemas)"
            )
    else:
        errs = check_fixtures(a.contracts)
    for e in errs:
        print(f"  - {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
