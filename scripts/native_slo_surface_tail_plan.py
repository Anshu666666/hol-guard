#!/usr/bin/env python3
"""Emit an explicitly selected nonpriority companion matrix for GitHub Actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_surface_tail_contract import matrices  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = matrices(mode=args.mode, selection=args.selection)
    with args.output.open("a", encoding="utf-8", newline="\n") as stream:
        values = {
            "enabled": result["enabled"],
            "selection": args.selection,
            "first_enabled": bool(result["first"]["include"]),
            "second_enabled": bool(result["second"]["include"]),
            "first": result["first"],
            "second": result["second"],
        }
        for key, value in values.items():
            stream.write(
                key + "=" + (value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))) + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
