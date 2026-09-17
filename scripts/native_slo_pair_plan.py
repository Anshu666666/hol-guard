#!/usr/bin/env python3
"""Emit fixed qualification matrices after resolving one immutable source SHA."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PLATFORMS = (
    {
        "runner": "ubuntu-latest",
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "manylinux_2_17_x86_64",
        "deployment_target": "",
    },
    {
        "runner": "macos-15-intel",
        "target": "x86_64-apple-darwin",
        "platform_tag": "macosx_13_0_x86_64",
        "deployment_target": "13.0",
    },
    {
        "runner": "macos-15",
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64",
        "deployment_target": "11.0",
    },
    {
        "runner": "windows-latest",
        "target": "x86_64-pc-windows-msvc",
        "platform_tag": "win_amd64",
        "deployment_target": "",
    },
)


def matrices(mode: str, candidate_sha: str) -> dict[str, object]:
    if mode not in {"smoke", "qualification"} or re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None:
        raise ValueError("pair_plan_context_invalid")
    runs = 5 if mode == "qualification" else 1
    return {
        "mode": mode,
        "sha": candidate_sha,
        "runs": runs,
        "platforms": {"include": list(PLATFORMS)},
        "pairs": {"include": [{**platform, "pair_index": index} for platform in PLATFORMS for index in range(runs)]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = matrices(args.mode, args.candidate_sha)
    with args.output.open("a", encoding="utf-8", newline="\n") as stream:
        for key, value in result.items():
            stream.write(
                key + "=" + (json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else str(value)) + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
