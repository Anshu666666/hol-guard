"""Verify original8156 helpers, then apply four explicit diagnostic overrides."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import helper_overrides  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-source", type=Path, required=True)
    args = parser.parse_args()
    root = ROOT
    source = args.production_source.resolve(strict=True)
    manifest = json.loads((root / "source-manifest.json").read_bytes())
    actual = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD", "HEAD^{tree}"], text=True
    ).splitlines()
    if actual != [manifest["published_source_sha"], manifest["source_tree"]]:
        raise RuntimeError("production source commit/tree mismatch")
    overrides = helper_overrides(manifest)
    for name, expected in {**manifest["helpers"], **manifest["resources"]}.items():
        content = (source / name).read_bytes()
        if len(content) != expected["bytes"] or hashlib.sha256(content).hexdigest() != expected["sha256"]:
            raise RuntimeError("qualification helper source changed")
        if name in overrides:
            content = (root.parents[1] / name).read_bytes()
            expected = overrides[name]
            if len(content) != expected["bytes"] or hashlib.sha256(content).hexdigest() != expected["sha256"]:
                raise RuntimeError("diagnostic helper source changed")
        target = root / "helpers" / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(content)
    print(
        json.dumps(
            {
                "helpers": len(manifest["helpers"]),
                "resources": len(manifest["resources"]),
                "original_source_verified": True,
                "unchanged_helpers_materialized": len(manifest["helpers"]) - len(overrides),
                "diagnostic_overrides_materialized": overrides,
                "native_execution_performed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
