"""Materialize only manifest-bound qualification helpers from exact source8156."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-source", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    source = args.production_source.resolve(strict=True)
    manifest = json.loads((root / "source-manifest.json").read_bytes())
    actual = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD", "HEAD^{tree}"], text=True
    ).splitlines()
    if actual != [manifest["published_source_sha"], manifest["source_tree"]]:
        raise RuntimeError("production source commit/tree mismatch")
    for name, expected in {**manifest["helpers"], **manifest["resources"]}.items():
        content = (source / name).read_bytes()
        if len(content) != expected["bytes"] or hashlib.sha256(content).hexdigest() != expected["sha256"]:
            raise RuntimeError("qualification helper source changed")
        target = root / "helpers" / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(content)
    print(
        json.dumps(
            {
                "helpers": len(manifest["helpers"]),
                "resources": len(manifest["resources"]),
                "exact_source_materialized": True,
                "native_execution_performed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
