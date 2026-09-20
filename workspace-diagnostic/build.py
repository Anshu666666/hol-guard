"""Call the exact original default-wheel builder once, without paired workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SOURCE_SHA = "8f15b37b4a1bd054ef486148610e518b1be05cfc"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    if os.environ.get("CARGO_TARGET_DIR"):
        raise ValueError("original_builder_requires_its_target_directory")
    sys.path.insert(0, str(source))
    from scripts.build_native_qualification_artifacts import _build

    python, wheel, metadata = _build(
        source, target="x86_64-unknown-linux-musl", platform_tag="linux_x86_64", deployment_target=""
    )
    if metadata["source_sha"] != SOURCE_SHA or metadata["python"] != "3.12.14":
        raise ValueError("workspace_build_source_or_python")
    digest = hashlib.sha256()
    size = 0
    with wheel.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > 256 * 1024 * 1024:
                raise ValueError("workspace_wheel_size")
            digest.update(block)
    record = {
        "schema": "hol-guard.workspace-cause-build.v1",
        "metadata": metadata,
        "wheel": {"name": wheel.name, "bytes": size, "sha256": digest.hexdigest()},
        "python_relative": str(python.relative_to(source)),
        "wheel_relative": str(wheel.relative_to(source)),
        "builder_calls": 1,
        "default_features": True,
        "paired_or_lifecycle_workload_executed": False,
    }
    descriptor = os.open(output / "build-result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as record_stream:
        json.dump(record, record_stream, sort_keys=True, indent=2)
        record_stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
