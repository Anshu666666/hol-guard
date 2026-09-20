"""Install the exact retained default wheel; no native build or workload runs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

SOURCE_SHA = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
ARCHIVE_BYTES = 8695956
ARCHIVE_SHA = "5d29d0870593309945330a4874d7bb74d8cc0ccf60e7d7974336ecba5caeaa95"
WHEEL_NAME = "hol_guard-3.0.1-py3-none-linux_x86_64.whl"
WHEEL_MEMBER = "hol-guard/hol-guard/original-source/qualification-native/" + WHEEL_NAME
WHEEL_BYTES = 8893563
WHEEL_SHA = "bbe3d933bf255c0a1ee82c421468479647856b8c1726a86d2623fa3613222102"
BUILD_MEMBER = "_temp/pr2974-workspace-cause/build-result.json"
BUILD_SHA = "caad73947d52c332223f68ad207f83fa3ea1b14e4722972c5454bd4489516d44"
RUNTIME_NAME = "codex_plugin_scanner/_native/hol-guard-runtime"
RUNTIME_SHA = "418e381f74a3d84d4d1f0aa8148ff62aa048997fd72e1fe47faf912bbec00fe0"
RULE_DIGEST = "e9d2024f94d91cb5ae1a9d8e8c60a398f24bf1af7767c578e1997f33cc98a32a"


def verified_wheel(archive: Path) -> tuple[bytes, dict[str, Any]]:
    with archive.open("rb") as stream:
        raw = stream.read(ARCHIVE_BYTES + 1)
    if len(raw) != ARCHIVE_BYTES or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError("retained_archive_identity")
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        if len(bundle.namelist()) != len(set(bundle.namelist())):
            raise ValueError("retained_archive_duplicates")
        wheel = bundle.read(WHEEL_MEMBER)
        build_raw = bundle.read(BUILD_MEMBER)
    if len(wheel) != WHEEL_BYTES or hashlib.sha256(wheel).hexdigest() != WHEEL_SHA:
        raise ValueError("retained_wheel_identity")
    if hashlib.sha256(build_raw).hexdigest() != BUILD_SHA:
        raise ValueError("retained_builder_record")
    build = json.loads(build_raw)
    if build["builder_calls"] != 1 or build["default_features"] is not True:
        raise ValueError("retained_builder_contract")
    if build["metadata"]["source_sha"] != SOURCE_SHA or build["metadata"]["python"] != "3.12.14":
        raise ValueError("retained_builder_source")
    with zipfile.ZipFile(io.BytesIO(wheel)) as package:
        if len(package.namelist()) != len(set(package.namelist())):
            raise ValueError("retained_wheel_duplicates")
        manifest_raw = package.read("codex_plugin_scanner/_native/runtime-manifest.json")
        runtime = package.read(RUNTIME_NAME)
    expected = {
        "schema": "hol-guard-native-runtime.v1",
        "package_version": "3.0.1",
        "platform_tag": "linux_x86_64",
        "protocol_version": 1,
        "rule_digest": RULE_DIGEST,
        "runtime_sha256": RUNTIME_SHA,
        "runtime_size": 12402936,
        "source_sha": SOURCE_SHA,
        "target": "x86_64-unknown-linux-musl",
    }
    if json.loads(manifest_raw) != expected:
        raise ValueError("retained_runtime_manifest")
    if len(runtime) != expected["runtime_size"] or hashlib.sha256(runtime).hexdigest() != RUNTIME_SHA:
        raise ValueError("retained_runtime_identity")
    return wheel, build


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    archive = Path(os.environ["RUNNER_TEMP"]) / "pr2974-workspace-first.zip"
    wheel_raw, original = verified_wheel(archive)
    destination = source / "qualification-native"
    destination.mkdir(mode=0o700, exist_ok=False)
    wheel = destination / WHEEL_NAME
    with wheel.open("xb") as stream:
        stream.write(wheel_raw)
    sys.path.insert(0, str(source))
    from scripts.build_native_qualification_artifacts import _run

    # Preserve the original frozen dependency preparation and noneditable install.
    # The exact prior successful builder already ran capabilities and self-test.
    _run(["uv", "sync", "--frozen", "--extra", "dev", "--python", "3.12"], cwd=source)
    python = source / ".venv/bin/python"
    _run(["uv", "pip", "uninstall", "--python", str(python), "hol-guard"], cwd=source)
    _run(["uv", "pip", "install", "--python", str(python), "--no-deps", "--force-reinstall", str(wheel)], cwd=source)
    version = _run([str(python), "-c", "import platform; print(platform.python_version())"], cwd=source).strip()
    if version != "3.12.14":
        raise ValueError("retained_install_python")
    record = {
        "schema": "hol-guard.workspace-cause-build.v1",
        "metadata": original["metadata"],
        "metadata_scope": "original successful build, not a new build",
        "wheel": original["wheel"],
        "python_relative": ".venv/bin/python",
        "wheel_relative": str(wheel.relative_to(source)),
        "builder_calls": 0,
        "prior_builder_calls": 1,
        "default_features": True,
        "wheel_reused": True,
        "archive": {"artifact_id": 10606006587, "run_id": 35511427638, "bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA},
        "verified_runtime_sha256": RUNTIME_SHA,
        "verified_rule_digest": RULE_DIGEST,
        "paired_or_lifecycle_workload_executed": False,
    }
    descriptor = os.open(output / "build-result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as record_stream:
        json.dump(record, record_stream, sort_keys=True, indent=2)
        record_stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
