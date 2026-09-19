"""Bind the fixed nine validation distributions and interpreter; no native qualification."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
from pathlib import Path

EXPECTED = {
    "pytest": "9.0.3",
    "iniconfig": "2.3.0",
    "packaging": "26.0",
    "pluggy": "1.6.0",
    "pygments": "2.20.0",
    "ruff": "0.15.17",
    "basedpyright": "1.39.8",
    "nodejs-wheel-binaries": "24.16.0",
    "pyyaml": "6.0.3",
}


def identity(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= 256 * 1024 * 1024:
            raise ValueError("environment file")
        digest = hashlib.sha256()
        size = 0
        while data := stream.read(1024 * 1024):
            size += len(data)
            if size > before.st_size:
                raise ValueError("environment file grew")
            digest.update(data)
        after = os.fstat(stream.fileno())

        def fields(value: os.stat_result) -> tuple[int, ...]:
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

        if size != before.st_size or fields(before) != fields(after) or fields(after) != fields(path.stat()):
            raise ValueError("environment file changed")
    return {"bytes": size, "sha256": digest.hexdigest()}


def observe() -> dict[str, object]:
    if sys.version_info[:3] != (3, 12, 10):
        raise ValueError("native Python version")
    files = {}
    for name, version in EXPECTED.items():
        distribution = importlib.metadata.distribution(name)
        if distribution.version != version or distribution.files is None:
            raise ValueError("fixed validation distribution")
        for item in distribution.files:
            located = distribution.locate_file(item)
            if not isinstance(located, Path):
                raise ValueError("distribution path type")
            path = Path(located).resolve(strict=True)
            if not path.is_file():
                raise ValueError("distribution file unavailable")
            files[str(path)] = identity(path)
            if len(files) > 30000:
                raise ValueError("distribution population")
    versions = sorted([row.metadata["Name"], row.version] for row in importlib.metadata.distributions())
    return {
        "schema": "hol-guard.macos-endpoint-validation-environment.v1",
        "python_version": sys.version,
        "executable": str(Path(sys.executable).resolve(strict=True)),
        "interpreter": identity(Path(sys.executable)),
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "expected_versions": EXPECTED,
        "all_installed_versions": versions,
        "files": dict(sorted(files.items())),
        "observer_source": identity(Path(__file__)),
        "scope": "fixed_nine_distribution_files_and_interpreter",
        "system_framework_or_loaded_memory_closure_claimed": False,
        "qualification_pass": False,
    }


def main() -> int:
    if len(sys.argv) not in (2, 3):
        return 64
    output = Path(sys.argv[1])
    try:
        result = observe()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if len(sys.argv) == 3 and json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")) != result:
            raise ValueError("environment differs")
        return 0
    except (OSError, ValueError, KeyError, importlib.metadata.PackageNotFoundError) as error:
        failure = output.with_suffix(".failure.json")
        failure.parent.mkdir(parents=True, exist_ok=True)
        failure.write_text(
            json.dumps({"error_type": type(error).__name__, "stage": "environment", "qualification_pass": False}) + "\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
