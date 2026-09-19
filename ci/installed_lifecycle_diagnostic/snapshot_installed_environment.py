"""Snapshot installed artifacts using metadata only; do not import Guard."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import sys
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--observer-requirements", type=Path)
    args = parser.parse_args()
    assert sys.flags.isolated
    prefix = Path(sys.prefix).resolve()
    distributions = []
    for distribution in sorted(
        importlib.metadata.distributions(),
        key=lambda item: item.metadata["Name"].lower(),
    ):
        direct_url = distribution.read_text("direct_url.json")
        assert direct_url is None or not json.loads(direct_url).get("dir_info", {}).get(
            "editable", False
        )
        files = []
        for member in sorted(distribution.files or [], key=str):
            # Interpreter bytecode caches are generated observations, not
            # canonical installed source/native/dependency artifact bytes.
            if "__pycache__" in member.parts or member.suffix == ".pyc":
                continue
            path = Path(str(distribution.locate_file(member))).resolve()
            assert path.is_relative_to(prefix), (
                distribution.metadata["Name"],
                str(member),
            )
            assert path.is_file()
            files.append(
                {
                    "path": str(path.relative_to(prefix)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
        distributions.append(
            {
                "name": distribution.metadata["Name"],
                "version": distribution.version,
                "files": files,
            }
        )
    guard = importlib.metadata.distribution("hol-guard")
    wheel_matches = []
    with zipfile.ZipFile(args.wheel) as wheel:
        for member in sorted(wheel.namelist()):
            if not member.startswith("codex_plugin_scanner/") or member.endswith("/"):
                continue
            path = Path(str(guard.locate_file(member)))
            content = wheel.read(member)
            expected = hashlib.sha256(content).hexdigest()
            assert sha256(path) == expected, member
            wheel_matches.append(
                {"member": member, "sha256": expected, "bytes": len(content)}
            )
    executable = Path(sys.executable).resolve()

    def normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    def read_pins(path: Path) -> dict[str, str]:
        pins = {}
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(
                r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line.strip()
            )
            assert match is not None, "dependency_pin_format"
            name, version = normalize(match[1]), match[2]
            assert name not in pins, "duplicate_dependency_pin"
            pins[name] = version
        return pins

    expected = read_pins(args.requirements)
    assert len(expected) == 47 and "hol-guard" not in expected, "dependency_pin_shape"
    expected["hol-guard"] = "3.0.1"
    if args.observer_requirements:
        observer = read_pins(args.observer_requirements)
        assert observer == {"psutil": "7.2.2"}, "observer_dependency_pin_shape"
        assert not expected.keys() & observer.keys(), (
            "duplicate_observer_dependency_pin"
        )
        expected.update(observer)
    actual = {normalize(item["name"]): item["version"] for item in distributions}
    assert len(actual) == len(distributions), "dependency_inventory_shape"
    assert actual == expected, "installed_dependency_versions_differ_from_explicit_pins"
    result = {
        "schema": "installed-environment-snapshot.v1",
        "python_version": sys.version,
        "python_executable": str(executable),
        "python_executable_sha256": sha256(executable),
        "platform": platform.platform(),
        "isolated": bool(sys.flags.isolated),
        "virtual_environment": str(prefix),
        "wheel_sha256": sha256(args.wheel),
        "distributions": distributions,
        "dependency_version_binding": {
            "requirements_sha256": sha256(args.requirements),
            "observer_requirements_sha256": (
                sha256(args.observer_requirements)
                if args.observer_requirements
                else None
            ),
            "complete_name_version_match": True,
            "expected_distribution_count": len(expected),
            "dependency_artifact_hashes": "observed in this run, not historical dependency artifact locks",
        },
        "all_guard_wheel_members_exact": wheel_matches,
        "guard_code_imported": False,
        "native_execution_performed": False,
    }
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(
        json.dumps(
            {
                "distributions": len(distributions),
                "installed_files": sum(len(item["files"]) for item in distributions),
                "exact_guard_wheel_members": len(wheel_matches),
                "snapshot_sha256": sha256(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()
