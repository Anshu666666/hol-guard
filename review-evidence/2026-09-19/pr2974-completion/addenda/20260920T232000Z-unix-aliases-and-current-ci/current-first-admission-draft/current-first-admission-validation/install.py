"""Admit one retained normal-CI wheel and install its exact package bytes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, cast

import tomllib

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import digest, run, write

SOURCE_EXCLUSION = "src/codex_plugin_scanner/guard/native_runtime_resident.py"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def admitted_wheel(archive: Path, specification: dict[str, Any], source: Path) -> tuple[bytes, dict[str, Any]]:
    require(digest(archive, 64 * 1024 * 1024) == specification["archive_identity"], "retained_archive_identity")
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        require(len(names) == len(set(names)) and len(names) <= 64, "archive_member_roster")
        name = specification["wheel_member"]
        require(bundle.getinfo(name).file_size == specification["wheel_identity"]["bytes"], "wheel_size")
        wheel = bundle.read(name)
    require(
        {"bytes": len(wheel), "sha256": hashlib.sha256(wheel).hexdigest()} == specification["wheel_identity"],
        "wheel_digest",
    )
    with zipfile.ZipFile(io.BytesIO(wheel)) as package:
        names = package.namelist()
        require(len(names) == len(set(names)) and len(names) < 10_000, "wheel_roster")
        entries: dict[str, Any] = {}
        for item in package.infolist():
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and ".." not in path.parts, "wheel_path")
            if not item.filename.startswith("codex_plugin_scanner/") or item.is_dir():
                continue
            require(0 <= item.file_size <= 64 * 1024 * 1024, "package_member_bound")
            raw = package.read(item)
            entries[item.filename] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        runtime_name = "codex_plugin_scanner/_native/hol-guard-runtime"
        require(entries[runtime_name] == specification["runtime_identity"], "runtime_digest")
        manifest = json.loads(package.read("codex_plugin_scanner/_native/runtime-manifest.json"))
        require(manifest == specification["runtime_manifest"], "runtime_manifest")
        python_names = {name for name in entries if name.endswith(".py")}
        source_names = {
            str(path.relative_to(source / "src")).replace(os.sep, "/")
            for path in (source / "src/codex_plugin_scanner").rglob("*.py")
        }
        configuration = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
        exclusions = configuration["tool"]["hatch"]["build"]["exclude"]
        require(type(exclusions) is list and all(type(value) is str for value in exclusions), "exclusion_shape")
        package_exclusions = [
            value for value in cast(list[str], exclusions) if value.startswith("src/codex_plugin_scanner/")
        ]
        require(package_exclusions == [SOURCE_EXCLUSION], "package_exclusion_contract")
        excluded_name = SOURCE_EXCLUSION.removeprefix("src/")
        require(excluded_name in source_names, "excluded_source_missing")
        require(python_names == source_names - {excluded_name}, "package_source_roster")
        for name in sorted(python_names):
            require(digest(source / "src" / name) == entries[name], "package_source_bytes")
    return wheel, {
        "package_entries": entries,
        "runtime_manifest": manifest,
        "source_python_files_matched": len(python_names),
        "configured_source_python_exclusions": [SOURCE_EXCLUSION],
    }


def inspect_install(source: Path, expected: dict[str, Any]) -> dict[str, Any]:
    prefix = source / ".venv"
    require(Path(sys.executable).absolute() == prefix / "bin/python", "owned_python_executable")
    require(Path(sys.prefix).resolve(strict=True) == prefix.resolve(strict=True), "owned_python_prefix")
    require(Path(sys.base_prefix).resolve(strict=True) != prefix.resolve(strict=True), "owned_python_venv")
    distribution = importlib.metadata.distribution("hol-guard")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    require(direct.get("dir_info", {}).get("editable") is not True, "editable_install")
    files = distribution.files
    require(files is not None, "installed_record")
    installed = {
        str(item).replace(os.sep, "/")
        for item in files or ()
        if str(item).replace(os.sep, "/").startswith("codex_plugin_scanner/") and not str(item).endswith(".pyc")
    }
    require(installed == set(expected["package_entries"]), "installed_package_roster")
    for name, identity in expected["package_entries"].items():
        path = Path(str(distribution.locate_file(name))).resolve(strict=True)
        require(path.is_relative_to(prefix) and not path.is_relative_to(source / "src"), "installed_origin")
        require(digest(path, 64 * 1024 * 1024) == identity, "installed_package_bytes")
    runtime = Path(str(distribution.locate_file("codex_plugin_scanner/_native/hol-guard-runtime"))).resolve(strict=True)
    dependencies = sorted((str(item.metadata["Name"]), item.version) for item in importlib.metadata.distributions())
    return {
        "package_version": distribution.version,
        "runtime_relative": runtime.relative_to(source).as_posix(),
        "package_files_verified": len(installed),
        "noneditable": True,
        "runtime": expected["runtime_manifest"],
        "native_process_launched": False,
        "interpreter": {
            "version": list(sys.version_info[:3]),
            "executable_identity": digest(Path(sys.executable).resolve(strict=True), 64 * 1024 * 1024),
            "owned_venv": True,
        },
        "dependency_names_versions": dependencies,
        "dependency_scope": "installed distribution names and versions; not a full dependency-file attestation",
    }


def install(source: Path, archive: Path, specification: dict[str, Any], output: Path) -> tuple[Path, dict[str, Any]]:
    wheel_raw, expected = admitted_wheel(archive, specification, source)
    wheel = output / specification["wheel_name"]
    with wheel.open("xb") as stream:
        stream.write(wheel_raw)
    write(output / "expected-installed.json", expected)
    run(
        "sync", ["uv", "sync", "--frozen", "--extra", "dev", "--python", "3.12"], cwd=source, output=output, timeout=600
    )
    python = source / ".venv/bin/python"
    run("uninstall", ["uv", "pip", "uninstall", "--python", str(python), "hol-guard"], cwd=source, output=output)
    run(
        "install",
        ["uv", "pip", "install", "--python", str(python), "--no-deps", "--force-reinstall", str(wheel)],
        cwd=source,
        output=output,
    )
    return python, expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(sys.version_info[:2] == (3, 12), "python_version")
    result = inspect_install(args.source.resolve(strict=True), json.loads(args.expected.read_text(encoding="utf-8")))
    write(args.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
