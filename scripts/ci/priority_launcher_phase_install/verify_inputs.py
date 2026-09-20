"""Bind retained artifact bytes before install and after one phase diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, cast

_NEW_PATHS = {
    ".github/workflows/priority-launcher-phase-diagnostic.yml",
    "scripts/ci/priority_launcher_phase_install/input-contract.json",
    "scripts/ci/priority_launcher_phase_install/run-source-bindings.json",
    "scripts/ci/priority_launcher_phase_install/verify_inputs.py",
}
_FIRST_DRIVER = "ecdab397f256f857e6e1d1d6dba2cbfe2206ba8c"
_CORRECTION_PATHS = _NEW_PATHS - {"scripts/ci/priority_launcher_phase_install/run-source-bindings.json"}


def _require(value: bool, label: str) -> None:
    if not value:
        raise ValueError("phase_input_" + label)


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    _require(len(raw) <= 128 * 1024, "json_bound")
    value = json.loads(raw, object_pairs_hook=_pairs)
    _require(type(value) is dict, "json_object")
    return cast(dict[str, Any], value)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=True, timeout=10)
    _require(len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 65536, "git_bound")
    return result.stdout.decode().strip()


def _digest(path: Path, *, maximum: int = 128 * 1024 * 1024) -> dict[str, object]:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum, "regular_file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while data := stream.read(65536):
            size += len(data)
            _require(size <= maximum, "stream_bound")
            digest.update(data)
    _require(size == metadata.st_size, "file_size_changed")
    return {"bytes": size, "sha256": digest.hexdigest()}


def _verify(args: argparse.Namespace) -> dict[str, object]:
    driver = args.driver.resolve(strict=True)
    source = args.source.resolve(strict=True)
    artifact = args.artifact.resolve(strict=True)
    inputs = Path(__file__).resolve().parent
    contract = _json(inputs / "input-contract.json")
    manifest_path = driver / contract["source_bindings_path"]
    _require(_digest(manifest_path)["sha256"] == contract["source_bindings_sha256"], "manifest_bytes")
    manifest = _json(manifest_path)
    _require(sys.platform == "darwin" and platform.machine() == "arm64", "platform")
    _require(sys.version_info[:2] == (3, 12), "python_version")
    _require(_git(driver, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"], "driver_commit")
    _require(
        _git(driver, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [_FIRST_DRIVER],
        "driver_parent",
    )
    _require(_git(driver, "rev-parse", "HEAD~2") == contract["observer_source"], "observer_parent")
    _require(
        set(_git(driver, "diff", "--name-only", "HEAD^", "HEAD").splitlines()) == _CORRECTION_PATHS, "correction_delta"
    )
    _require(set(_git(driver, "diff", "--name-only", "HEAD~2", "HEAD").splitlines()) == _NEW_PATHS, "driver_delta")
    _require(not _git(driver, "status", "--porcelain", "--untracked-files=no"), "driver_modified")
    _require(_git(source, "rev-parse", "HEAD") == contract["selected_build_source"], "source_commit")
    _require(_git(source, "rev-parse", "HEAD^{tree}") == contract["selected_tree"], "source_tree")
    _require(not _git(source, "status", "--porcelain", "--untracked-files=no"), "source_modified")
    _require(
        manifest["source_sha"] == contract["selected_build_source"]
        and manifest["source_tree"] == contract["selected_tree"],
        "manifest_source",
    )
    observer_files = {}
    for row in contract["observer_files"]:
        actual = _digest(driver / row["path"])
        _require(actual == {"bytes": row["bytes"], "sha256": row["sha256"]}, "observer_bytes")
        _require(_git(driver, "rev-parse", "HEAD:" + row["path"]) == row["git_blob"], "observer_blob")
        observer_files[row["path"]] = actual
    providers = {}
    _require(len(manifest["files"]) == 36, "provider_count")
    for row in manifest["files"]:
        actual = _digest(source / row["path"], maximum=1024 * 1024)
        _require(actual["sha256"] == row["sha256"], "provider_bytes")
        _require(_git(source, "rev-parse", "HEAD:" + row["path"]) == row["git_blob"], "provider_blob")
        providers[row["path"]] = actual
    preparation_helpers = {}
    for row in contract["interpreter_preparation"]["helpers"]:
        actual = _digest(source / row["path"], maximum=1024 * 1024)
        _require(actual["sha256"] == row["sha256"], "interpreter_helper_bytes")
        _require(_git(source, "rev-parse", "HEAD:" + row["path"]) == row["git_blob"], "interpreter_helper_blob")
        preparation_helpers[row["path"]] = actual
    members = {row["name"]: row for row in contract["artifact"]["members"]}
    actual_names = {p.relative_to(artifact).as_posix() for p in artifact.rglob("*") if not p.is_dir()}
    _require(actual_names == set(members), "artifact_members")
    records = {}
    for name, row in members.items():
        actual = _digest(artifact / name)
        _require(actual == {"bytes": row["bytes"], "sha256": row["sha256"]}, "artifact_member_bytes")
        records[name] = actual
    wheel = contract["wheel"]
    _require(records[wheel["path"]] == {"bytes": wheel["bytes"], "sha256": wheel["sha256"]}, "wheel_bytes")
    with zipfile.ZipFile(artifact / wheel["path"]) as archive:
        names = archive.namelist()
        _require(len(names) == len(set(names)) <= 16384, "wheel_names")
        info = archive.getinfo("codex_plugin_scanner/_native/runtime-manifest.json")
        _require(0 < info.file_size <= 65536, "native_manifest_bound")
        metadata = json.loads(archive.read(info), object_pairs_hook=_pairs)
        _require(metadata == wheel["manifest"], "native_manifest")
        runtime = wheel["runtime"][0]
        info = archive.getinfo(runtime["path"])
        _require(info.file_size == runtime["bytes"], "runtime_size")
        digest = hashlib.sha256()
        size = 0
        with archive.open(info) as stream:
            while data := stream.read(65536):
                size += len(data)
                _require(size <= runtime["bytes"], "runtime_bound")
                digest.update(data)
        _require(size == runtime["bytes"] and digest.hexdigest() == runtime["sha256"], "runtime_bytes")
    return {
        "driver_sha": os.environ["GITHUB_SHA"],
        "driver_tree": _git(driver, "rev-parse", "HEAD^{tree}"),
        "source_sha": contract["selected_build_source"],
        "source_tree": contract["selected_tree"],
        "product_sha_with_equal_tree": contract["product_source"],
        "observer_files": observer_files,
        "providers": providers,
        "interpreter_preparation_helpers": preparation_helpers,
        "artifact_members": records,
        "native_manifest": metadata,
        "runtime": runtime,
        "archive_scope": contract["archive_scope"],
    }


def _interpreter_metadata(python: Path) -> dict[str, object]:
    invocation = python.lstat()
    target = python.resolve(strict=True)
    metadata = target.lstat()
    return {
        "invocation_path": str(python),
        "invocation_symlink": stat.S_ISLNK(invocation.st_mode),
        "target_sha256": _digest(target)["sha256"],
        "target_mode": stat.S_IMODE(metadata.st_mode),
        "target_owner_current": metadata.st_uid == os.getuid(),
        "target_owner_root": metadata.st_uid == 0,
        "target_group_current": metadata.st_gid == os.getgid(),
        "target_group_root": metadata.st_gid == 0,
        "target_group_writable": bool(metadata.st_mode & stat.S_IWGRP),
        "target_world_writable": bool(metadata.st_mode & stat.S_IWOTH),
        "python_version": platform.python_version(),
    }


def _provision(args: argparse.Namespace, report: dict[str, object]) -> None:
    source = args.source.resolve(strict=True)
    python = source / ".venv/bin/python"
    _require(Path(sys.executable).absolute() == python, "preparation_invocation")
    _require(Path(sys.prefix).resolve() == python.parent.parent, "preparation_venv")
    report["interpreter_before"] = _interpreter_metadata(python)
    sys.path.insert(0, str(source))
    module = importlib.import_module("scripts.native_qualification_interpreter")
    filename = module.__file__
    _require(isinstance(filename, str), "preparation_module_file")
    _require(
        Path(cast(str, filename)).resolve() == source / "scripts/native_qualification_interpreter.py",
        "preparation_import",
    )
    try:
        report["preparation"] = module.provision_venv_interpreter(python)
    except module.InterpreterProvisioningError as error:
        report["preparation"] = error.evidence
        raise
    finally:
        try:
            report["interpreter_after"] = _interpreter_metadata(python)
        except Exception as error:
            report["interpreter_after_failure"] = {"kind": type(error).__name__}
    _require("interpreter_after_failure" not in report, "preparation_after_metadata")
    proof = cast(dict[str, Any], report["preparation"])
    _require(proof["passed"] is True and proof["identical_bytes"] is True, "preparation_proof")
    _require(
        proof["original_target_preserved"] is True and proof["managed_integrity_validated"] is True,
        "preparation_integrity",
    )
    _require(proof["owned"]["mode"] == 0o755 and proof["owned"]["owner_current"] is True, "preparation_owner_mode")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("before", "provision", "after"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, object] = {"schema": "priority-phase-installed-input-check.v1", "passed": False}
    try:
        report["binding"] = _verify(args)
        if args.operation == "provision":
            _provision(args, report)
        if args.operation == "after":
            before = _json(args.output / "input-before.json")
            _require(before.get("passed") is True and before.get("binding") == report["binding"], "after_identity")
        report["passed"] = True
    except Exception as error:
        report["failure_type"] = type(error).__name__
        report["failure_message_sha256"] = hashlib.sha256(str(error).encode()).hexdigest()
    with (args.output / ("input-" + args.operation + ".json")).open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
