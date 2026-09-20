"""Exact source, default installed wheel and host bindings outside samples."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, cast

from .capture import json_bytes
from .projection import _pairs


def require(value: bool, label: str) -> None:
    if not value:
        raise RuntimeError("priority_phase_binding_" + label)


def digest(path: Path, maximum: int = 128 * 1024 * 1024) -> str:
    result = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            require(size <= maximum, "file_size")
            result.update(chunk)
    require(size > 0, "empty_file")
    return result.hexdigest()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536, "git_output")
    return result.stdout.strip()


def checkout_binding(root: Path, sha: str, tree: str | None = None) -> dict[str, object]:
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "sha")
    actual_sha = git(root, "rev-parse", "HEAD")
    actual_tree = git(root, "rev-parse", "HEAD^{tree}")
    clean = not git(root, "status", "--porcelain", "--untracked-files=no")
    require(actual_sha == sha and (tree is None or actual_tree == tree) and clean, "checkout")
    return {"sha": actual_sha, "tree": actual_tree, "tracked_clean": clean}


def read_bindings(path: Path, source_sha: str, source_tree: str) -> dict[str, Any]:
    with path.open("rb") as stream:
        data = stream.read(128 * 1024 + 1)
    require(len(data) <= 128 * 1024, "manifest_size")
    value = json.loads(data, object_pairs_hook=_pairs)
    require(
        type(value) is dict and value.get("schema") == "hol-guard.priority-launcher-phase-source.v1", "manifest_schema"
    )
    value = cast(dict[str, Any], value)
    require(value.get("source_sha") == source_sha and value.get("source_tree") == source_tree, "manifest_source")
    rows = value.get("files")
    require(type(rows) is list and 8 <= len(rows) <= 64, "manifest_files")
    rows = cast(list[Any], rows)
    seen: set[str] = set()
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "git_blob", "sha256"}, "manifest_row")
        row = cast(dict[str, Any], row)
        name = row["path"]
        require(
            type(name) is str
            and name.endswith(".py")
            and name.startswith(("src/codex_plugin_scanner/", "scripts/"))
            and ".." not in Path(name).parts
            and name not in seen,
            "manifest_path",
        )
        name = cast(str, name)
        seen.add(name)
        require(re.fullmatch(r"[0-9a-f]{40}", row["git_blob"]) is not None, "manifest_blob")
        require(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, "manifest_digest")
    return value


def source_binding(root: Path, manifest: dict[str, Any]) -> dict[str, object]:
    result = checkout_binding(root, manifest["source_sha"], manifest["source_tree"])
    files: dict[str, str] = {}
    for row in manifest["files"]:
        name = row["path"]
        require(git(root, "rev-parse", "HEAD:" + name) == row["git_blob"], "source_blob")
        value = digest(root / name, 1024 * 1024)
        require(value == row["sha256"], "source_bytes")
        files[name] = value
    result["files_sha256"] = files
    return result


def installed_binding(wheel: Path, source_sha: str, manifest: dict[str, Any]) -> tuple[dict[str, object], Path]:
    import codex_plugin_scanner
    from codex_plugin_scanner.guard import native_runtime

    distribution = importlib.metadata.distribution("hol-guard")
    package_root = Path(str(distribution.locate_file(""))).resolve()
    module = package_root / "codex_plugin_scanner/__init__.py"
    require(
        Path(str(codex_plugin_scanner.__file__)).resolve() == module and "site-packages" in module.parts,
        "installed_import",
    )
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    require(not direct.get("dir_info", {}).get("editable", False), "editable")
    record = distribution.read_text("RECORD")
    require(type(record) is str and 0 < len(record) <= 4 * 1024 * 1024, "record")
    status = native_runtime.native_runtime_status()
    require(
        status.mode == "auto"
        and status.available
        and status.compatible
        and status.identity is not None
        and status.capabilities is not None,
        "default_auto",
    )
    assert status.identity is not None and status.capabilities is not None and record is not None
    require(status.capabilities.build_sha == source_sha, "native_source")
    require(not any("diagnostic" in feature for feature in status.capabilities.features), "default_features")
    runtime = status.identity.path
    require(digest(runtime) == status.identity.sha256, "native_bytes")
    expected: dict[str, str | None] = {
        row["path"][4:]: row["sha256"] for row in manifest["files"] if row["path"].startswith("src/")
    }
    expected.update(
        {
            runtime.relative_to(package_root).as_posix(): status.identity.sha256,
            runtime.with_name("runtime-manifest.json").relative_to(package_root).as_posix(): None,
        }
    )
    installed: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel_duplicate")
        for name, wanted in expected.items():
            information = archive.getinfo(name)
            require(0 < information.file_size <= 128 * 1024 * 1024, "wheel_member")
            hashed = hashlib.sha256()
            with archive.open(information) as stream:
                while chunk := stream.read(64 * 1024):
                    hashed.update(chunk)
            value = digest(package_root / name)
            require(value == hashed.hexdigest() and (wanted is None or value == wanted), "wheel_member_bytes")
            installed[name] = value
    return {
        "wheel_sha256": digest(wheel),
        "record_sha256": hashlib.sha256(record.encode()).hexdigest(),
        "package_version": distribution.version,
        "native_runtime_sha256": status.identity.sha256,
        "native_build_sha": status.capabilities.build_sha,
        "native_target": status.capabilities.target,
        "native_features": list(status.capabilities.features),
        "installed_files_sha256": installed,
        "noneditable_installed_import": True,
    }, runtime


def host_details() -> dict[str, object]:
    import resource

    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "load_average": list(os.getloadavg()),
        "file_descriptor_limit": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "address_space_limit": list(resource.getrlimit(resource.RLIMIT_AS)),
        "interpreter_sha256": digest(Path(sys.executable)),
    }


def write_report(path: Path, report: object, *, maximum: int = 1024 * 1024) -> None:
    encoded = json_bytes(report) + b"\n"
    require(len(encoded) <= maximum, "report_size")
    with path.open("xb") as stream:
        stream.write(encoded)
