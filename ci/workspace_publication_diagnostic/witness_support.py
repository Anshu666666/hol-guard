"""Bounded, metadata-only admission for the installed workspace witness."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SOURCE_SHA = "8156ba5ec1e69908290d481bad421ba5f9bd93b2"
SOURCE_TREE = "1c551084cffda3f73ec410b432f0455579502754"
BUILD_SHA = "c331bb1ac5d9ee2082ea379713490b5b6d41e782"
WHEEL_SHA = "7b82fa210d88b2e4be3f21791101a9a0d378cd7df29205ee13fe024388c97bc8"
RUNTIME_SHA = "679da56f12eca504da0e3bc65b9abb99b1109e4caab2deb6961283865db9b2ba"
MANIFEST_SHA = "fa20cf9b73c6d7b695ab6f4c8888153f83f3451a6f0190c03fa5175a12c78b12"
ARTIFACT_SHA = "857e3701e64130d078b4483a7d5b3dc8267a6ae9e348ef1322c28f6810f8f14c"
WHEEL = (
    ROOT.parent
    / "recovered-hosted/8156/extracted/10573761511/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl"
)


class Failure(RuntimeError):
    """A fixed privacy-safe witness failure reason."""


def require(condition: object, reason: str) -> None:
    if not condition:
        raise Failure(reason)


def error_name(error: BaseException) -> str:
    return str(error) if isinstance(error, Failure) else type(error).__name__


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        result = handle.read(maximum + 1)
    require(len(result) <= maximum, "file_bound_exceeded")
    return result


def private_directory(path: Path) -> None:
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
        "private_directory_identity",
    )


def write_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def compact_directory(home: Path) -> Path:
    scope = home / "native-runtime" / ("resident-v3-" + RUNTIME_SHA[:16])
    return Path("/tmp") / ("hgr-" + RUNTIME_SHA[:8] + "-" + digest(os.fsencode(scope))[:8])


def verify_environment() -> None:
    require(sys.platform == "linux" and bool(sys.flags.isolated), "isolated_linux_interpreter_required")
    require(bool(sys.dont_write_bytecode), "bytecode_writes_disabled_required")
    prefixes = (
        "HOL_GUARD_",
        "GUARD_NATIVE",
        "GUARD_TEST_",
        "GUARD_ORACLE",
        "GUARD_DIAGNOSTIC",
        "GUARD_BINARY",
        "GUARD_FAST_PATH",
        "GUARD_HOOK_",
        "GUARD_PYTHON_ORACLE",
        "GUARD_PYTEST_",
        "PYTEST_",
    )
    require(
        not any(name.startswith(prefixes) or name == "PYTHONPATH" for name in os.environ),
        "development_override_present",
    )


def verify_helpers() -> dict[str, Any]:
    content = bounded(ROOT / "source-manifest.json", 1024 * 1024)
    manifest = json.loads(content)
    require(
        manifest["published_source_sha"] == SOURCE_SHA and manifest["source_tree"] == SOURCE_TREE,
        "helper_source_identity",
    )
    for name, expected in {**manifest["helpers"], **manifest["resources"]}.items():
        data = bounded(ROOT / "helpers" / name, 1024 * 1024)
        require(len(data) == expected["bytes"] and digest(data) == expected["sha256"], "copied_helper_changed")
    return {
        "source_sha": SOURCE_SHA,
        "source_tree": SOURCE_TREE,
        "files": len(manifest["helpers"]),
        "resource_files": len(manifest["resources"]),
        "manifest_sha256": digest(content),
    }


def verify_installation(wheel: Path = WHEEL) -> tuple[Path, dict[str, Any]]:
    verify_environment()
    require(digest(bounded(wheel, 64 * 1024 * 1024)) == WHEEL_SHA, "wheel_digest")
    distribution = importlib.metadata.distribution("hol-guard")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    require(not direct.get("dir_info", {}).get("editable", False), "editable_install")
    identities = []
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate_wheel_member")
        for name in names:
            if not name.startswith("codex_plugin_scanner/") or name.endswith("/"):
                continue
            path = Path(str(distribution.locate_file(name))).resolve(strict=True)
            require("site-packages" in path.parts, "installed_package_origin")
            content = bounded(path, 64 * 1024 * 1024)
            require(content == archive.read(name), "installed_wheel_member_changed")
            identities.append({"member": name, "bytes": len(content), "sha256": digest(content)})
    require(len(identities) == 1329, "installed_guard_member_count")
    executable = Path(str(distribution.locate_file("codex_plugin_scanner/_native/hol-guard-runtime"))).resolve(
        strict=True
    )
    require(digest(bounded(executable, 64 * 1024 * 1024)) == RUNTIME_SHA, "runtime_digest")
    manifest = bounded(executable.with_name("runtime-manifest.json"), 16384)
    require(digest(manifest) == MANIFEST_SHA, "runtime_manifest_digest")
    require(json.loads(manifest)["source_sha"] == BUILD_SHA, "runtime_build_sha")
    return executable, {
        "published_source_sha": SOURCE_SHA,
        "production_source_tree": SOURCE_TREE,
        "runtime_build_sha": BUILD_SHA,
        "artifact_id": 10573761511,
        "artifact_archive_sha256": ARTIFACT_SHA,
        "wheel_sha256": WHEEL_SHA,
        "runtime_sha256": RUNTIME_SHA,
        "manifest_sha256": MANIFEST_SHA,
        "all_guard_members_verified": len(identities),
        "installed_member_inventory_sha256": digest(encoded(sorted(identities, key=lambda item: item["member"]))),
        "package_version": distribution.version,
        "python_version": sys.version.split()[0],
    }


def verify_loaded_origins() -> None:
    distribution = importlib.metadata.distribution("hol-guard")
    expected = Path(str(distribution.locate_file("codex_plugin_scanner"))).resolve()
    for name, module in tuple(sys.modules.items()):
        if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
            filename = getattr(module, "__file__", None)
            if filename is not None:
                require(
                    Path(filename).resolve().is_relative_to(expected), "production_import_escaped_installed_package"
                )
