"""Read-only installed identity for the isolated priority campaign worker.

Source/build Git provenance and hash-enforced installation belong to the outer
driver. This read repeats the actual original wheel members, installed RECORD,
package import origin, default native identity, provider and interpreter bytes.
Generated unlisted caches are outside this declared inventory scope.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, cast


def require(value: bool, label: str) -> None:
    if not value:
        raise ValueError("campaign_identity_" + label)


def digest(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and 0 <= metadata.st_size <= 256 * 1024 * 1024, "file")
    result = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            total += len(chunk)
            require(total <= metadata.st_size, "file_growth")
            result.update(chunk)
    after = path.lstat()
    require(
        total == metadata.st_size
        and all(
            getattr(metadata, key) == getattr(after, key)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ),
        "file_changed",
    )
    return {"bytes": total, "sha256": result.hexdigest()}


def wheel_members(distribution: importlib.metadata.Distribution, wheel: Path) -> int:
    """Same member/RECORD boundary as the retained installed-route driver."""
    root = Path(str(distribution.locate_file(""))).resolve(strict=True)
    verified = 0
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        require(len(infos) == len({row.filename for row in infos}) <= 20_000, "wheel_members_duplicate")
        require(sum(row.file_size for row in infos) <= 256 * 1024 * 1024, "wheel_members_bound")
        for row in infos:
            name = PurePosixPath(row.filename)
            require(not name.is_absolute() and ".." not in name.parts, "wheel_member_path")
            if row.is_dir() or row.filename.endswith(".dist-info/RECORD"):
                continue
            path = Path(str(distribution.locate_file(row.filename)))
            require(path.resolve(strict=True).is_relative_to(root), "installed_member_origin")
            actual = digest(path)
            require(
                actual == {"bytes": row.file_size, "sha256": hashlib.sha256(archive.read(row)).hexdigest()},
                "installed_member_bytes",
            )
            verified += 1
    require(verified > 0, "empty_wheel")
    return verified


def json_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        require(key not in result, "duplicate_json")
        result[key] = value
    return result


class InstalledIdentity:
    """Construct and call only after the protected kernel boundary is admitted."""

    def __init__(self, *, wheel: Path, python: Path, providers: Path, contract: dict[str, Any]) -> None:
        self.wheel = wheel
        self.python = python
        self.providers = providers
        self.contract = contract
        self.runtime: Path | None = None
        self.last_inventory: dict[str, Any] = {}
        self.inventories: list[dict[str, Any]] = []

    def __call__(self) -> dict[str, Any]:
        require(sys.platform == "linux" and platform.machine() == "x86_64" and sys.flags.isolated == 1, "platform")
        require(sys.version_info[:2] == (3, 12), "python_version")
        require(self.contract["default_native_features"] is True, "bound_default_features")
        require(
            Path(sys.executable).absolute() == self.python
            and Path(sys.prefix).resolve() == self.python.parent.parent.resolve(),
            "venv",
        )
        executable = self.python.resolve(strict=True)
        metadata = executable.stat()
        require(
            metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o755 and not self.python.is_symlink(),
            "owned_interpreter",
        )
        from codex_plugin_scanner.guard.config import hook_fast_path_enabled
        from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status
        from scripts.installed_canary_proof import verify_installed_record
        from scripts.native_slo_artifact import (
            assert_installed_import_origin,
            installed_package_digest,
            wheel_package_digest,
        )
        from scripts.native_slo_contract import proof_environment_violations

        require(not proof_environment_violations(), "proof_environment")
        require(native_mode() == "auto" and hook_fast_path_enabled(), "default_auto")
        distribution = importlib.metadata.distribution("hol-guard")
        installation_root = Path(str(distribution.locate_file(""))).resolve(strict=True)
        require(installation_root.is_relative_to(Path(sys.prefix).resolve()), "installed_prefix")
        direct_url = distribution.read_text("direct_url.json")
        require(type(direct_url) is str and 0 < len(direct_url) <= 65_536, "installed_origin")
        origin = json.loads(cast(str, direct_url), object_pairs_hook=unique_pairs)
        require(
            type(origin) is dict
            and set(origin) == {"url", "archive_info"}
            and origin["url"] == self.wheel.absolute().as_uri()
            and type(origin["archive_info"]) is dict,
            "installed_origin",
        )
        assert_installed_import_origin(distribution)
        package_digest = installed_package_digest(distribution)
        require(package_digest == wheel_package_digest(self.wheel), "package_bytes")
        member_count = wheel_members(distribution, self.wheel)
        record_sha, record_count = verify_installed_record(distribution)
        status = native_runtime_status()
        require(status.available and status.compatible and status.reason == "native_ready", "native_status")
        native, capabilities = status.identity, status.capabilities
        require(native is not None and capabilities is not None, "native_identity")
        assert native is not None and capabilities is not None
        require(capabilities.build_sha == self.contract["build_commit"], "native_build")
        require(capabilities.target == self.contract["target"] == "x86_64-unknown-linux-musl", "native_target")
        self.runtime = native.path
        native_digest = digest(native.path)
        require(native_digest["sha256"] == native.sha256, "native_bytes")
        observed = []
        rows = self.contract["providers"]
        require(type(rows) is list and 1 <= len(rows) <= 256, "provider_count")
        seen = set()
        for row in cast(list[dict[str, Any]], rows):
            require(type(row) is dict and set(row) == {"path", "bytes", "sha256"}, "provider_schema")
            name = row["path"]
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and ".." not in relative.parts and name not in seen, "provider_path")
            seen.add(name)
            actual = digest(self.providers / name)
            require(actual == {"bytes": row["bytes"], "sha256": row["sha256"]}, "provider_bytes")
            observed.append({"path": name, **actual})
        dependencies = sorted([item.metadata["Name"], item.version] for item in importlib.metadata.distributions())
        inventory = {
            "package_sha256": package_digest,
            "wheel_members": member_count,
            "record_sha256": record_sha,
            "record_members": record_count,
            "dependencies_sha256": json_digest(dependencies),
            "scope": "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches",
        }
        self.last_inventory = inventory
        self.inventories.append(inventory)
        require(len(self.inventories) <= 2, "identity_call_bound")
        if len(self.inventories) == 2:
            require(self.inventories[0] == self.inventories[1], "local_installation_changed")
        result = {name: self.contract[name] for name in ("source_commit", "source_tree", "build_commit", "build_tree")}
        result.update(
            wheel_sha256=digest(self.wheel)["sha256"],
            # Common per-arm content identity excludes host-local generated
            # installer metadata. Its full original RECORD is still verified
            # twice and retained/joined in inventories for this exact worker.
            installed_manifest_sha256=package_digest,
            runtime_sha256=native.sha256,
            runtime_rule_digest=capabilities.rule_digest,
            policy_fixture_sha256=self.contract["policy_fixture_sha256"],
            corpus_sha256=digest(self.providers / "tests/fixtures/guard-native-qualification/corpus.v1.json")["sha256"],
            producer_sha256=digest(self.providers / "scripts/native_slo_priority_launchers.py")["sha256"],
            providers_sha256=json_digest(observed),
            interpreter_sha256=digest(executable)["sha256"],
            package_version=distribution.version,
            python_version=platform.python_version(),
            default_native_features=self.contract["default_native_features"],
        )
        require(result == self.contract["expected_identity"], "expected_identity")
        return result
