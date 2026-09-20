"""Exact Git, dependency and import bindings for the Linux cause diagnostic."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

import tomllib

SOURCE = "4d10758e2cb44e5afa72a08aa631a02541dad534"
SOURCE_TREE = "fbc00caa3788eb422158a2263a578e83ac626183"
SOURCE_PARENT = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
SOURCE_FILES = 4751
DRIVER = "ci/native_runtime/linux_live_cause_diagnostic.py"
TEST = "ci/native_runtime/test_native_hook_client_transport.py"
WORKFLOW = ".github/workflows/pr2974-linux-live-cause-diagnostic.yml"
REVIEWED = {
    "rust/crates/guard-runtime/src/native_client_failure_observation.rs": "255f487df2302956c38957f80d0fd33136eba060",
    "rust/crates/guard-runtime/src/main.rs": "9f116263c7248ca1fb7a1b8fa5678ba2ce24f429",
    "rust/crates/guard-runtime/src/managed_resident.rs": "e62d276b5ac14c3c81700f179a8ae4568e1e22da",
    "ci/native_runtime/native_live_failure_diagnostic.py": "0249c090e53f1af596584c58b3cd8a562005d255",
    "ci/native_runtime/test_native_live_failure_diagnostic.py": "572f44770390955e4637c679cbe9e64b575bdc01",
    "ci/native_runtime/native_hook_client_support.py": "fa43685e6a7b2dfa36e6eb1fe9d4ed6d40375543",
}
ADDITIONS = frozenset(
    {
        DRIVER,
        WORKFLOW,
        "ci/native_runtime/linux_live_cause_identity.py",
        "rust/crates/guard-runtime/src/native_client_failure_observation.rs",
        "ci/native_runtime/native_live_failure_diagnostic.py",
        "ci/native_runtime/test_native_live_failure_diagnostic.py",
    }
)
CHANGES = frozenset(set(REVIEWED) - ADDITIONS)
TEST_NAMES = (
    "test_native_resident_contains_spoof_partial_frame_and_slow_client",
    "test_native_resident_returns_bounded_overload_signal",
)
TEST_BLOB = "6092900f8c3f69fb1e36486d0be519bc4eb5bd42"
PROCESS_SECONDS = 180.0
DRAIN_SECONDS = 5.0
OUTPUT_LIMIT = 256 * 1024
RUNTIME = "rust/target/release/hol-guard-runtime"


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_id(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(root: Path, *arguments: str) -> bytes:
    # The command and committed tree are fixed; this never runs repository code.
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        check=True,
    )
    require(len(result.stdout) <= 4_000_000, "git_output_bound")
    return result.stdout


def tree_manifest(root: Path, expected_head: str) -> dict[str, object]:
    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    require(head == expected_head, "checkout_head_mismatch")
    tree = git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    header = git(root, "cat-file", "-p", "HEAD").split(b"\n\n", 1)[0]
    parents = [
        line.removeprefix(b"parent ").decode("ascii") for line in header.splitlines() if line.startswith(b"parent ")
    ]
    rows: dict[str, dict[str, object]] = {}
    for record in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not record:
            continue
        identity, encoded_path = record.split(b"\t", 1)
        mode, kind, expected_blob = identity.decode("ascii").split()
        path = encoded_path.decode("utf-8")
        relative = Path(path)
        require(
            kind == "blob"
            and mode in {"100644", "100755"}
            and not relative.is_absolute()
            and ".." not in relative.parts,
            "unsupported_tree_entry",
        )
        file = root / relative
        require(file.is_file() and not file.is_symlink(), "tracked_file_missing_or_link")
        data = file.read_bytes()
        require(blob_id(data) == expected_blob, "raw_checkout_blob_mismatch")
        rows[path] = {"git_blob": expected_blob, "mode": mode, "bytes": len(data), "sha256": digest(data)}
    return {"head": head, "tree": tree, "parents": parents, "files": rows}


def bind_checkouts(source: Path, harness: Path, harness_sha: str) -> dict[str, object]:
    production = tree_manifest(source, SOURCE)
    validation = tree_manifest(harness, harness_sha)
    require(production["tree"] == SOURCE_TREE, "source_tree_mismatch")
    require(production["parents"] == [SOURCE_PARENT], "source_parent_mismatch")
    require(validation["parents"] == [SOURCE], "harness_parent_mismatch")
    original = production["files"]
    combined = validation["files"]
    require(isinstance(original, dict) and isinstance(combined, dict), "manifest_shape")
    require(len(original) == SOURCE_FILES, "source_file_count_mismatch")
    require(set(combined) == set(original) | ADDITIONS, "harness_addition_scope_mismatch")
    require(not (set(original) & ADDITIONS), "addition_replaces_source")
    require(
        all(combined[path] == row for path, row in original.items() if path not in CHANGES),
        "unreviewed_source_changed",
    )
    require(all(combined[path]["git_blob"] == blob for path, blob in REVIEWED.items()), "reviewed_patch_changed")
    require(combined[TEST]["git_blob"] == TEST_BLOB, "original_failed_tests_changed")
    return {"source": production, "harness": validation}


def install_identity(source: Path) -> dict[str, object]:
    executable = Path(sys.executable).resolve(strict=True)
    expected = source / ".venv" / "bin" / "python"
    require(executable == expected.resolve(strict=True), "interpreter_not_source_environment")
    require(Path(sys.prefix).resolve() == (source / ".venv").resolve(), "environment_prefix_mismatch")
    require(sys.version_info[:2] == (3, 12), "python_version_mismatch")
    distribution = importlib.metadata.distribution("hol-guard")
    direct_raw = distribution.read_text("direct_url.json")
    require(direct_raw is not None, "editable_identity_missing")
    direct = json.loads(direct_raw)
    require(direct.get("url") == source.as_uri(), "editable_source_mismatch")
    require(direct.get("dir_info", {}).get("editable") is True, "editable_flag_missing")
    lock = tomllib.loads((source / "uv.lock").read_text(encoding="utf-8"))

    def normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    locked = {(normalize(row["name"]), row["version"]) for row in lock["package"]}
    installed = []
    for entry in importlib.metadata.distributions():
        name = entry.metadata["Name"]
        require(isinstance(name, str), "distribution_name_missing")
        require((normalize(name), entry.version) in locked, "distribution_not_in_frozen_lock")
        metadata = entry.read_text("METADATA")
        require(metadata is not None, "distribution_metadata_missing")
        installed.append({"name": name, "version": entry.version, "metadata_sha256": digest(metadata.encode())})
    return {
        "kind": "frozen_editable_source_environment",
        "native_wheel_qualification": False,
        "python": sys.version,
        "platform": platform.platform(),
        "executable": str(executable),
        "executable_sha256": digest(executable.read_bytes()),
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "hol_guard_direct_url": direct,
        "installed": sorted(installed, key=lambda row: row["name"].lower()),
    }


def imported_source_identity(source: Path) -> dict[str, object]:
    expected = {}
    for item in git(source, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if item:
            identity, path = item.split(b"\t", 1)
            expected[path.decode()] = identity.decode().split()[2]
    rows = {}
    diagnostic = {
        "ci.native_runtime.native_hook_client_support",
        "native_hook_client_support",
        "ci.native_runtime.native_live_failure_diagnostic",
        "ci.native_runtime.test_native_hook_client_transport",
        "test_native_hook_client_transport",
        "scripts.ci.installed_transition_owner",
        "_linux_live_cause_identity",
        "conftest",
    }
    for name, module in sorted(sys.modules.items()):
        if not (name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") or name in diagnostic):
            continue
        file = getattr(module, "__file__", None)
        require(isinstance(file, str), "imported_source_file_missing")
        resolved = Path(file).resolve(strict=True)
        require(resolved.is_relative_to(source), "imported_source_outside_checkout")
        relative = resolved.relative_to(source).as_posix()
        data = resolved.read_bytes()
        require(blob_id(data) == expected.get(relative), "imported_source_not_tracked_blob")
        rows[name] = {"path": relative, "git_blob": blob_id(data), "sha256": digest(data)}
    require(bool(rows), "no_production_modules_loaded")
    return rows


def configure_imports(source: Path) -> None:
    require(sys.platform == "linux", "actual_linux_required")
    require(sys.flags.isolated == 1, "isolated_python_required")
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(source / "src"), str(source)]
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
