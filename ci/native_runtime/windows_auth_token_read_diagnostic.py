"""One fixed Windows source-level sharing control; no installed native qualification."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

SOURCE = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
SOURCE_TREE = "c10faac2d156cac06f9f803d63f50d15e3ca82bf"
SOURCE_FILES = 4751
DRIVER = "ci/native_runtime/windows_auth_token_read_diagnostic.py"
TEST = "ci/native_runtime/test_windows_auth_token_held_reader_diagnostic.py"
WORKFLOW = ".github/workflows/pr2974-windows-auth-token-read-diagnostic.yml"
ADDITIONS = frozenset({DRIVER, TEST, WORKFLOW})
TEST_NAME = "test_original_reader_blocks_atomic_token_replacement_on_windows"
TEST_BLOB = "ec24de880dcd709743cfe10abc86429aadb9d545"
PROCESS_SECONDS = 30.0
OUTPUT_LIMIT = 1_000_000


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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=True,
    )
    require(len(result.stdout) <= 4_000_000, "git_output_bound")
    return result.stdout


def tree_manifest(root: Path, expected_head: str) -> dict[str, object]:
    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    require(head == expected_head, "checkout_head_mismatch")
    tree = git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    parents = git(root, "show", "-s", "--format=%P", "HEAD").decode("ascii").split()
    rows: dict[str, dict[str, object]] = {}
    for record in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not record:
            continue
        identity, encoded_path = record.split(b"\t", 1)
        mode, kind, expected_blob = identity.decode("ascii").split()
        path = encoded_path.decode("utf-8")
        relative = Path(path)
        require(
            kind == "blob" and mode in {"100644", "100755"}
            and not relative.is_absolute() and ".." not in relative.parts,
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
    require(validation["parents"] == [SOURCE], "harness_parent_mismatch")
    original = production["files"]
    combined = validation["files"]
    require(isinstance(original, dict) and isinstance(combined, dict), "manifest_shape")
    require(len(original) == SOURCE_FILES, "source_file_count_mismatch")
    require(set(combined) == set(original) | ADDITIONS, "harness_addition_scope_mismatch")
    require(not (set(original) & ADDITIONS), "addition_replaces_source")
    require(all(combined[path] == row for path, row in original.items()), "harness_source_changed")
    require(combined[TEST]["git_blob"] == TEST_BLOB, "reviewed_test_changed")
    return {"source": production, "harness": validation}


def install_identity(source: Path) -> dict[str, object]:
    executable = Path(sys.executable).resolve(strict=True)
    expected = source / ".venv" / "Scripts" / "python.exe"
    require(executable == expected.resolve(strict=True), "interpreter_not_source_environment")
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
    prefix = source / "src"
    rows = {}
    for name, module in sorted(sys.modules.items()):
        if name != "codex_plugin_scanner" and not name.startswith("codex_plugin_scanner."):
            continue
        file = getattr(module, "__file__", None)
        require(isinstance(file, str), "imported_source_file_missing")
        resolved = Path(file).resolve(strict=True)
        require(resolved.is_relative_to(prefix), "imported_source_outside_checkout")
        data = resolved.read_bytes()
        rows[name] = {
            "path": resolved.relative_to(source).as_posix(),
            "git_blob": blob_id(data),
            "sha256": digest(data),
        }
    require(bool(rows), "no_production_modules_loaded")
    return rows


def configure_imports(source: Path) -> None:
    require(os.name == "nt", "actual_windows_required")
    require(sys.flags.isolated == 1, "isolated_python_required")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "src"))
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"


class Reports:
    def __init__(self) -> None:
        self.collected: list[str] = []
        self.phases: list[dict[str, object]] = []

    def pytest_collection_finish(self, session) -> None:
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report) -> None:
        self.phases.append({
            "nodeid": report.nodeid,
            "when": report.when,
            "outcome": report.outcome,
            "duration_seconds": report.duration,
        })


def child(args) -> int:
    import pytest

    output = args.output
    report = {"schema": "windows-auth-token-child.v1", "status": "started"}
    write_json(output / "child.json", report)
    reports = Reports()
    exit_code = None
    try:
        report["installation_before"] = install_identity(args.source_root)
        exit_code = pytest.main([
            "-q", "-o", "addopts=", "--noconftest", "-p", "no:cacheprovider",
            "--rootdir=" + str(args.harness_root / "ci/native_runtime"),
            "--basetemp=" + str(output / "pytest-temp"),
            "--junitxml=" + str(output / "junit.xml"),
            str(args.harness_root / TEST) + "::" + TEST_NAME,
        ], plugins=[reports])
        report["pytest_exit_code"] = int(exit_code)
        require(len(reports.collected) == 1, "expected_one_collected_test")
        require(reports.collected[0].endswith("::" + TEST_NAME), "unexpected_test")
        require(
            [(row["when"], row["outcome"]) for row in reports.phases]
            == [("setup", "passed"), ("call", "passed"), ("teardown", "passed")],
            "test_phases_not_all_passed",
        )
        report["status"] = "passed"
    finally:
        report["collected"] = reports.collected
        report["phases"] = reports.phases
        report["imported_source_after"] = imported_source_identity(args.source_root)
        report["installation_after"] = install_identity(args.source_root)
        write_json(output / "child.json", report)
    return int(exit_code)


def clean_environment() -> tuple[dict[str, str], list[str]]:
    environment = dict(os.environ)
    removed = []
    for key in tuple(environment):
        if key.upper().startswith(("PYTHON", "PYTEST", "HOL_GUARD", "GUARD_")):
            removed.append(key)
            del environment[key]
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment, sorted(removed)


def validate_result(output: Path) -> None:
    child_report = json.loads((output / "child.json").read_text(encoding="utf-8"))
    require(child_report["status"] == "passed" and child_report["pytest_exit_code"] == 0, "child_not_passed")
    require(
        child_report["installation_before"] == child_report["installation_after"],
        "child_installation_changed",
    )
    require((output / "junit.xml").stat().st_size <= OUTPUT_LIMIT, "junit_size_bound")
    cases = list(ET.parse(output / "junit.xml").getroot().iter("testcase"))
    require(len(cases) == 1 and cases[0].get("name") == TEST_NAME, "junit_case_mismatch")
    require(not list(cases[0]), "junit_not_clean_pass")


def emit_terminal_evidence(output: Path) -> None:
    """Expose exact small originals without relying on artifact download access."""

    names = (
        "result.json", "child.json", "installation-before.json", "installation-after.json",
        "junit.xml", "stdout.log", "stderr.log",
    )
    evidence: dict[str, object] = {
        "schema": "windows-auth-token-terminal.v1", "files": {}, "source_manifests": {},
    }
    for name in names:
        file = output / name
        if not file.is_file():
            evidence["files"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 2_000_000, "terminal_file_bound")
        raw = file.read_bytes()
        evidence["files"][name] = {
            "bytes": len(raw), "sha256": digest(raw), "content": raw.decode("utf-8"),
        }
    for name in ("source-before.json", "source-after.json"):
        file = output / name
        if not file.is_file():
            evidence["source_manifests"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 8_000_000, "terminal_manifest_bound")
        raw = file.read_bytes()
        manifest = json.loads(raw)
        evidence["source_manifests"][name] = {
            "bytes": len(raw), "sha256": digest(raw),
            "bindings": {
                key: {
                    "head": value["head"], "tree": value["tree"], "parents": value["parents"],
                    "file_count": len(value["files"]),
                }
                for key, value in manifest.items()
            },
            "full_original_retained_in_artifact": True,
        }
    encoded = json.dumps(evidence, sort_keys=True)
    require(len(encoded.encode("utf-8")) <= 8_000_000, "terminal_total_bound")
    print("WINDOWS_AUTH_TOKEN_DIAGNOSTIC_BEGIN")
    print(encoded, flush=True)
    print("WINDOWS_AUTH_TOKEN_DIAGNOSTIC_END", flush=True)


def parent(args) -> int:
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "windows-auth-token-held-reader.v1",
        "status": "started",
        "source": SOURCE,
        "source_tree": SOURCE_TREE,
        "harness": args.harness_sha,
        "process_seconds": PROCESS_SECONDS,
        "combined_output_byte_cap": OUTPUT_LIMIT,
        "native_wheel_or_performance_qualification": False,
        "historical_conflicting_handle_identified": False,
    }
    write_json(output / "result.json", result)
    before = None
    installation = None
    try:
        before = bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
        write_json(output / "source-before.json", before)
        installation = install_identity(args.source_root)
        write_json(output / "installation-before.json", installation)
        from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

        environment, removed = clean_environment()
        result["removed_environment_key_names"] = removed
        command = [
            sys.executable, "-I", str(args.harness_root / DRIVER), "--child",
            "--source-root", str(args.source_root), "--harness-root", str(args.harness_root),
            "--harness-sha", args.harness_sha, "--output", str(output),
        ]
        result["command"] = command
        result["process_start_monotonic"] = time.monotonic()
        bounded = run_isolated_hook_process(
            command, input_text="", cwd=args.source_root, environment=environment,
            deadline_monotonic=result["process_start_monotonic"] + PROCESS_SECONDS,
            output_limit=OUTPUT_LIMIT, allow_windows_breakaway=False, windows_kill_on_job_close=True,
        )
        result["process_finish_monotonic"] = time.monotonic()
        (output / "stdout.log").write_text(bounded.stdout, encoding="utf-8")
        (output / "stderr.log").write_text(bounded.stderr, encoding="utf-8")
        outcome = asdict(bounded)
        outcome.pop("stdout")
        outcome.pop("stderr")
        result["process"] = outcome
        require(
            bounded.returncode == 0 and not bounded.timed_out
            and not bounded.output_limit_exceeded and not bounded.containment_failed,
            "bounded_process_not_passed",
        )
        validate_result(output)
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["failure_type"] = type(error).__name__
        raise
    finally:
        try:
            after = bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
            write_json(output / "source-after.json", after)
            current_installation = install_identity(args.source_root)
            write_json(output / "installation-after.json", current_installation)
            result["parent_imports"] = imported_source_identity(args.source_root)
            require(before == after, "source_or_harness_changed")
            require(installation == current_installation, "parent_installation_changed")
            result["source_and_installation_unchanged"] = True
        except Exception as error:
            result["status"] = "failed"
            result["postflight_failure_type"] = type(error).__name__
            raise
        finally:
            write_json(output / "result.json", result)
            emit_terminal_evidence(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--harness-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.harness_sha) is not None, "harness_sha_invalid")
    args.source_root = args.source_root.resolve(strict=True)
    args.harness_root = args.harness_root.resolve(strict=True)
    args.output = args.output.resolve()
    require(
        not args.output.is_relative_to(args.source_root)
        and not args.output.is_relative_to(args.harness_root),
        "output_inside_checkout",
    )
    configure_imports(args.source_root)
    if args.child:
        return child(args)
    return parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
