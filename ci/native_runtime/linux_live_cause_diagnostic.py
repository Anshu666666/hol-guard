"""One fixed two-case Linux cause diagnostic; no performance qualification."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

IDENTITY_SHA256 = "79a6fc84f8fd34b4c40faca71c3690bbe4a344cd4d241c28d0f4b74c58c37ffe"
IDENTITY_PATH = Path(__file__).resolve().with_name("linux_live_cause_identity.py")
if hashlib.sha256(IDENTITY_PATH.read_bytes()).hexdigest() != IDENTITY_SHA256:
    raise RuntimeError("identity_helper_bytes_mismatch")
_spec = importlib.util.spec_from_file_location("_linux_live_cause_identity", IDENTITY_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("identity_helper_unavailable")
_identity = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _identity
_spec.loader.exec_module(_identity)

SOURCE = _identity.SOURCE
SOURCE_TREE = _identity.SOURCE_TREE
DRIVER = _identity.DRIVER
TEST = _identity.TEST
TEST_NAMES = _identity.TEST_NAMES
PROCESS_SECONDS = _identity.PROCESS_SECONDS
DRAIN_SECONDS = _identity.DRAIN_SECONDS
OUTPUT_LIMIT = _identity.OUTPUT_LIMIT
RUNTIME = _identity.RUNTIME
require = _identity.require
digest = _identity.digest
write_json = _identity.write_json
bind_checkouts = _identity.bind_checkouts
install_identity = _identity.install_identity
imported_source_identity = _identity.imported_source_identity
configure_imports = _identity.configure_imports


class Reports:
    def __init__(self) -> None:
        self.collected: list[str] = []
        self.phases: list[dict[str, object]] = []

    def pytest_collection_finish(self, session) -> None:
        self.collected = [item.nodeid for item in session.items]
        require(self.collected == [TEST + "::" + name for name in TEST_NAMES], "fixed_collection_changed")

    def pytest_runtest_logreport(self, report) -> None:
        self.phases.append(
            {
                "nodeid": report.nodeid,
                "when": report.when,
                "outcome": report.outcome,
                "duration_seconds": report.duration,
                "properties": list(report.user_properties),
            }
        )


def child(args) -> int:
    import pytest

    output = args.output
    report = {"schema": "linux-live-cause-child.v1", "status": "started"}
    write_json(output / "child.json", report)
    reports = Reports()
    exit_code = None
    try:
        report["installation_before"] = install_identity(args.harness_root)
        exit_code = pytest.main(
            [
                "-q",
                "-o",
                "junit_family=xunit1",
                "-p",
                "no:cacheprovider",
                "--tb=short",
                "--rootdir=" + str(args.harness_root),
                "--basetemp=" + str(output / "pytest-temp"),
                "--junitxml=" + str(output / "junit.xml"),
                *[str(args.harness_root / TEST) + "::" + name for name in TEST_NAMES],
            ],
            plugins=[reports],
        )
        report["pytest_exit_code"] = int(exit_code)
        expected_nodes = [TEST + "::" + name for name in TEST_NAMES]
        require(reports.collected == expected_nodes, "expected_exact_two_collected_tests")
        require(
            [(row["nodeid"], row["when"], row["outcome"]) for row in reports.phases]
            == [(node, phase, "passed") for node in expected_nodes for phase in ("setup", "call", "teardown")],
            "test_phases_not_all_passed",
        )
        report["status"] = "passed"
    finally:
        report["collected"] = reports.collected
        report["phases"] = reports.phases
        report["imported_source_after"] = imported_source_identity(args.harness_root)
        report["installation_after"] = install_identity(args.harness_root)
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
    report = json.loads((output / "child.json").read_text(encoding="utf-8"))
    require(report["status"] == "passed" and report["pytest_exit_code"] == 0, "child_not_passed")
    require(report["installation_before"] == report["installation_after"], "child_installation_changed")
    require((output / "junit.xml").stat().st_size <= OUTPUT_LIMIT, "junit_size_bound")
    cases = list(ET.parse(output / "junit.xml").getroot().iter("testcase"))
    require([case.get("name") for case in cases] == list(TEST_NAMES), "junit_case_mismatch")
    require(all(not list(case) for case in cases), "junit_not_clean_pass")


def binary_identity(harness: Path) -> dict[str, object]:
    path = harness / RUNTIME
    require(path.is_file() and not path.is_symlink(), "runtime_file_invalid")
    before = path.stat()
    require(0 < before.st_size <= 128 * 1024 * 1024, "runtime_size_bound")
    data = path.read_bytes()
    after = path.stat()
    keys = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(
        all(getattr(before, key) == getattr(after, key) for key in keys) and len(data) == before.st_size,
        "runtime_changed_while_reading",
    )
    require(data.startswith(b"\x7fELF"), "runtime_not_elf")
    return {
        "path": RUNTIME,
        "bytes": len(data),
        "sha256": digest(data),
        "file_identity": {key: getattr(before, key) for key in keys},
    }


def capability_witness(harness: Path, harness_sha: str) -> dict[str, object]:
    result = subprocess.run(
        [str(harness / RUNTIME), "self-test", "--json"],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
    )
    require(len(result.stdout) <= 65536 and not result.stderr, "capability_output_bound")
    value = json.loads(result.stdout)
    require(value.get("ok") is True, "runtime_self_test_failed")
    require(value["capabilities"]["build_sha"] == harness_sha, "compiled_source_sha_mismatch")
    return value


def emit_terminal_evidence(output: Path) -> None:
    """Expose exact small originals without relying on artifact download access."""

    names = (
        "result.json",
        "child.json",
        "installation-before.json",
        "installation-after.json",
        "junit.xml",
        "stdout.log",
        "stderr.log",
        "binary-before.json",
        "binary-after.json",
        "capabilities.json",
    )
    evidence: dict[str, object] = {
        "schema": "linux-live-cause-terminal.v1",
        "files": {},
        "source_manifests": {},
    }
    for name in names:
        file = output / name
        if not file.is_file():
            evidence["files"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 2_000_000, "terminal_file_bound")
        raw = file.read_bytes()
        evidence["files"][name] = {
            "bytes": len(raw),
            "sha256": digest(raw),
            "content": raw.decode("utf-8"),
        }
    for name in ("source-prebuild.json", "source-before.json", "source-after.json"):
        file = output / name
        if not file.is_file():
            evidence["source_manifests"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 8_000_000, "terminal_manifest_bound")
        raw = file.read_bytes()
        manifest = json.loads(raw)
        evidence["source_manifests"][name] = {
            "bytes": len(raw),
            "sha256": digest(raw),
            "bindings": {
                key: {
                    "head": value["head"],
                    "tree": value["tree"],
                    "parents": value["parents"],
                    "file_count": len(value["files"]),
                }
                for key, value in manifest.items()
            },
            "full_original_retained_in_artifact": True,
        }
    encoded = json.dumps(evidence, sort_keys=True)
    require(len(encoded.encode("utf-8")) <= 8_000_000, "terminal_total_bound")
    print("LINUX_LIVE_CAUSE_DIAGNOSTIC_BEGIN")
    print(encoded, flush=True)
    print("LINUX_LIVE_CAUSE_DIAGNOSTIC_END", flush=True)


def parent(args) -> int:
    output = args.output
    require(output.is_dir(), "preflight_output_missing")
    result = {
        "schema": "linux-live-cause-diagnostic.v1",
        "status": "started",
        "source": SOURCE,
        "source_tree": SOURCE_TREE,
        "harness": args.harness_sha,
        "process_seconds_after_spawn": PROCESS_SECONDS,
        "drain_seconds": DRAIN_SECONDS,
        "workflow_step_seconds": 240,
        "combined_output_byte_cap": OUTPUT_LIMIT,
        "qualification_complete": False,
        "headline_timing_eligible": False,
        "original15_case_validation_credit": False,
        "original_cli_timeout_seconds": 8,
        "selected_tests": list(TEST_NAMES),
        "population_runs": 1,
        "pre_spawn_wall_bound": "outer240secondworkflowstep; owner deadline begins after Popen",
    }
    write_json(output / "result.json", result)
    before = None
    installation = None
    binary = None
    try:
        before = bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
        require(before == json.loads((output / "source-prebuild.json").read_text()), "prebuild_source_changed")
        write_json(output / "source-before.json", before)
        binary = binary_identity(args.harness_root)
        write_json(output / "binary-before.json", binary)
        write_json(output / "capabilities.json", capability_witness(args.harness_root, args.harness_sha))
        installation = install_identity(args.harness_root)
        require(
            installation == json.loads((output / "installation-prebuild.json").read_text()),
            "prebuild_installation_changed",
        )
        write_json(output / "installation-before.json", installation)
        from scripts.ci.installed_transition_owner import run_owned

        environment, removed = clean_environment()
        result["removed_environment_key_names"] = removed
        environment["HOL_GUARD_NATIVE"] = "force"
        environment["HOL_GUARD_NATIVE_BINARY"] = str(args.harness_root / RUNTIME)
        command = [
            sys.executable,
            "-I",
            str(args.harness_root / DRIVER),
            "--child",
            "--source-root",
            str(args.source_root),
            "--harness-root",
            str(args.harness_root),
            "--harness-sha",
            args.harness_sha,
            "--output",
            str(output),
        ]
        result["command"] = command
        result["process_start_monotonic"] = time.monotonic()
        bounded = run_owned(
            tuple(command),
            cwd=args.harness_root,
            environment=environment,
            timeout_seconds=PROCESS_SECONDS,
            drain_seconds=DRAIN_SECONDS,
            output_limit=OUTPUT_LIMIT,
        )
        result["process_finish_monotonic"] = time.monotonic()
        (output / "stdout.log").write_bytes(bounded.stdout)
        (output / "stderr.log").write_bytes(bounded.stderr)
        result["process"] = {"returncode": bounded.returncode, "ownership": bounded.evidence}
        require(bounded.evidence.get("verified") is True, "owned_retirement_unverified")
        require(bounded.returncode == 0, "original_pytest_failed")
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
            current_binary = binary_identity(args.harness_root)
            write_json(output / "binary-after.json", current_binary)
            require(binary == current_binary, "runtime_changed")
            current_installation = install_identity(args.harness_root)
            write_json(output / "installation-after.json", current_installation)
            result["parent_imports"] = imported_source_identity(args.harness_root)
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
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.harness_sha) is not None, "harness_sha_invalid")
    args.source_root = args.source_root.resolve(strict=True)
    args.harness_root = args.harness_root.resolve(strict=True)
    args.output = args.output.resolve()
    require(
        not args.output.is_relative_to(args.source_root) and not args.output.is_relative_to(args.harness_root),
        "output_inside_checkout",
    )
    configure_imports(args.harness_root)
    if args.preflight:
        args.output.mkdir(parents=True, exist_ok=False)
        write_json(
            args.output / "source-prebuild.json",
            bind_checkouts(args.source_root, args.harness_root, args.harness_sha),
        )
        write_json(args.output / "installation-prebuild.json", install_identity(args.harness_root))
        return 0
    if args.child:
        return child(args)
    return parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
