"""Exact-source finite kernel accounting validation; never a benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=30).decode().strip()


def write(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def duplicate_free(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("report_size")
    return json.loads(path.read_bytes(), object_pairs_hook=duplicate_free)


def verify_junit(path: Path, expected: list[str]) -> None:
    cases = list(ET.parse(path).iter("testcase"))
    nodes = [f"{case.attrib['classname']}::{case.attrib['name']}" for case in cases]
    if nodes != expected or len(set(nodes)) != len(nodes) or any(list(case) for case in cases):
        raise ValueError("ordered_controls_not_all_passed")


def admit_result(document: Any, names: list[str]) -> None:
    if not isinstance(document, dict):
        raise ValueError("controller_result")
    for key in ("passed", "worker_launched", "cleanup_complete", "stream_capture_complete"):
        if document.get(key) is not True:
            raise ValueError("controller_incomplete")
    if (
        document.get("schema") != "hol-guard.kernel-resource-host-controller.v1"
        or document.get("original_workload_executed") is not False
        or type(document.get("worker_exit")) is not int
        or document["worker_exit"] != 0
        or document.get("fault") is not None
        or document.get("collection_failure") is not None
        or document.get("stderr_retained_bytes") != 0
    ):
        raise ValueError("controller_failure")
    worker = document.get("worker_report")
    if not isinstance(worker, dict) or worker.get("admitted") is not True or worker.get("passed") is not True:
        raise ValueError("worker_incomplete")
    rows = worker.get("controls")
    if not isinstance(rows, list) or [row.get("name") for row in rows] != names:
        raise ValueError("worker_controls")
    if any(row.get("passed") is not True or row.get("error") is not None for row in rows):
        raise ValueError("worker_control_failure")


def interpreter(path: Path, *, root_owned: bool) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ValueError("interpreter_file")
    if root_owned:
        for member in (resolved, *resolved.parents):
            info = member.stat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError("root_interpreter_ownership")
    return {
        "invoked": str(path),
        "resolved": str(resolved),
        "uid": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "bytes": metadata.st_size,
        "sha256": sha(resolved.read_bytes()),
    }


def snapshot(source: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        path = source / row["path"]
        body = path.read_bytes()
        if len(body) != row["bytes"] or sha(body) != row["sha256"]:
            raise ValueError("source_bytes_changed")
        blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        if blob != row["git_blob"] or git(source, "rev-parse", "HEAD:" + row["path"]) != blob:
            raise ValueError("source_blob_changed")
        result.append(dict(row))
    git(source, "diff", "--exit-code", "HEAD", "--")
    return result


def command(argv: list[str], cwd: Path, output: Path, label: str, timeout: float) -> int:
    # These finite source commands use direct-child timeout semantics. They are
    # not benchmark cleanup evidence. The privileged controller has its own
    # pinned-group timeout/cleanup; an outer timeout cannot certify its cleanup.
    write(output / (label + ".command.json"), {"argv": argv, "timeout_seconds": timeout})
    try:
        with (output / (label + ".stdout")).open("xb") as stdout, (output / (label + ".stderr")).open("xb") as stderr:
            result = subprocess.run(argv, cwd=cwd, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
    except BaseException as error:
        write(output / (label + ".status.json"), {"returncode": None, "failure_kind": type(error).__name__})
        raise
    write(output / (label + ".status.json"), {"returncode": result.returncode, "failure_kind": None})
    return result.returncode


def run(source: Path, driver: Path, output: Path, source_sha: str) -> bool:
    output.mkdir(parents=True, exist_ok=False)
    contract = read_json(driver / "scripts/ci/kernel_resource_contract.json")
    result: dict[str, Any] = {
        "schema": "hol-guard.kernel-resource-hosted-validation.v1",
        "passed": False,
        "finite_controller_offers": 0,
        "original_workload_executed": False,
        "after_verified": False,
        "fault": None,
    }
    before = None
    try:
        if (
            platform.system() != "Linux"
            or platform.machine() != "x86_64"
            or sys.version_info[:2] != (3, 12)
            or sys.prefix == sys.base_prefix
            or len(set(os.getresuid())) != 1
            or os.geteuid() == 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "hashgraph-online/hol-guard"
        ):
            raise ValueError("host_scope")
        if (
            git(source, "rev-parse", "HEAD") != source_sha
            or git(source, "show", "-s", "--format=%P", "HEAD") != contract["base_sha"]
        ):
            raise ValueError("source_parent")
        if (
            git(driver, "rev-parse", "HEAD") != os.environ.get("GITHUB_SHA")
            or git(driver, "show", "-s", "--format=%P", "HEAD") != source_sha
        ):
            raise ValueError("driver_parent")
        changes = git(source, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()
        if changes != sorted(contract["source_delta_paths"]):
            raise ValueError("source_delta")
        driver_changes = git(driver, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()
        if driver_changes != sorted(contract["driver_paths"]):
            raise ValueError("driver_delta")
        before = snapshot(source, contract["source_paths"] + contract["providers"])
        write(output / "before.json", before)
        python = Path(sys.executable).absolute()
        system = Path("/usr/bin/python3")
        write(
            output / "interpreters.json",
            {
                "worker": interpreter(python, root_owned=False),
                "controller": interpreter(system, root_owned=True),
                "worker_version": sys.version,
                "worker_prefix": sys.prefix,
                "worker_base_prefix": sys.base_prefix,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "source_sha": source_sha,
                "source_tree": git(source, "rev-parse", "HEAD^{tree}"),
                "driver_sha": git(driver, "rev-parse", "HEAD"),
                "driver_tree": git(driver, "rev-parse", "HEAD^{tree}"),
            },
        )
        paths = [row["path"] for row in contract["source_paths"]]
        for name, args in (
            ("ruff", ["-m", "ruff", "check", *paths]),
            ("format", ["-m", "ruff", "format", "--check", *paths]),
            ("types", ["-m", "basedpyright", "--pythonpath", str(python), "--outputjson", *paths]),
            (
                "controls",
                [
                    "-m",
                    "pytest",
                    "tests/test_launcher_group_resources.py",
                    "tests/test_launcher_measurement_consumer.py",
                    "tests/test_launcher_offer_ledger.py",
                    "tests/test_qualification_resource_worker.py",
                    "tests/test_qualification_cpu_controller.py",
                    "tests/test_native_slo_lifetime_cpu.py",
                    "tests/test_native_slo_launcher_resources.py",
                    "--deselect=tests/test_native_slo_lifetime_cpu.py::test_real_protected_group_accounts_exited_child_and_grandchild",
                    "-q",
                    "--junitxml=" + str(output / "controls.xml"),
                ],
            ),
        ):
            if command([str(python), *args], source, output, name, 180) != 0:
                raise ValueError("source_control_failed")
        if read_json(output / "types.stdout")["summary"]["errorCount"] != 0:
            raise ValueError("types_failed")
        verify_junit(output / "controls.xml", contract["ordered_nodes"])
        # No product install, native build or original producer occurs here.
        snapshot(source, contract["source_paths"] + contract["providers"])
        result["finite_controller_offers"] = 1
        argv = [
            "sudo",
            "-n",
            str(system),
            "-I",
            "-S",
            str(source / "scripts/ci/qualification_cpu_controller.py"),
            "--python",
            str(python),
            "--uid",
            str(os.getuid()),
            "--gid",
            str(os.getgid()),
            "--control-kind",
            "resources",
        ]
        code = command(argv, source, output, "finite-controller", 45)
        document = read_json(output / "finite-controller.stdout")
        write(output / "finite-controller-parsed.json", document)
        if code != 0 or (output / "finite-controller.stderr").stat().st_size != 0:
            raise ValueError("finite_controller_failed")
        admit_result(document, contract["control_names"])
        result["passed"] = True
    except BaseException as error:
        result["fault"] = type(error).__name__
        result["passed"] = False
    finally:
        try:
            after = snapshot(source, contract["source_paths"] + contract["providers"])
            write(output / "after.json", after)
            result["after_verified"] = before is not None and after == before
            result["passed"] = result["passed"] and result["after_verified"]
        except BaseException:
            result["passed"] = False
        write(output / "RESULT.json", result)
    return result["passed"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    return 0 if run(args.source.resolve(), args.driver.resolve(), args.output.resolve(), args.source_sha) else 1


if __name__ == "__main__":
    raise SystemExit(main())
