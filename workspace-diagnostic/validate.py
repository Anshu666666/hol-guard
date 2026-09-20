"""Immutable source/build/control admission before one bounded workspace diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SOURCE_SHA = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
SOURCE_TREE = "c10faac2d156cac06f9f803d63f50d15e3ca82bf"
MAX_LOG_BYTES = 16 * 1024 * 1024
COMMANDS: list[dict[str, Any]] = []


def digest(path: Path, maximum: int = MAX_LOG_BYTES) -> dict[str, Any]:
    size, hashed = 0, hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > maximum:
                raise RuntimeError("artifact_read_bound")
            hashed.update(block)
    return {"bytes": size, "sha256": hashed.hexdigest()}


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def git(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(path), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    if len(completed.stdout) > 512 * 1024 or len(completed.stderr) > 512 * 1024:
        raise RuntimeError("git_output_bound")
    return completed.stdout.strip()


def source_state(path: Path, expected_sha: str, expected_tree: str | None = None) -> dict[str, Any]:
    state = {
        "head": git(path, "rev-parse", "HEAD"),
        "tree": git(path, "rev-parse", "HEAD^{tree}"),
        "tracked_status": git(path, "status", "--porcelain", "--untracked-files=no"),
    }
    if (
        state["head"] != expected_sha
        or state["tracked_status"]
        or (expected_tree is not None and state["tree"] != expected_tree)
    ):
        raise RuntimeError("immutable_source_binding")
    return state


def verify_files(root: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    verified = []
    for entry in entries:
        relative = entry["path"]
        path = root / relative
        if path.resolve(strict=True) != path or not path.is_file():
            raise RuntimeError("source_file_type")
        observed = digest(path, 2 * 1024 * 1024)
        raw = path.read_bytes()
        observed["git_blob"] = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if any(observed[key] != entry[key] for key in ("bytes", "sha256", "git_blob")):
            raise RuntimeError("source_file_hash")
        verified.append({"path": relative, **observed})
    return verified


def kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def run(
    name: str,
    argv: list[str],
    *,
    cwd: Path,
    output: Path,
    environment: dict[str, str] | None = None,
    timeout: float = 360,
    require_success: bool = True,
) -> int:
    if any(row["name"] == name for row in COMMANDS):
        raise RuntimeError("duplicate_command")
    out_path, err_path = output / "commands" / f"{name}.stdout", output / "commands" / f"{name}.stderr"
    started, timed_out, cleanup_confirmed = time.monotonic(), False, True
    process = None
    code = None
    try:
        with out_path.open("wb") as stdout, err_path.open("wb") as stderr:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_group(process.pid)
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup_confirmed = False
    finally:
        record: dict[str, Any] = {
            "name": name,
            "returncode": code,
            "timed_out": timed_out,
            "direct_child_exited": process is not None and process.poll() is not None,
            "timeout_cleanup_confirmed": cleanup_confirmed and not timed_out,
            "elapsed_seconds": time.monotonic() - started,
            "scope": "preparation_or_diagnostic_command_not_headline_workload_timing",
        }
        for kind, path in (("stdout", out_path), ("stderr", err_path)):
            try:
                record[kind] = digest(path)
            except Exception:
                record[kind] = {"available_within_bound": False}
        COMMANDS.append(record)
        write(output / "commands.json", COMMANDS)
    if timed_out or code is None or (require_success and code != 0):
        raise RuntimeError("command_failed:" + name)
    if any(record[kind].get("available_within_bound") is False for kind in ("stdout", "stderr")):
        raise RuntimeError("command_log_bound:" + name)
    return code


def python_controls(python: Path, driver: Path, source: Path, output: Path) -> None:
    expected_record = json.loads((driver / "EXPECTED-CONTROLS.json").read_text(encoding="utf-8"))
    expected = expected_record["expected_nodes"]
    if expected_record["expected_count"] != 29 or len(expected) != 29 or len(set(expected)) != 29:
        raise RuntimeError("control_manifest_roster")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(driver), str(source)))
    shared = [
        str(python),
        "-m",
        "pytest",
        "-c",
        str(driver / "pytest.ini"),
        "--noconftest",
        "--import-mode=importlib",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "tests/test_capture.py",
        "tests/test_hooks.py",
        "tests/test_forwarding.py",
        "tests/test_workload.py",
    ]
    run("controls-collect", [*shared, "--collect-only", "-q"], cwd=driver, output=output, environment=environment)
    collected = [
        line.strip()
        for line in (output / "commands/controls-collect.stdout").read_text(encoding="utf-8").splitlines()
        if line.startswith("tests/") and "::" in line
    ]
    if collected != expected:
        raise RuntimeError("control_collection_identity")
    run(
        "controls-run",
        [*shared, "-q", "--tb=short", "-o", "junit_family=xunit2", "--junitxml", str(output / "controls.xml")],
        cwd=driver,
        output=output,
        environment=environment,
    )
    junit = ET.parse(output / "controls.xml").getroot()
    cases = list(junit.iter("testcase"))
    actual = [case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"] for case in cases]
    if actual != expected or any(list(case.iter(kind)) for case in cases for kind in ("failure", "error", "skipped")):
        raise RuntimeError("control_execution_identity_or_outcome")
    write(
        output / "controls-result.json",
        {
            "collected_nodes": collected,
            "executed_nodes": actual,
            "passed": len(cases),
            "skipped": 0,
            "failed": 0,
            "exact_identity_join": True,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--driver-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source, driver_root = args.source.resolve(strict=True), args.driver.resolve(strict=True)
    driver = driver_root / "workspace-diagnostic"
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "commands").mkdir(mode=0o700)
    manifest_path = driver / "MANIFEST.json"
    if digest(manifest_path)["sha256"] != args.manifest_sha256:
        raise RuntimeError("driver_manifest_hash")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_before = source_state(source, SOURCE_SHA, SOURCE_TREE)
    driver_before = source_state(driver_root, args.driver_sha)
    if manifest["source"] != {"sha": SOURCE_SHA, "tree": SOURCE_TREE}:
        raise RuntimeError("manifest_source")
    files_before = verify_files(driver_root, manifest["driver_files"])
    source_files_before = verify_files(source, manifest["source_files"])
    write(
        output / "binding-before.json",
        {
            "source": source_before,
            "driver": driver_before,
            "driver_files": files_before,
            "source_files": source_files_before,
            "untracked_owned_build_outputs": "not part of tracked-source immutability claim",
        },
    )
    failed = None
    workload_code = None
    after_matches = False
    try:
        run("rust-version", ["rustc", "+1.88.0", "--version"], cwd=source, output=output)
        version = (output / "commands/rust-version.stdout").read_text(encoding="utf-8").strip()
        if not version.startswith("rustc 1.88.0 "):
            raise RuntimeError("rust_version")
        run("python-version", [sys.executable, "--version"], cwd=driver, output=output)
        if (output / "commands/python-version.stdout").read_text(encoding="utf-8").strip() != "Python 3.12.14":
            raise RuntimeError("python_version")
        run(
            "prepare-retained-wheel",
            [sys.executable, str(driver / "build.py"), "--source", str(source), "--output", str(output)],
            cwd=driver,
            output=output,
            timeout=1200,
        )
        build = json.loads((output / "build-result.json").read_text(encoding="utf-8"))
        python = source / ".venv/bin/python"
        if build["python_relative"] != ".venv/bin/python" or build["metadata"]["source_sha"] != SOURCE_SHA:
            raise RuntimeError("build_identity")
        paths = [str(driver_root / item["path"]) for item in manifest["driver_files"] if item["path"].endswith(".py")]
        run(
            "ruff",
            [str(python), "-m", "ruff", "check", "--no-cache", "--config", str(source / "pyproject.toml"), *paths],
            cwd=driver,
            output=output,
        )
        run(
            "format-check",
            [
                str(python),
                "-m",
                "ruff",
                "format",
                "--check",
                "--no-cache",
                "--config",
                str(source / "pyproject.toml"),
                *paths,
            ],
            cwd=driver,
            output=output,
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join((str(driver), str(source)))
        run(
            "types",
            [
                str(source / ".venv/bin/basedpyright"),
                "--pythonpath",
                str(python),
                "--pythonversion",
                "3.12",
                *paths,
            ],
            cwd=driver,
            output=output,
            environment=environment,
        )
        python_controls(python, driver, source, output)
        # No extra runtime prewarming or readiness probe. The original sweep
        # performs its own installed/default-auto identity and service setup.
        workload_code = run(
            "original-three-cells",
            [str(python), "-I", str(driver / "run_workload.py"), "--source", str(source), "--output", str(output)],
            cwd=driver,
            output=output,
            timeout=180,
            require_success=False,
        )
        result = json.loads((output / "diagnostic-result.json").read_text(encoding="utf-8"))
        if result["diagnostic_admitted"] is not True or result["original_function_calls"] != 1:
            raise RuntimeError("diagnostic_collection_incomplete")
        if workload_code != 0 or result["original_selected_cells_passed"] is not True:
            raise RuntimeError("original_selected_lifecycle_failure")
    except BaseException as error:
        failed = (
            str(error)
            if isinstance(error, RuntimeError)
            and str(error).startswith(
                (
                    "command_failed:",
                    "command_log_bound:",
                    "control_",
                    "diagnostic_",
                    "original_",
                    "build_",
                    "rust_",
                    "python_",
                )
            )
            else type(error).__name__
        )
    finally:
        try:
            source_after = source_state(source, SOURCE_SHA, SOURCE_TREE)
            driver_after = source_state(driver_root, args.driver_sha)
            files_after = verify_files(driver_root, manifest["driver_files"])
            source_files_after = verify_files(source, manifest["source_files"])
            after_matches = (
                source_after == source_before
                and driver_after == driver_before
                and files_after == files_before
                and source_files_after == source_files_before
            )
            write(
                output / "binding-after.json",
                {
                    "source": source_after,
                    "driver": driver_after,
                    "driver_files": files_after,
                    "source_files": source_files_after,
                },
            )
        except Exception:
            after_matches = False
        write(
            output / "validation-result.json",
            {
                "schema": "hol-guard.workspace-cause-validation.v1",
                "source_sha": SOURCE_SHA,
                "source_tree": SOURCE_TREE,
                "driver_sha": args.driver_sha,
                "source_and_driver_preserved": after_matches,
                "failure": failed,
                "original_selected_command_exit": workload_code,
                "commands": COMMANDS,
                "passed": failed is None and after_matches,
                "original_readiness_deadline_ms": 400,
                "original_full_matrix_passed": False,
                "headline_timing_eligible": False,
                "qualification_complete": False,
                "workload_retries": 0,
            },
        )
    return 0 if failed is None and after_matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
