"""Isolated Windows storage controls around an unchanged installed wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import site
import sqlite3
import subprocess
import sys
import tempfile
import threading
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, cast

SOURCE_SHA = "ed7313dff240292a482c53410a2492f80ba8a220"
SOURCE_TREE = "cfb0c3707db387518e4051ba1b0efa236515f2ef"
BUILD_SHA = "1e966652e7e7fc9a983d76680b3b1e889af3dc0f"
ARTIFACT_ID = 10595777802
ARTIFACT_RUN = 35481095629
ARTIFACT_SHA = "2321b633013596c1f871a2c7cd9daab3bf1700df1dfbca032ba0fe4e807bfa31"
MEMBERS = {
    "native-dist/hol_guard-3.0.1-py3-none-win_amd64.whl": (
        8418623,
        "ab7c7e5f6145f43d26a8a90e8f128ea86fe03b00dd6f0aefb12120d3c89f30a4",
    ),
    "native-default-auto.json": (2705, "aa483ea998d9f7f5eb30150dd9c20068bc8541a8797244ef852ee4f46352c9f2"),
    "native-installed-identity.json": (
        3153,
        "d34a4bc937e5e08e17c8e24c50fa101144b70bdb16e910f9ce0132894238df7f",
    ),
    "native-installed-control-lock.json": (
        562,
        "1ae57f60e5e9ee0f380ac83036c5ec6fdce1ba85e7d2fd4bd1d461aee7ff36c7",
    ),
}
DRIVER_FILES = (
    ".github/workflows/windows-storage-diagnostics.yml",
    "scripts/ci/windows_storage_diagnostics.py",
    "scripts/ci/windows_storage_failure_capture.py",
    "tests/test_windows_storage_diagnostics.py",
    "ci/native_runtime/test_guard_native_runtime_windows_resident.py",
    "tests/test_windows_resident_review_failure.py",
)
WRITER_TIMEOUT_SECONDS = 0.05
PACKAGE_FILES = {
    "guard/store_connection_schema.py": "fe10c17052f674724b1a757a33ba799cce778b28f4ca7411edd4b4311d6425f7",
    "guard/daemon/runtime_hook_evidence_writer.py": "663f4e3902b74cd8eada35743fe5dfeb9bed16d95ebd79e61d5fae3e4e26c0fe",
    "guard/sqlite_tuning.py": "8be8df00c0d73c05a5e03e16a95ff926410be4752346f0237ff10a2d8637a2a7",
    "guard/native_command_control_windows_lock.py": "d0ccbb2f115ba3923bf174c6ea60c9058d35aaecbc4c2188f9aff0d0be3167e7",
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding(candidate: Path, artifact: Path, phase: str) -> dict[str, object]:
    driver = Path(__file__).resolve().parents[2]
    _require(_git(candidate, "rev-parse", "HEAD") == SOURCE_SHA, "candidate_commit_mismatch")
    _require(_git(candidate, "rev-parse", "HEAD^{tree}") == SOURCE_TREE, "candidate_tree_mismatch")
    _require(not _git(candidate, "status", "--porcelain", "--untracked-files=all"), "candidate_checkout_dirty")
    driver_sha = _git(driver, "rev-parse", "HEAD")
    _require(driver_sha == os.environ.get("VALIDATION_WORKFLOW_SHA"), "driver_commit_mismatch")
    _require(not _git(driver, "status", "--porcelain", "--untracked-files=all"), "driver_checkout_dirty")
    member_hashes = {}
    for name, (size, digest) in MEMBERS.items():
        path = artifact / name
        _require(path.is_file() and path.stat().st_size == size, "artifact_member_size_mismatch")
        _require(_digest(path) == digest, "artifact_member_digest_mismatch")
        member_hashes[name] = {"bytes": size, "sha256": digest}
    return {
        "schema": "hol-guard.windows-storage-checkouts.v1",
        "phase": phase,
        "candidate_sha": SOURCE_SHA,
        "candidate_tree": SOURCE_TREE,
        "installed_build_sha": BUILD_SHA,
        "driver_sha": driver_sha,
        "driver_tree": _git(driver, "rev-parse", "HEAD^{tree}"),
        "driver_files": {name: _digest(driver / name) for name in DRIVER_FILES},
        "run_id": os.environ.get("VALIDATION_RUN_ID"),
        "run_attempt": os.environ.get("VALIDATION_RUN_ATTEMPT"),
        "artifact_id": ARTIFACT_ID,
        "artifact_run_id": ARTIFACT_RUN,
        "artifact_zip_sha256_prior_verified_download": ARTIFACT_SHA,
        "artifact_members_verified_in_this_run": member_hashes,
        "product_source_changed": False,
        "runtime_deadline_changed": False,
        "runtime_retries_changed": False,
        "first_review_scope": "driver_fixture_with_original_ci_force_mode_on_installed_package_and_runtime",
        "first_review_installed_qualification": False,
        "headline_qualification": False,
    }


def _installed(candidate: Path) -> dict[str, object]:
    import codex_plugin_scanner
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    package = Path(codex_plugin_scanner.__file__).resolve()
    _require(not package.is_relative_to(candidate / "src"), "source_package_imported")
    _require(any(package.is_relative_to(Path(path).resolve()) for path in site.getsitepackages()), "not_installed")
    status = native_runtime_status()
    _require(status.available and status.compatible and status.identity is not None, "installed_runtime_unavailable")
    _require(status.capabilities is not None and status.capabilities.build_sha == BUILD_SHA, "installed_build_mismatch")
    _require(
        status.identity is not None
        and status.identity.sha256 == "8841a5b8bf13ba59ad7bfee619d53c7565d4419fa8f87859823e49c112c0d289",
        "installed_runtime_digest_mismatch",
    )
    for name, expected in PACKAGE_FILES.items():
        _require(_digest(package.parent / name) == expected, "installed_python_module_digest_mismatch")
    return {
        "build_sha": BUILD_SHA,
        "runtime_sha256": status.identity.sha256 if status.identity is not None else None,
        "python_files": PACKAGE_FILES,
        "verified_site_packages_import": True,
    }


def _lease(store: Any, kind: str) -> AbstractContextManager[object]:
    if kind == "connection":
        return store._connect()
    return store._hold_storage_gate(exclusive=kind == "exclusive")


def _gate_case(store: Any, label: str, holder_kind: str, waiter_kind: str) -> dict[str, object]:
    from windows_storage_failure_capture import failure_origin, timeout_origins

    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override

    entered, release = threading.Event(), threading.Event()
    holder_state: dict[str, object] = {"entered": False, "released": False, "failed": False}

    def hold() -> None:
        try:
            with _lease(store, holder_kind) as connection:
                if holder_kind == "connection":
                    cast(sqlite3.Connection, connection).execute("select 1").fetchone()
                holder_state["entered"] = True
                entered.set()
                _require(release.wait(timeout=5), "diagnostic_holder_release_timeout")
            holder_state["released"] = True
        except BaseException:
            holder_state["failed"] = True
            entered.set()

    holder = threading.Thread(target=hold, name="storage-diagnostic-holder", daemon=True)
    holder.start()
    acquired = False
    origin: str | None = None
    timeout_observed = False
    unexpected_failure = False
    try:
        _require(entered.wait(timeout=5) and holder_state["entered"] is True, "diagnostic_holder_not_ready")
        with sqlite_connect_timeout_override(WRITER_TIMEOUT_SECONDS):
            try:
                with _lease(store, waiter_kind) as connection:
                    if waiter_kind == "connection":
                        cast(sqlite3.Connection, connection).execute("select 1").fetchone()
                    acquired = True
            except BaseException as error:
                timeout_observed = type(error) is TimeoutError
                unexpected_failure = not timeout_observed
                origin = failure_origin(error, timeout_origins())
    finally:
        release.set()
        holder.join(timeout=5)
    return {
        "case": label,
        "holder": holder_kind,
        "waiter": waiter_kind,
        "waiter_acquired_while_holder_active": acquired,
        "waiter_timeout_observed": timeout_observed,
        "waiter_failure_origin": origin,
        "waiter_unexpected_failure": unexpected_failure,
        "holder_released": holder_state["released"],
        "holder_failed": holder_state["failed"],
        "holder_thread_stopped": not holder.is_alive(),
        "expected_shared_admission": holder_kind == waiter_kind == "connection",
    }


def gate_controls(candidate: Path) -> dict[str, object]:
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
    from codex_plugin_scanner.guard.store import GuardStore

    _require(os.name == "nt", "windows_diagnostic_requires_windows")
    installed = _installed(candidate)
    cases = []
    with tempfile.TemporaryDirectory(prefix="hg-storage-") as temporary:
        store = GuardStore(Path(temporary) / "guard", prime_policy_integrity=False)
        for label, holder, waiter in (
            ("shared_connections", "connection", "connection"),
            ("shared_blocks_recovery", "shared", "exclusive"),
            ("recovery_blocks_shared", "exclusive", "shared"),
            ("recovery_blocks_recovery", "exclusive", "exclusive"),
        ):
            cases.append(_gate_case(store, label, holder, waiter))
        with sqlite_connect_timeout_override(WRITER_TIMEOUT_SECONDS), store._connect() as connection:
            released_connection_usable = connection.execute("select 1").fetchone()[0] == 1
    complete = all(
        case["holder_released"]
        and case["holder_thread_stopped"]
        and not case["holder_failed"]
        and not case["waiter_unexpected_failure"]
        for case in cases
    )
    return {
        "schema": "hol-guard.windows-storage-gate-diagnostic.v1",
        "scope": "two_sqlite_connections_in_distinct_threads_and_store_gate_recovery_controls",
        "installed_artifact": installed,
        "cases": cases,
        "writer_timeout_seconds": WRITER_TIMEOUT_SECONDS,
        "diagnostic_complete": complete and released_connection_usable,
        "gate_contract_passed": complete
        and all(case["waiter_acquired_while_holder_active"] == case["expected_shared_admission"] for case in cases),
        "released_connection_usable": released_connection_usable,
        "timing_qualification": False,
        "headline_qualification": False,
    }


def corpus(candidate: Path, output: Path) -> int:
    from windows_storage_failure_capture import FailureOriginCapture

    installed = _installed(candidate)
    # Import only the exact candidate's existing CI driver; product imports
    # resolve to the installed wheel, never candidate/src.
    sys.path.append(str(candidate))
    probe = importlib.import_module("ci.native_runtime.probe_native_default_auto")
    if not isinstance(probe.__file__, str):
        raise RuntimeError("probe_driver_file_missing")
    probe_file = Path(probe.__file__)
    _require(probe_file.resolve().is_relative_to(candidate), "probe_driver_mismatch")
    capture = FailureOriginCapture()
    original_exit_code = 1
    original_failed = False
    try:
        with capture:
            original_exit_code = probe.main(json_path=output / "default-auto.json")
        return original_exit_code
    except BaseException:
        original_failed = True
        return 1
    finally:
        report = capture.snapshot()
        report["original_probe_exit_code"] = original_exit_code
        report["original_probe_failed"] = original_failed
        report["installed_artifact"] = installed
        report["unchanged_probe_sha256"] = _digest(probe_file)
        _write(output / "failure-origins.json", report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("binding", "gate", "corpus"))
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("before", "after"), default="before")
    args = parser.parse_args()
    candidate, artifact, output = args.candidate.resolve(), args.artifact.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.mode == "binding":
        _write(output / f"checkouts-{args.phase}.json", binding(candidate, artifact, args.phase))
        return 0
    if args.mode == "gate":
        _write(output / "storage-gate.json", gate_controls(candidate))
        return 0
    return corpus(candidate, output)


if __name__ == "__main__":
    raise SystemExit(main())
