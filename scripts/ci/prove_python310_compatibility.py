"""Closed native Python 3.10 compatibility evidence for a fixed test-only tree."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

BASE = "bc0479bcab1cbc925421c9ebc7a7b926bccd131d"
BASE_TREE = "28ad4a5c3f0f3f5860f81a19c150b43aca7b6ba6"
PARENT = "f62e3cb7008eaf98ff0c2e2f9f9635af6b4448ee"
HTTP = "tests/test_guard_bounded_http_exception_compatibility.py"
LIFECYCLE = "tests/test_guard_daemon_lifecycle_transition.py"
LIFECYCLE_CASE = "test_failed_start_retains_ownership_when_serve_join_returns_a_live_thread"
PINS = {
    HTTP: "a0d8a20f4e17694feccacaa8a2cec3af0c8901ac",
    LIFECYCLE: "05db6d62a4cf734c77370daa148cb90fc26149d7",
    "src/codex_plugin_scanner/guard/daemon/bounded_http.py": "96561ddfaa5b0edb50b3a21ecf3ee1a9eeca68b8",
}
CHANGED = {
    HTTP, LIFECYCLE, ".github/workflows/ci.yml",
    "scripts/ci/prove_python310_compatibility.py",
}
PHASES = ("setup", "call", "teardown")
_COLLECTED: list[dict[str, Any]] = []
_REPORTS: list[dict[str, Any]] = []
_CALL_ERRORS: dict[tuple[str, str], dict[str, object]] = {}
_DESELECTED = 0
_COLLECTION_ERRORS = 0
_INTERNAL_ERRORS = 0


def expected_signatures() -> set[str]:
    expected = []
    errors = [
        ("TimeoutError", None, 1, 0, False),
        ("BrokenPipeError", None, 0, 1, False),
        ("ConnectionAbortedError", None, 0, 1, False),
        ("ConnectionResetError", None, 0, 1, False),
        ("_PlainOSError", errno.EPIPE, 0, 1, False),
        ("_PlainOSError", errno.ECONNABORTED, 0, 1, False),
        ("_PlainOSError", errno.ECONNRESET, 0, 1, False),
        ("_PlainOSError", errno.ETIMEDOUT, 0, 1, False),
        ("ValueError", None, 0, 0, True),
    ]
    for context in ("native", "python310"):
        for kind, number, timeouts, aborts, parent in errors:
            expected.append(["active", context, kind, number, timeouts, aborts, parent])
        expected.extend([["missing", context], ["parent", context]])
    expected.extend([["lifecycle", True], ["lifecycle", False]])
    return {json.dumps(value, separators=(",", ":")) for value in expected}


def pytest_collection_finish(session: Any) -> None:
    for item in session.items:
        params = item.callspec.params
        name = item.originalname
        if name == "test_active_request_error_keeps_metrics_and_parent_fallback":
            error = params["error"]
            signature = [
                "active", params["handler_context"], type(error).__name__,
                getattr(error, "errno", None), params["timeouts"], params["aborts"], params["uses_parent"],
            ]
        elif name == "test_missing_active_error_still_reaches_parent":
            signature = ["missing", params["handler_context"]]
        elif name == "test_parent_handler_failure_is_not_suppressed":
            signature = ["parent", params["handler_context"]]
        elif name == LIFECYCLE_CASE:
            signature = ["lifecycle", params["record_notes"]]
        else:
            signature = ["unexpected"]
        _COLLECTED.append({"node": item.nodeid, "signature": signature})


def pytest_deselected(items: Any) -> None:
    global _DESELECTED
    _DESELECTED += len(items)


def pytest_collectreport(report: Any) -> None:
    global _COLLECTION_ERRORS
    _COLLECTION_ERRORS += int(report.failed)


def pytest_internalerror(excrepr: Any, excinfo: Any) -> None:
    global _INTERNAL_ERRORS
    del excrepr, excinfo
    _INTERNAL_ERRORS += 1


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any):
    yield
    if call.excinfo is None:
        return
    error = call.excinfo.value
    terminal = error.__traceback__
    bounded_terminal = False
    for _ in range(64):
        if terminal is None:
            break
        if terminal.tb_next is None:
            bounded_terminal = True
            break
        terminal = terminal.tb_next
    exact_attribute = type(error) is AttributeError
    target = getattr(error, "obj", None) if exact_attribute else None
    source_frame = bool(
        bounded_terminal and terminal is not None
        and Path(terminal.tb_frame.f_code.co_filename).resolve()
        == Path("src/codex_plugin_scanner/guard/daemon/bounded_http.py").resolve()
        and terminal.tb_frame.f_code.co_name == "handle_error"
        and terminal.tb_frame.f_code.co_firstlineno == 341 and terminal.tb_lineno == 342
    )
    _CALL_ERRORS[(item.nodeid, call.when)] = {
        "exceptionKind": "attribute" if exact_attribute else "assertion"
        if type(error) is AssertionError else "runtime" if type(error) is RuntimeError else "other",
        "expectedAttribute": exact_attribute and getattr(error, "name", None) == "exception",
        "sysModuleObject": type(target) is type(sys) and getattr(target, "__name__", None) == "sys",
        "sourceFrame": source_frame,
    }


def pytest_runtest_logreport(report: Any) -> None:
    observed = _CALL_ERRORS.get((report.nodeid, report.when), {})
    missing_api = (
        observed.get("exceptionKind") == "attribute"
        and observed.get("expectedAttribute") is True
        and observed.get("sysModuleObject") is True
        and observed.get("sourceFrame") is True
    )
    _REPORTS.append({
        "node": report.nodeid, "when": report.when, "outcome": report.outcome,
        "failureCategory": "missing_sys_exception" if report.failed and missing_api
        else "unexpected_failure" if report.failed else None,
        **({"exceptionObservation": observed} if report.failed else {}),
    })


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:
    del session
    phase = os.environ.get("GUARD_PY310_RECEIPT_PHASE")
    destination = os.environ.get("GUARD_PY310_RECEIPT_DIR")
    if phase not in {"collect", "run"} or not destination:
        return
    write(Path(destination) / (phase + "-plugin.json"), {
        "exit": int(exitstatus), "collected": _COLLECTED, "reports": _REPORTS,
        "deselected": _DESELECTED, "collectionErrors": _COLLECTION_ERRORS,
        "internalErrors": _INTERNAL_ERRORS,
    })


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def inventory(ref: str) -> dict[str, tuple[str, str]]:
    result = {}
    for row in git("ls-tree", "-r", "-z", ref).split(b"\0"):
        if not row:
            continue
        header, path = row.split(b"\t", 1)
        mode, kind, digest = header.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise RuntimeError("unsupported_source_entry")
        result[path.decode()] = (mode, digest)
    return result


def verify_source() -> dict[str, object]:
    commit = os.environ["EXPECTED_DIAGNOSTIC_SHA"]
    tree = os.environ["EXPECTED_DIAGNOSTIC_TREE"]
    if not re.fullmatch("[0-9a-f]{40}", commit) or not re.fullmatch("[0-9a-f]{40}", tree):
        raise RuntimeError("source_identity")
    if commit != os.environ["GITHUB_SHA"] or git("rev-parse", "HEAD").decode().strip() != commit:
        raise RuntimeError("source_identity")
    if git("rev-parse", "HEAD^{tree}").decode().strip() != tree:
        raise RuntimeError("source_identity")
    if git("show", "-s", "--format=%P", "HEAD").decode().strip() != PARENT:
        raise RuntimeError("source_parent")
    if git("rev-parse", BASE + "^{tree}").decode().strip() != BASE_TREE:
        raise RuntimeError("source_base")
    original, current = inventory(BASE), inventory("HEAD")
    changed = {path for path in set(original) | set(current) if original.get(path) != current.get(path)}
    if changed != CHANGED or len(original) != 4087 or len(current) != 4089:
        raise RuntimeError("source_delta")
    if any(current.get(path) != ("100644", digest) for path, digest in PINS.items()):
        raise RuntimeError("source_pin")
    mismatches = 0
    for path, (mode, digest) in current.items():
        file = Path(path)
        try:
            file_mode = file.lstat().st_mode
            if mode == "120000":
                valid = stat.S_ISLNK(file_mode)
                data = os.readlink(file).encode() if valid else b""
            else:
                valid = stat.S_ISREG(file_mode) and bool(file_mode & 0o111) == (mode == "100755")
                data = file.read_bytes() if valid else b""
            mismatches += int(not valid or blob(data) != digest)
        except OSError:
            mismatches += 1
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    if mismatches or any(untracked):
        raise RuntimeError("source_contents")
    return {
        "commit": commit, "tree": tree, "base": BASE, "baseTree": BASE_TREE,
        "originalFiles": len(original), "checkedFiles": len(current),
        "mismatches": 0, "unexpectedUntracked": 0, "pins": PINS,
    }


def execute(command: list[str], log: Path, timeout: int, env: dict[str, str]) -> dict[str, object]:
    start = time.monotonic()
    timed_out = False
    with log.open("wb") as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = child.wait(timeout=10)
    digest = hashlib.sha256()
    with log.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "exit": code, "timedOut": timed_out, "seconds": round(time.monotonic() - start, 3),
        "logBytes": log.stat().st_size, "logSha256": digest.hexdigest(),
    }


def validate_collection(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    records = receipt["collected"]
    signatures = [json.dumps(value["signature"], separators=(",", ":")) for value in records]
    nodes = [value["node"] for value in records]
    allowed = (HTTP + "::", LIFECYCLE + "::" + LIFECYCLE_CASE + "[")
    if (len(records) != 24 or len(set(nodes)) != 24 or len(set(signatures)) != 24
            or set(signatures) != expected_signatures()
            or any(not node.startswith(allowed) for node in nodes)
            or receipt["deselected"] or receipt["collectionErrors"] or receipt["internalErrors"]):
        raise RuntimeError("selection_incomplete")
    return sorted(records, key=lambda value: value["node"])


def prove() -> int:
    destination = Path(os.environ["GUARD_PY310_RECEIPT_DIR"])
    destination.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "schema": "guard.native-python310-compatibility-baseline.v1",
        "complete": False, "expectedRedObserved": False, "tier": "E2",
        "pythonVersion": ".".join(map(str, sys.version_info[:3])),
        "nativePython310": sys.version_info[:2] == (3, 10),
        "nativeSysExceptionAvailable": hasattr(sys, "exception"),
        "nativeAddNoteAvailable": hasattr(RuntimeError(), "add_note"),
        "productChanged": False,
    }
    exit_code = 2
    try:
        if sys.version_info[:2] != (3, 10) or hasattr(sys, "exception"):
            raise RuntimeError("unexpected_interpreter")
        result["sourceBefore"] = verify_source()
        selection = [HTTP, LIFECYCLE + "::" + LIFECYCLE_CASE]
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short",
                   "-p", "scripts.ci.prove_python310_compatibility"]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GUARD_PY310_RECEIPT_PHASE="collect")
        result["collectionProcess"] = execute(command + ["--collect-only", *selection],
                                               destination / "collect.log", 120, env)
        result["sourceAfterCollection"] = verify_source()
        collected = json.loads((destination / "collect-plugin.json").read_text())
        nodes = validate_collection(collected)
        if (result["collectionProcess"]["exit"] != 0
                or result["collectionProcess"]["timedOut"] or collected["exit"] != 0):
            raise RuntimeError("collection_process")
        result["selection"] = nodes
        env["GUARD_PY310_RECEIPT_PHASE"] = "run"
        result["testProcess"] = execute(command + ["--junitxml=" + str(destination / "results.xml"), *selection],
                                        destination / "run.log", 180, env)
        result["sourceAfter"] = verify_source()
        observed = json.loads((destination / "run-plugin.json").read_text())
        if validate_collection(observed) != nodes:
            raise RuntimeError("selection_changed")
        reports = observed["reports"]
        result["phaseReports"] = reports
        result["observedRunnerExit"] = observed["exit"]
        result["observedCallOutcomes"] = {
            outcome: sum(row["when"] == "call" and row["outcome"] == outcome for row in reports)
            for outcome in ("passed", "failed", "skipped")
        }
        result["cases"] = [
            {**entry, "observedPhases": [row for row in reports if row["node"] == entry["node"]]}
            for entry in nodes
        ]
        junit = ET.parse(destination / "results.xml").getroot()
        suites = [junit] if junit.tag == "testsuite" else list(junit.iter("testsuite"))
        totals = {key: sum(int(suite.attrib.get(key, 0)) for suite in suites)
                  for key in ("tests", "failures", "errors", "skipped")}
        result["junit"] = totals
        if len(reports) != 72 or {row["node"] for row in reports} != {row["node"] for row in nodes}:
            raise RuntimeError("phase_incomplete")
        cases = []
        for entry in nodes:
            phases = [row for row in reports if row["node"] == entry["node"]]
            if len(phases) != 3 or {row["when"] for row in phases} != set(PHASES):
                raise RuntimeError("phase_incomplete")
            phase_map = {row["when"]: row for row in phases}
            http = entry["node"].startswith(HTTP + "::")
            if any(phase_map[when]["outcome"] != "passed" for when in ("setup", "teardown")):
                raise RuntimeError("fixture_failure")
            call = phase_map["call"]
            if http:
                if call["outcome"] != "failed" or call["failureCategory"] != "missing_sys_exception":
                    raise RuntimeError("unexpected_call_result")
            elif call["outcome"] != "passed":
                raise RuntimeError("lifecycle_control_failed")
            cases.append({**entry, "outcome": call["outcome"], "failureCategory": call["failureCategory"]})
        if totals != {"tests": 24, "failures": 22, "errors": 0, "skipped": 0}:
            raise RuntimeError("junit_mismatch")
        result["cases"] = cases
        result["junit"] = totals
        result["phaseReports"] = reports
        result["expectedRedObserved"] = (
            observed["exit"] == 1 and result["testProcess"]["exit"] == 1
            and not result["testProcess"]["timedOut"]
        )
        result["complete"] = result["expectedRedObserved"]
        exit_code = 1 if result["complete"] else 2
    except Exception as error:
        known = {
            "unsupported_source_entry", "source_identity", "source_parent", "source_base",
            "source_delta", "source_pin", "source_contents", "selection_incomplete",
            "unexpected_interpreter", "collection_process", "selection_changed",
            "phase_incomplete", "fixture_failure", "unexpected_call_result",
            "lifecycle_control_failed", "junit_mismatch",
        }
        result["failureCategory"] = str(error) if str(error) in known else "setup_or_receipt_incomplete"
    finally:
        try:
            result["sourceFinal"] = verify_source()
        except Exception:
            result["complete"] = False
            result["expectedRedObserved"] = False
            result["finalSourceValid"] = False
            exit_code = 2
        write(destination / "summary.json", result)
        print("PYTHON310_COMPATIBILITY_BASELINE " + json.dumps(result, separators=(",", ":")), flush=True)
    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raise SystemExit(prove())
