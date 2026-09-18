"""Observe the original storage-liveness failure after its measured interval."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

BASE = "35c677ac2ed71a04dbff83c7248ee2709188c158"
BASE_TREE = "e3d2bad58eca6c6b4d637e2d41362890705f8ca2"
PARENT = BASE
TEST = "tests/test_guard_daemon_storage_liveness.py"
NODE = TEST + "::test_locked_storage_hook_burst_fails_safe_without_stranding_daemon"
NODES = (NODE,)
TARGET = NODE
EXPECTED_CASES = 1
SCRIPT = "scripts/ci/prove_storage_failure_boundary.py"
CHANGED = {SCRIPT, ".github/workflows/ci.yml"}
PINS = {
    "tests/test_guard_daemon_storage_liveness.py": "e8b8a7390425de274a770580334797aacd0b9700",
    "src/codex_plugin_scanner/guard/daemon/server.py": "6ad89d53d38a634464069192ae2e7a57fdf4839e",
    "src/codex_plugin_scanner/guard/daemon/hook_process_runner.py": "7f036980410215bee326e27f433ab71720c0581c",
    "src/codex_plugin_scanner/guard/daemon/hook_failure_response.py": "5fb0cdba6e2432fb6e1bf480f98fa6de7d367296",
    "src/codex_plugin_scanner/guard/daemon/hook_worker_responses.py": "f1fb94dea872db81cd8750237f3d65dbe410fb38",
    "src/codex_plugin_scanner/guard/daemon/hook_availability_floor.py": "4a11b4d62783d649c03a78e660a7fc3dd5919fc4",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51"
}

_ITEMS, _REPORTS, _ERRORS = [], [], {}
_DESELECTED = _COLLECTION_ERRORS = _INTERNAL_ERRORS = 0
_SUBREAPER = False


def pytest_collection_finish(session):
    _ITEMS.extend(item.nodeid for item in session.items)


def pytest_deselected(items):
    global _DESELECTED
    _DESELECTED += len(items)


def pytest_collectreport(report):
    global _COLLECTION_ERRORS
    _COLLECTION_ERRORS += int(report.failed)


def pytest_internalerror(excrepr, excinfo):
    global _INTERNAL_ERRORS
    _INTERNAL_ERRORS += 1


def _storage_failure_boundary(frame):
    """Read only existing measurements and fixed response categories after failure."""
    incomplete = {"complete": False}
    try:
        rows = frame.f_locals.get("results")
        health = frame.f_locals.get("health_elapsed")
        if type(rows) is not list or len(rows) != 24:
            return incomplete
        if type(health) not in (int, float) or not math.isfinite(health) or not 0 <= health < 10000:
            return incomplete
        reasons = {
            "daemon_hook_deadline_exhausted", "daemon_hook_process_closed",
            "daemon_hook_process_deadline_exhausted", "daemon_hook_process_failed",
            "daemon_hook_process_invalid_json", "daemon_hook_process_not_ready",
            "daemon_hook_queue_capacity", "daemon_worker_exception",
            "harness_not_managed", "native_policy_not_ready",
            "native_scoped_authority_unavailable", "native_degraded_emergency_safe",
        }
        observations = []
        for index, row in enumerate(rows):
            if type(row) is not tuple or len(row) != 2 or type(row[0]) is not dict:
                return incomplete
            payload, elapsed = row
            if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed < 10000:
                return incomplete
            decision = payload.get("decision")
            reason = payload.get("reason_code")
            observations.append({
                "requestIndex": index, "elapsedSeconds": elapsed,
                "decision": decision if type(decision) is str and decision in {"allow", "deny", "block"} else (
                    "missing" if "decision" not in payload else "other"
                ),
                "reason": reason if type(reason) is str and reason in reasons else (
                    "missing" if "reason_code" not in payload else "other"
                ),
            })
        return {"complete": True, "results": observations, "healthElapsedSeconds": health}
    except BaseException:
        return incomplete


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    yield
    if call.excinfo is None:
        return
    error = call.excinfo.value
    record = {"exceptionClass": type(error).__name__ if type(error).__name__ in {
        "AssertionError", "TimeoutError", "RuntimeError", "ValueError"
    } else "OtherException"}
    terminal = error.__traceback__
    for _ in range(64):
        if terminal is None:
            break
        if terminal.tb_next is None:
            code = terminal.tb_frame.f_code
            if (item.nodeid == NODE and call.when == "call"
                    and Path(code.co_filename).resolve() == Path(TEST).resolve()
                    and code.co_name == "test_locked_storage_hook_burst_fails_safe_without_stranding_daemon"
                    and code.co_firstlineno == 113):
                record["sourceBlob"], record["line"] = PINS[TEST], terminal.tb_lineno
                if type(error) is AssertionError and terminal.tb_lineno in {157, 158, 159, 160, 161}:
                    record["failureBoundary"] = _storage_failure_boundary(terminal.tb_frame)
            break
        terminal = terminal.tb_next
    _ERRORS[(item.nodeid, call.when)] = record

def pytest_runtest_logreport(report):
    _REPORTS.append({"node": report.nodeid, "when": report.when, "outcome": report.outcome,
                     **(_ERRORS.get((report.nodeid, report.when), {}) if report.failed else {})})


def pytest_sessionfinish(session, exitstatus):
    destination = os.environ.get("STORAGE_BOUNDARY_OUTPUT")
    stage = os.environ.get("STORAGE_BOUNDARY_STAGE")
    if destination and stage in {"collect", "run"}:
        write(Path(destination) / (stage + "-plugin.json"), {
            "nodes": _ITEMS, "reports": _REPORTS, "exit": int(exitstatus),
            "deselected": _DESELECTED, "collectionErrors": _COLLECTION_ERRORS, "internalErrors": _INTERNAL_ERRORS,
        })


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.PIPE, timeout=20)


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def inventory(ref):
    result = {}
    for row in git("ls-tree", "-rz", ref).split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, sha = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("source_entry")
        result[name.decode()] = (mode, sha)
    return result


def verify():
    head, tree = os.environ["EXPECTED_DIAGNOSTIC_SHA"], os.environ["EXPECTED_DIAGNOSTIC_TREE"]
    if not all(re.fullmatch("[0-9a-f]{40}", value) for value in (head, tree)):
        raise ValueError("source_identity")
    if head != os.environ["GITHUB_SHA"] or git("rev-parse", "HEAD").decode().strip() != head:
        raise ValueError("source_identity")
    if git("rev-parse", "HEAD^{tree}").decode().strip() != tree:
        raise ValueError("source_identity")
    if git("show", "-s", "--format=%P", "HEAD").decode().strip() != PARENT:
        raise ValueError("source_parent")
    if git("rev-parse", BASE + "^{tree}").decode().strip() != BASE_TREE:
        raise ValueError("source_base")
    original, current = inventory(BASE), inventory("HEAD")
    changed = {name for name in original.keys() | current.keys() if original.get(name) != current.get(name)}
    if changed != CHANGED or len(original) != 4118 or len(current) != 4119:
        raise ValueError("source_delta")
    if any(current.get(name) != ("100644", sha) for name, sha in PINS.items()):
        raise ValueError("source_pin")
    for name, (mode, sha) in current.items():
        path = Path(name)
        info = path.lstat().st_mode
        valid = stat.S_ISLNK(info) if mode == "120000" else (
            stat.S_ISREG(info) and bool(info & 0o111) == (mode == "100755")
        )
        content = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        if not valid or blob(content) != sha:
            raise ValueError("source_contents")
    if any(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        raise ValueError("source_contents")
    return {"commit": head, "tree": tree, "baseFiles": 4118, "files": 4119, "mismatches": 0}


def enable_owned_child_cleanup():
    global _SUBREAPER
    if sys.platform != "linux":
        raise ValueError("cleanup_platform")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise ValueError("cleanup_setup")
    value = ctypes.c_int()
    pointer = ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value
    if libc.prctl(37, pointer, 0, 0, 0) != 0 or value.value != 1:
        raise ValueError("cleanup_setup")
    _SUBREAPER = True


def cleanup_owned_children():
    if not _SUBREAPER:
        return {"complete": False, "error": "subreaper_unavailable"}
    result = {"observed": 0, "signals": 0, "reaped": 0, "remaining": 0, "complete": False}
    children_file = Path("/proc/self/task/" + str(os.getpid()) + "/children")
    deadline = time.monotonic() + 5
    seen = set()
    while time.monotonic() < deadline:
        raw = children_file.read_text().split()
        if len(raw) > 64 or any(not value.isdecimal() for value in raw):
            raise ValueError("cleanup_children")
        children = [int(value) for value in raw]
        if not children:
            result["complete"] = True
            return result
        for pid in children:
            if pid <= 1 or pid in {os.getpid(), os.getppid()}:
                raise ValueError("cleanup_children")
            seen.add(pid)
            if len(seen) > 64:
                raise ValueError("cleanup_children")
            result["observed"] = len(seen)
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                result["reaped"] += 1
                continue
            # A live direct child cannot have its PID reused until this parent reaps it.
            fields = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[1]) != os.getpid():
                raise ValueError("cleanup_owner")
            try:
                if os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
                result["signals"] += 1
            except ProcessLookupError:
                pass
        time.sleep(0.05)
    result["remaining"] = len(children_file.read_text().split())
    result["complete"] = result["remaining"] == 0
    return result


def execute(command, path, timeout, environment):
    started = time.monotonic()
    timed_out = reap_timeout = False
    with path.open("wb") as stream:
        child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                 env=environment, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                reap_timeout, code = True, child.poll()
    data = path.read_bytes()
    return {"exit": code, "timedOut": timed_out, "reapTimedOut": reap_timeout,
            "seconds": time.monotonic() - started, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def selection(value):
    if (value["nodes"] != list(NODES) or value["deselected"] or value["collectionErrors"] or value["internalErrors"]):
        raise ValueError("selection")


def main():
    os.umask(0o077)
    output = Path(os.environ["RUNNER_TEMP"]) / "guard-storage-boundary"
    output.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "guard.storage-liveness-failure-boundary.v1", "base": BASE, "baseTree": BASE_TREE,
               "complete": False, "passed": False, "phase": "storage",
               "productChanged": False, "originalTimingTestChanged": False,
               "performanceAcceptance": False, "originalBudgetsSeconds": {"burst": 1.6, "socket": 1.75, "future": 2, "health": 0.5, "recovery": 1.0, "capacity": 15},
               "python": list(sys.version_info[:3])}
    code = 2
    try:
        if sys.version_info[:2] != (3, 12):
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        enable_owned_child_cleanup()
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
                   "-p", "scripts.ci.prove_storage_failure_boundary"]
        environment = dict(os.environ, STORAGE_BOUNDARY_OUTPUT=str(output), STORAGE_BOUNDARY_STAGE="collect",
                           PYTHONDONTWRITEBYTECODE="1")
        summary["collectionProcess"] = execute(
            command + ["--collect-only", TARGET], output / "collect.log", 120, environment)
        collected = json.loads((output / "collect-plugin.json").read_bytes())
        summary["collection"] = collected
        summary["sourceAfterCollection"] = verify()
        summary["collectionCleanup"] = cleanup_owned_children()
        if not summary["collectionCleanup"]["complete"] or summary["collectionCleanup"]["signals"]:
            raise ValueError("collection_cleanup")
        selection(collected)
        if summary["collectionProcess"]["exit"] != 0 or collected["exit"] != 0:
            raise ValueError("collection_process")
        environment["STORAGE_BOUNDARY_STAGE"] = "run"
        summary["testProcess"] = execute(command + [
            "--junitxml=" + str(output / "junit.xml"), TARGET], output / "run.log", 180, environment)
        observed = json.loads((output / "run-plugin.json").read_bytes())
        summary["observed"] = observed
        cases = list(ET.fromstring((output / "junit.xml").read_bytes()).iter("testcase"))
        counts = {"tests": len(cases), "failed": sum(bool(row.findall("failure")) for row in cases),
                  "errors": sum(bool(row.findall("error")) for row in cases),
                  "skipped": sum(bool(row.findall("skipped")) for row in cases)}
        summary["junit"] = counts
        summary["junitIdentityValid"] = len(cases) == EXPECTED_CASES and {
            (row.get("classname"), row.get("name")) for row in cases
        } == {(node.split("::")[0][:-3].replace("/", "."), node.split("::")[1]) for node in NODES}
        summary["sourceAfter"] = verify()
        selection(observed)
        reports = observed["reports"]
        keyed = {(row["node"], row["when"]): row for row in reports}
        if len(reports) != EXPECTED_CASES * 3 or len(keyed) != EXPECTED_CASES * 3 or set(keyed) != {
            (node, phase) for node in NODES for phase in ("setup", "call", "teardown")
        }:
            raise ValueError("phase_count")
        if any(keyed[node, phase]["outcome"] != "passed"
               for node in NODES for phase in ("setup", "teardown")):
            raise ValueError("fixture_failure")
        calls = [keyed[node, "call"] for node in NODES]
        failures = {row["node"] for row in calls if row["outcome"] == "failed"}
        summary["actualFailedNodes"] = sorted(failures)
        summary["actualCounts"] = {"tests": EXPECTED_CASES, "failed": len(failures), "passed": EXPECTED_CASES - len(failures)}
        if any(row["outcome"] not in {"passed", "failed"} for row in calls) or counts != {
            "tests": EXPECTED_CASES, "failed": len(failures), "errors": 0, "skipped": 0
        } or not summary["junitIdentityValid"]:
            raise ValueError("result")
        failed = int(bool(failures))
        process = summary["testProcess"]
        if (process["exit"] != failed or observed["exit"] != failed or process["timedOut"]
                or process["reapTimedOut"]):
            raise ValueError("process_result")
        summary["complete"], summary["passed"], code = True, not failed, failed
        summary["performanceAcceptance"] = False
        if failed:
            summary["failureBoundaryComplete"] = calls[0].get("failureBoundary", {}).get("complete") is True
            if not summary["failureBoundaryComplete"]:
                raise ValueError("failure_boundary_incomplete")
    except BaseException as error:
        summary["complete"], code = False, 2
        summary["errorClass"] = type(error).__name__ if type(error).__name__ in {
            "ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "KeyError", "ParseError"
        } else "OtherException"
        codes = {"source_entry", "source_identity", "source_parent", "source_base", "source_delta",
                 "source_pin", "source_contents", "interpreter", "selection", "collection_process",
                 "cleanup_platform", "cleanup_setup", "collection_cleanup", "phase_count", "fixture_failure", "result", "process_result", "failure_boundary_incomplete"}
        if type(error) is ValueError and len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in codes:
            summary["errorCode"] = error.args[0]
    finally:
        try:
            summary["ownedChildCleanup"] = cleanup_owned_children()
            if not summary["ownedChildCleanup"]["complete"] or summary["ownedChildCleanup"]["signals"]:
                summary["complete"], summary["passed"], code = False, False, 2
        except BaseException:
            summary["ownedChildCleanup"] = {"complete": False, "error": "closed_cleanup_failure"}
            summary["complete"], summary["passed"], code = False, False, 2
        try:
            summary["sourceFinal"] = verify()
        except BaseException:
            summary["complete"], summary["passed"], summary["finalSourceValid"], code = False, False, False, 2
        if not summary["complete"]:
            summary["performanceAcceptance"] = False
        summary["exit"] = code
        write(output / "summary.json", summary)
        print("STORAGE_BOUNDARY " + json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raise SystemExit(main())
