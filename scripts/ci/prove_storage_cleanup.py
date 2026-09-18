"""Prove unconditional test cleanup without changing any liveness budget."""
from __future__ import annotations

import argparse
import ctypes
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

import pytest

BASE = "35c677ac2ed71a04dbff83c7248ee2709188c158"
BASE_TREE = "e3d2bad58eca6c6b4d637e2d41362890705f8ca2"
PARENT = BASE
TEST = "tests/test_guard_daemon_storage_liveness.py"
PROOF = "tests/test_guard_daemon_storage_cleanup.py"
PAYLOAD = "scripts/ci/storage_liveness_cleanup_candidate.txt"
SCRIPT = "scripts/ci/prove_storage_cleanup.py"
CHANGED = {SCRIPT, PAYLOAD, PROOF, ".github/workflows/ci.yml"}
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
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
    "tests/test_guard_daemon_storage_cleanup.py": "3735a1e85a79faf6824937562b1af29a5ea67ae5",
    "scripts/ci/storage_liveness_cleanup_candidate.txt": "4ef9f0f87fda00079324685e7555a0d4cb517f82"
}
EXISTING_NODES = [
    "tests/test_guard_daemon_storage_liveness.py::test_critical_daemon_liveness_does_not_wait_for_locked_storage",
    "tests/test_guard_daemon_storage_liveness.py::test_locked_storage_hook_burst_fails_safe_without_stranding_daemon",
    "tests/test_guard_daemon_storage_liveness.py::test_runtime_heartbeat_writer_coalesces_pending_updates",
    "tests/test_guard_daemon_storage_liveness.py::test_bounded_runtime_heartbeat_connection_closes_after_write_error",
    "tests/test_guard_daemon_storage_liveness.py::test_internal_hook_sqlite_timeout_is_bounded_without_changing_default",
    "tests/test_guard_daemon_storage_liveness.py::test_sqlite_timeout_override_is_scoped_to_current_context",
    "tests/test_guard_daemon_storage_liveness.py::test_store_promotes_rollback_journal_before_bounded_hook_writes",
    "tests/test_guard_daemon_storage_liveness.py::test_new_store_keeps_incremental_auto_vacuum_with_wal",
    "tests/test_guard_daemon_storage_liveness.py::test_unclassified_watchdog_distinguishes_complete_headers_from_trickle",
    "tests/test_guard_daemon_storage_liveness.py::test_storage_maintenance_failure_requests_immediate_retry"
]
PROOF_FUNCTION = "test_storage_burst_always_stops_its_started_daemon"
PROOF_NODES = tuple(PROOF + "::" + PROOF_FUNCTION + "[" + value + "]" for value in (
    "burst-assertion", "future-error", "connect-error", "recovery-assertion", "complete",
))
EXPECTED_RED = set(PROOF_NODES[:3])
ALL_NODES = set(PROOF_NODES) | set(EXISTING_NODES)
_ITEMS, _REPORTS, _ERRORS = [], [], {}
_DESELECTED = _COLLECTION_ERRORS = _INTERNAL_ERRORS = 0
_SUBREAPER = False
_VARIANT = "baseline"


def pytest_collection_finish(session):
    _ITEMS.extend(item.nodeid if item.nodeid in ALL_NODES else "unknown-node" for item in session.items)


def pytest_deselected(items):
    global _DESELECTED
    _DESELECTED += len(items)


def pytest_collectreport(report):
    global _COLLECTION_ERRORS
    _COLLECTION_ERRORS += int(report.failed)


def pytest_internalerror(excrepr, excinfo):
    global _INTERNAL_ERRORS
    _INTERNAL_ERRORS += 1


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    yield
    if call.excinfo is None:
        return
    error = call.excinfo.value
    allowed = {"AssertionError", "TimeoutError", "RuntimeError", "ValueError", "OSError"}
    record = {"exceptionClass": type(error).__name__ if type(error).__name__ in allowed else "OtherException"}
    terminal = error.__traceback__
    for _ in range(64):
        if terminal is None:
            break
        if terminal.tb_next is None:
            code = terminal.tb_frame.f_code
            filename = Path(code.co_filename).resolve()
            for path in (PROOF, TEST):
                if filename == Path(path).resolve():
                    source_sha = PINS[path]
                    if path == TEST and os.environ.get("STORAGE_CLEANUP_VARIANT") == "candidate":
                        source_sha = PINS[PAYLOAD]
                    record.update(sourceBlob=source_sha, line=terminal.tb_lineno)
                    if path == PROOF:
                        record["cleanupAssertionOrigin"] = (
                            type(error) is AssertionError and call.when == "call"
                            and item.nodeid in EXPECTED_RED and terminal.tb_lineno == 150
                            and code.co_name == PROOF_FUNCTION and code.co_firstlineno == 15
                        )
            break
        terminal = terminal.tb_next
    _ERRORS[(item.nodeid, call.when)] = record


def pytest_runtest_logreport(report):
    _REPORTS.append({
        "node": report.nodeid if report.nodeid in ALL_NODES else "unknown-node",
        "when": report.when if report.when in {"setup", "call", "teardown"} else "unknown-phase",
        "outcome": report.outcome if report.outcome in {"passed", "failed", "skipped"} else "unknown-outcome",
        **(_ERRORS.get((report.nodeid, report.when), {}) if report.failed else {}),
    })


def pytest_sessionfinish(session, exitstatus):
    destination = os.environ.get("STORAGE_CLEANUP_OUTPUT")
    stage = os.environ.get("STORAGE_CLEANUP_STAGE")
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
    if changed != CHANGED or len(original) != 4118 or len(current) != 4121:
        raise ValueError("source_delta")
    if any(current.get(name) != ("100644", sha) for name, sha in PINS.items()):
        raise ValueError("source_pin")
    expected = dict(current)
    if _VARIANT == "candidate":
        expected[TEST] = ("100644", PINS[PAYLOAD])
    elif _VARIANT != "baseline":
        raise ValueError("source_variant")
    for name, (mode, sha) in expected.items():
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
    return {"commit": head, "tree": tree, "baseFiles": 4118, "files": 4121,
            "variant": _VARIANT, "testBlob": expected[TEST][1], "mismatches": 0}


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



def selection(value, nodes):
    if (value["nodes"] != list(nodes) or value["deselected"]
            or value["collectionErrors"] or value["internalErrors"]):
        raise ValueError("selection")


def phase(output, name, nodes, targets, summary):
    folder = output / name
    folder.mkdir()
    record = {"complete": False, "expectedNodes": list(nodes)}
    summary[name] = record
    record["sourceBefore"] = verify()
    command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
               "-p", "scripts.ci.prove_storage_cleanup"]
    environment = dict(os.environ, STORAGE_CLEANUP_OUTPUT=str(folder), STORAGE_CLEANUP_STAGE="collect",
                       STORAGE_CLEANUP_VARIANT=_VARIANT, PYTHONDONTWRITEBYTECODE="1")
    record["collectionProcess"] = execute(
        command + ["--collect-only", *targets], folder / "collect.log", 120, environment)
    collected = json.loads((folder / "collect-plugin.json").read_bytes())
    record["collection"] = collected
    record["sourceAfterCollection"] = verify()
    record["collectionCleanup"] = cleanup_owned_children()
    if not record["collectionCleanup"]["complete"] or record["collectionCleanup"]["signals"]:
        raise ValueError("collection_cleanup")
    selection(collected, nodes)
    if record["collectionProcess"]["exit"] != 0 or collected["exit"] != 0:
        raise ValueError("collection_process")
    environment["STORAGE_CLEANUP_STAGE"] = "run"
    record["testProcess"] = execute(command + [
        "--junitxml=" + str(folder / "junit.xml"), *targets], folder / "run.log", 240, environment)
    observed = json.loads((folder / "run-plugin.json").read_bytes())
    record["observed"] = observed
    data = (folder / "junit.xml").read_bytes()
    cases = list(ET.fromstring(data).iter("testcase"))
    counts = {"tests": len(cases), "failed": sum(bool(row.findall("failure")) for row in cases),
              "errors": sum(bool(row.findall("error")) for row in cases),
              "skipped": sum(bool(row.findall("skipped")) for row in cases)}
    record["junit"], record["junitSha256"] = counts, hashlib.sha256(data).hexdigest()
    record["junitIdentityValid"] = len(cases) == len(nodes) and {
        (row.get("classname"), row.get("name")) for row in cases
    } == {(node.split("::")[0][:-3].replace("/", "."), node.split("::")[1]) for node in nodes}
    record["sourceAfter"] = verify()
    record["ownedChildCleanup"] = cleanup_owned_children()
    selection(observed, nodes)
    reports = observed["reports"]
    keyed = {(row["node"], row["when"]): row for row in reports}
    if len(reports) != len(nodes) * 3 or len(keyed) != len(nodes) * 3 or set(keyed) != {
        (node, when) for node in nodes for when in ("setup", "call", "teardown")
    }:
        raise ValueError("phase_count")
    if any(keyed[node, when]["outcome"] != "passed"
           for node in nodes for when in ("setup", "teardown")):
        raise ValueError("fixture_failure")
    calls = [keyed[node, "call"] for node in nodes]
    failures = {row["node"] for row in calls if row["outcome"] == "failed"}
    record["actualFailedNodes"] = sorted(failures)
    record["actualCounts"] = {"tests": len(nodes), "failed": len(failures), "passed": len(nodes) - len(failures)}
    if any(row["outcome"] not in {"passed", "failed"} for row in calls) or counts != {
        "tests": len(nodes), "failed": len(failures), "errors": 0, "skipped": 0
    } or not record["junitIdentityValid"]:
        raise ValueError("result")
    code = int(bool(failures))
    process = record["testProcess"]
    if process["exit"] != code or observed["exit"] != code or process["timedOut"] or process["reapTimedOut"]:
        raise ValueError("process_result")
    if not record["ownedChildCleanup"]["complete"] or record["ownedChildCleanup"]["signals"]:
        raise ValueError("test_cleanup")
    record["complete"] = True
    if name == "baseline":
        record["expectedRedObserved"] = failures == EXPECTED_RED and all(
            row.get("cleanupAssertionOrigin") is True
            and row.get("sourceBlob") == PINS[PROOF] and row.get("line") == 150
            and row.get("exceptionClass") == "AssertionError"
            for row in calls if row["outcome"] == "failed"
        )
        if not record["expectedRedObserved"]:
            raise ValueError("expected_red_missing")
    else:
        record["passed"] = not failures
    return code


def main():
    global _VARIANT
    os.umask(0o077)
    output = Path(os.environ["RUNNER_TEMP"]) / "guard-storage-cleanup"
    output.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "guard.storage-cleanup-pair.v1", "base": BASE, "baseTree": BASE_TREE,
               "complete": False, "candidatePassed": False, "expectedRedObserved": False,
               "productChanged": False, "latencyFixClaim": False, "python": list(sys.version_info[:3]),
               "originalBudgetsSeconds": {"burst": 1.6, "socket": 1.75, "future": 2,
                                         "health": 0.5, "recovery": 1.0, "capacity": 15}}
    original = None
    code = 2
    try:
        if sys.version_info[:3] != (3, 12, 13):
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        original = Path(TEST).read_bytes()
        enable_owned_child_cleanup()
        baseline_code = phase(output, "baseline", PROOF_NODES, [PROOF], summary)
        summary["expectedRedObserved"] = summary["baseline"]["expectedRedObserved"]
        payload = Path(PAYLOAD).read_bytes()
        if blob(payload) != PINS[PAYLOAD]:
            raise ValueError("source_pin")
        Path(TEST).write_bytes(payload)
        _VARIANT = "candidate"
        summary["candidateSourceBefore"] = verify()
        candidate_code = phase(output, "candidate", (*PROOF_NODES, *EXISTING_NODES), [PROOF, TEST], summary)
        summary["candidatePassed"] = candidate_code == 0
        summary["complete"] = True
        # Deliberate baseline pytest exit1 remains the overall diagnostic exit.
        code = max(baseline_code, candidate_code)
    except BaseException as error:
        summary["complete"], summary["candidatePassed"], code = False, False, 2
        allowed = {"ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "KeyError", "ParseError"}
        summary["errorClass"] = type(error).__name__ if type(error).__name__ in allowed else "OtherException"
        codes = {"source_entry", "source_identity", "source_parent", "source_base", "source_delta",
                 "source_pin", "source_contents", "source_variant", "interpreter", "selection",
                 "collection_process", "cleanup_platform", "cleanup_setup", "collection_cleanup",
                 "phase_count", "fixture_failure", "result", "process_result", "test_cleanup",
                 "expected_red_missing"}
        if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in codes:
            summary["errorCode"] = error.args[0]
    finally:
        try:
            summary["ownedChildCleanup"] = cleanup_owned_children()
            if not summary["ownedChildCleanup"]["complete"] or summary["ownedChildCleanup"]["signals"]:
                summary["complete"], summary["candidatePassed"], code = False, False, 2
        except BaseException:
            summary["ownedChildCleanup"] = {"complete": False, "error": "closed_cleanup_failure"}
            summary["complete"], summary["candidatePassed"], code = False, False, 2
        try:
            summary["sourceFinalVariant"] = verify()
        except BaseException:
            summary["complete"], summary["candidatePassed"], summary["finalVariantValid"], code = False, False, False, 2
        try:
            if original is not None:
                Path(TEST).write_bytes(original)
            _VARIANT = "baseline"
            summary["sourceRestored"] = verify()
        except BaseException:
            summary["complete"], summary["candidatePassed"], summary["restorationValid"], code = False, False, False, 2
        summary["exit"] = code
        write(output / "summary.json", summary)
        print("STORAGE_CLEANUP " + json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raise SystemExit(main())
