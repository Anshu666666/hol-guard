"""Validate gated import readiness and unchanged current prewarm behavior."""
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

from scripts.ci.prewarm_terminal_capture import TerminalCapture, supported_interpreter

BASE = "155cc5e001cd03b96f5003f9ae2f66ac8d5d4468"
BASE_TREE = "7fad36a6f5c02f11d6e47d60c7c0f27e611afb31"
PARENT = BASE
MODE = os.environ.get("ORACLE_READY_MODE", "")
if MODE not in {"readiness", "prewarm"}:
    raise ValueError("mode")
TEST = "tests/test_guard_hook_oracle_ready_imports.py"
NODE_PREFIX = TEST + "::test_evaluator_ready_prepares_only_explicit_oracle_imports"
CASE_IDS = ("off-oracle", "shadow-oracle", "auto", "force", "oracle-disabled", "not-test-mode", "shadow-disabled")
READY_NODES = tuple(NODE_PREFIX + "[" + case + "]" for case in CASE_IDS)
PREWARM_TEST = "tests/test_guard_hook_process_runner.py"
PREWARM_NODE = PREWARM_TEST + "::test_prewarmed_runner_does_not_hide_a_second_worker_queue"
NODES = READY_NODES if MODE == "readiness" else (PREWARM_NODE,)
TARGET = TEST if MODE == "readiness" else PREWARM_NODE
EXPECTED_CASES = len(NODES)
SCRIPT = "scripts/ci/prove_oracle_ready_imports.py"
CHANGED = {SCRIPT, ".github/workflows/ci.yml", "scripts/ci/prewarm_terminal_capture.py",
           "scripts/ci/test_prewarm_terminal_capture.py"}
PINS = {
    "scripts/ci/prewarm_terminal_capture.py": "737e80110527534afd3cc8baf1a5a559e933c131",
    "scripts/ci/test_prewarm_terminal_capture.py": "72640f34fc53cc28c34bdf89cf5a9da2fa87a182",
    "tests/test_guard_hook_oracle_ready_imports.py": "49f5333dddb6659896373f0ada84c643b1e482db",
    "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py": "295caf98da549990aaad22ca8ff657e514468869",
    "src/codex_plugin_scanner/guard/native_mode.py": "545e059638123363a104b98c43633172bcdc796a",
    "src/codex_plugin_scanner/guard/native_runtime.py": "f5c44884658477eb6ac5da554700ea9fd7688da9",
    "src/codex_plugin_scanner/guard/cli/commands_hook.py": "45b8d6dfa3403a25deda44d4ab38f47f6f91cba4",
    "src/codex_plugin_scanner/guard/cli/commands_hook_compat_loader.py": "f2228533cb829f5242260350412b6395d7f0953f",
    "src/codex_plugin_scanner/guard/cli/render.py": "bc217ae776631fbf64230f627bcb5178eac40cff",
    "src/codex_plugin_scanner/guard/adapters/__init__.py": "bdb13e1f62e17e12a12721fff2bd3f8ffec3ff15",
    "src/codex_plugin_scanner/guard/adapters/base.py": "8026fd888a4f3235e9a0ac2aee59089a035e062b",
    "src/codex_plugin_scanner/guard/store.py": "4edf1f65655e01fea4f634252d4242819ef92f52",
    "tests/test_guard_hook_process_runner.py": "7b99972cdf5d6018eadcba60fefbe790bc4efda0",
    "src/codex_plugin_scanner/guard/daemon/hook_process_runner.py": "7f036980410215bee326e27f433ab71720c0581c",
    "src/codex_plugin_scanner/guard/daemon/hook_process_slot_review.py": "1d6cab3445585c23111d9854bb95c7036af15590",
    "src/codex_plugin_scanner/guard/daemon/hook_process_worker.py": "ac956a67b04463857afe1aaec48adafdb85609d3",
    "src/codex_plugin_scanner/guard/daemon/hook_process_capacity.py": "0e0ca3503b9b8252cebbf893dc9c6b2f938a44fc",
    "src/codex_plugin_scanner/guard/daemon/hook_process_runner_lifecycle.py": "8f11a06586e5f704bd8632d1c7cbec6c52f395c5",
    "docs/guard/contracts/hook-data-plane-ownership.v2.json": "a24594b668f7add8aba32fe27924b2349371b8d7",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "dd7ea7046ebb399bde94d1532dce9149437cab43",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
    "tests/fixtures/guard-command-corpus/decision-diff-report.json": "4f349e4eda32ed3c9df84ad135d84ad48db39222"
}

_ITEMS, _REPORTS, _ERRORS = [], [], {}
_DESELECTED = _COLLECTION_ERRORS = _INTERNAL_ERRORS = 0
_SUBREAPER = False
_PREWARM_CODE = _PREWARM_NAMESPACE = _CAPTURE = None
_TERMINAL_ADMITTED = False
_TERMINALS = {}


def pytest_collection_finish(session):
    global _PREWARM_CODE, _PREWARM_NAMESPACE, _TERMINAL_ADMITTED
    _ITEMS.extend(item.nodeid for item in session.items)
    if MODE == "prewarm" and len(session.items) == 1 and session.items[0].nodeid == PREWARM_NODE:
        function = session.items[0].obj
        code = getattr(function, "__code__", None)
        if (code is not None and Path(code.co_filename).resolve() == Path(PREWARM_TEST).resolve()
                and code.co_firstlineno == 411 and code.co_name == PREWARM_NODE.split("::")[1]
                and type(getattr(function, "__globals__", None)) is dict):
            _PREWARM_CODE, _PREWARM_NAMESPACE = code, function.__globals__
            _TERMINAL_ADMITTED = True


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    global _CAPTURE
    capture = None
    if MODE == "prewarm" and item.nodeid == PREWARM_NODE:
        try:
            function = item.obj
            exact = (_TERMINAL_ADMITTED and getattr(function, "__code__", None) is _PREWARM_CODE
                     and getattr(function, "__globals__", None) is _PREWARM_NAMESPACE)
            capture = TerminalCapture(_PREWARM_CODE if exact else None, _PREWARM_NAMESPACE)
            _CAPTURE = capture
            capture.install()
        except BaseException:
            _CAPTURE = None
    try:
        yield
    finally:
        if capture is not None:
            capture.close()


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
    if MODE == "prewarm" and item.nodeid == PREWARM_NODE and call.when == "call":
        observation = {"complete": False}
        if _CAPTURE is not None:
            if call.excinfo is not None:
                _CAPTURE.capture_failure(call.excinfo.value)
            observation = _CAPTURE.snapshot(call.excinfo is not None)
        _TERMINALS[(item.nodeid, call.when)] = observation
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
            if Path(code.co_filename).resolve() == Path(TEST).resolve() and item.nodeid in NODES:
                record["sourceBlob"], record["line"] = PINS[TEST], terminal.tb_lineno
                result = terminal.tb_frame.f_locals.get("result")
                if type(result) is subprocess.CompletedProcess and isinstance(result.stderr, str) and len(result.stderr) <= 65536:
                    markers = [line.removeprefix("ORACLE_READY_CHILD_FAILURE ") for line in result.stderr.splitlines()
                               if line.startswith("ORACLE_READY_CHILD_FAILURE ")]
                    if len(markers) == 1:
                        try:
                            child = json.loads(markers[0])
                        except (ValueError, TypeError):
                            child = None
                        if isinstance(child, dict) and set(child) == {"stage", "exceptionClass"} and (
                            child["stage"] in {"optional_imports_not_ready", "other_child_failure"}
                            and child["exceptionClass"] in {"AssertionError", "OtherException"}
                        ):
                            record["childFailure"] = child
            if MODE == "prewarm" and code is _PREWARM_CODE and item.nodeid == PREWARM_NODE:
                record["sourceBlob"], record["line"] = PINS[PREWARM_TEST], terminal.tb_lineno
            break
        terminal = terminal.tb_next
    _ERRORS[(item.nodeid, call.when)] = record


def pytest_runtest_logreport(report):
    _REPORTS.append({"node": report.nodeid, "when": report.when, "outcome": report.outcome,
                     **(_ERRORS.get((report.nodeid, report.when), {}) if report.failed else {}),
                     **({"terminalObservation": _TERMINALS[(report.nodeid, report.when)]}
                        if (report.nodeid, report.when) in _TERMINALS else {})})


def pytest_sessionfinish(session, exitstatus):
    destination = os.environ.get("ORACLE_READY_PROOF_OUTPUT")
    stage = os.environ.get("ORACLE_READY_PROOF_STAGE")
    if destination and stage in {"collect", "run"}:
        write(Path(destination) / (stage + "-plugin.json"), {
            "nodes": _ITEMS, "reports": _REPORTS, "exit": int(exitstatus),
            "deselected": _DESELECTED, "collectionErrors": _COLLECTION_ERRORS, "internalErrors": _INTERNAL_ERRORS,
            "terminalAdmission": _TERMINAL_ADMITTED,
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
    if subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode != 0:
        raise ValueError("source_contents")
    original, current = inventory(BASE), inventory("HEAD")
    changed = {name for name in original.keys() | current.keys() if original.get(name) != current.get(name)}
    if changed != CHANGED or len(original) != 4128 or len(current) != 4131:
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
    return {"commit": head, "tree": tree, "baseFiles": 4128, "files": 4131, "mismatches": 0}


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
    if (value["nodes"] != list(NODES) or value["deselected"] or value["collectionErrors"] or value["internalErrors"]
            or (MODE == "prewarm" and value.get("terminalAdmission") is not True)):
        raise ValueError("selection")


def main():
    os.umask(0o077)
    output = Path(os.environ["RUNNER_TEMP"]) / ("guard-oracle-ready-" + MODE)
    output.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "guard.oracle-ready-candidate-validation.v1", "base": BASE, "baseTree": BASE_TREE,
               "complete": False, "passed": False, "mode": MODE,
               "productChanged": False, "originalTimingTestChanged": False,
               "performanceAcceptance": False, "originalBudgetsSeconds": [1.0, 1.8, 2, 15],
               "python": list(sys.version_info[:3]), "observationScope": "one_selected_original_invocation"}
    code = 2
    try:
        if not supported_interpreter():
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        enable_owned_child_cleanup()
        control_environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                   ORACLE_READY_CONTROL_OUTPUT=str(output / "controls.json"))
        summary["controlProcess"] = execute(
            [sys.executable, "-m", "scripts.ci.test_prewarm_terminal_capture"],
            output / "controls.log", 120, control_environment)
        summary["controls"] = json.loads((output / "controls.json").read_bytes())
        summary["sourceAfterControls"] = verify()
        summary["controlCleanup"] = cleanup_owned_children()
        expected_controls = ("test_cleanup_fault_does_not_replace_escaping_exception",
                  "test_collector_error_preserves_escaping_exception",
                  "test_collector_error_preserves_return",
                  "test_duplicate_capture_is_incomplete",
                  "test_escaping_failure_preserves_exception",
                  "test_invalid_values_remain_closed",
                  "test_missing_capture_is_incomplete",
                  "test_nested_failure_refuses_other_terminal_frame",
                  "test_nonzero_global_mask_is_refused_without_enabling_events",
                  "test_occupied_lease_is_preserved",
                  "test_partial_install_failure_cleans_owned_state",
                  "test_prior_callback_is_restored",
                  "test_stale_local_mask_is_preserved",
                  "test_success_only_captures_after_cleanup",
                  "test_wrong_callback_frame_is_incomplete",)
        controls = summary["controls"]
        if (controls.get("names") != list(expected_controls) or controls.get("tests") != 15
                or controls.get("failures") != 0 or controls.get("errors") != 0 or controls.get("skipped") != 0
                or controls.get("successful") is not True or controls.get("python") != [3, 13, 15]
                or controls.get("globalEventsEnabled") is not False or controls.get("originalTestInvoked") is not False
                or summary["controlProcess"]["exit"] != 0 or summary["controlProcess"]["timedOut"]
                or summary["controlProcess"]["reapTimedOut"] or not summary["controlCleanup"]["complete"]
                or summary["controlCleanup"]["signals"]):
            raise ValueError("terminal_controls")
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
                   "-p", "scripts.ci.prove_oracle_ready_imports"]
        environment = dict(os.environ, ORACLE_READY_PROOF_OUTPUT=str(output), ORACLE_READY_PROOF_STAGE="collect",
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
        environment["ORACLE_READY_PROOF_STAGE"] = "run"
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
        summary["originalInvocationPassed"] = not failed
        if MODE == "prewarm":
            summary["terminalBoundaryComplete"] = calls[0].get("terminalObservation", {}).get("complete") is True
            if not summary["terminalBoundaryComplete"]:
                raise ValueError("terminal_boundary_incomplete")
    except BaseException as error:
        summary["complete"], summary["passed"], code = False, False, 2
        summary["errorClass"] = type(error).__name__ if type(error).__name__ in {
            "ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "KeyError", "ParseError"
        } else "OtherException"
        codes = {"source_entry", "source_identity", "source_parent", "source_base", "source_delta",
                 "source_pin", "source_contents", "interpreter", "selection", "collection_process",
                 "cleanup_platform", "cleanup_setup", "collection_cleanup", "phase_count", "fixture_failure", "result", "process_result", "terminal_controls", "terminal_boundary_incomplete"}
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
        print("ORACLE_READY_CANDIDATE " + json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raise SystemExit(main())
