"""Run the unchanged prewarm node with closed diagnostic spans only."""
from __future__ import annotations

import argparse
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

from scripts.ci import prewarm_span_observer as observer

BASE = "1b51463217211c0f619e82eaf085990372f5e835"
BASE_TREE = "89293e09aca144cd816977eb6301ff85d21a6530"
TEST = "tests/test_guard_hook_process_runner.py"
NODE = observer.NODE
SCRIPT = "scripts/ci/prove_prewarm_spans.py"
OBSERVER = "scripts/ci/prewarm_span_observer.py"
CHANGED = {SCRIPT, OBSERVER, ".github/workflows/ci.yml"}
PINS = {
    **observer.PINS,
    TEST: "7b99972cdf5d6018eadcba60fefbe790bc4efda0",
    OBSERVER: "871d7da16f026b458a17fdb29713be5999a61703",
    "src/codex_plugin_scanner/guard/daemon/hook_process_spawner.py": "2a317b333cffb7b1794e4f999f1a8b54b0af623b",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
}
_ITEMS, _REPORTS, _ERRORS = [], [], {}
_DESELECTED = _COLLECTION_ERRORS = _INTERNAL_ERRORS = 0


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
            if Path(code.co_filename).resolve() == Path(TEST).resolve() and item.nodeid == NODE:
                record["sourceBlob"], record["line"] = PINS[TEST], terminal.tb_lineno
                if code.co_firstlineno == 411:
                    for name in ("elapsed", "timing_scale"):
                        value = terminal.tb_frame.f_locals.get(name)
                        if type(value) in (float, int) and math.isfinite(value) and 0 <= value < 10000:
                            record[name] = value
            break
        terminal = terminal.tb_next
    _ERRORS[(item.nodeid, call.when)] = record


def pytest_runtest_logreport(report):
    _REPORTS.append({
        "node": report.nodeid, "when": report.when, "outcome": report.outcome,
        "observerIncompleteMarker": "PREWARM_OBSERVER_INCOMPLETE" in report.capstderr,
        **(_ERRORS.get((report.nodeid, report.when), {}) if report.failed else {}),
    })


def pytest_sessionfinish(session, exitstatus):
    destination = os.environ.get("PREWARM_PROOF_OUTPUT")
    stage = os.environ.get("PREWARM_PROOF_STAGE")
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
    if git("show", "-s", "--format=%P", "HEAD").decode().strip() != BASE:
        raise ValueError("source_parent")
    if git("rev-parse", BASE + "^{tree}").decode().strip() != BASE_TREE:
        raise ValueError("source_base")
    original, current = inventory(BASE), inventory("HEAD")
    changed = {name for name in original.keys() | current.keys() if original.get(name) != current.get(name)}
    if changed != CHANGED or len(original) != 4088 or len(current) != 4090:
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
    return {"commit": head, "tree": tree, "baseFiles": 4088, "files": 4090, "mismatches": 0}


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
            "sha256": hashlib.sha256(data).hexdigest(),
            "observerIncompleteMarker": b"PREWARM_OBSERVER_INCOMPLETE" in data}


def selection(value):
    if (value["nodes"] != [NODE] or value["deselected"] or value["collectionErrors"] or value["internalErrors"]):
        raise ValueError("selection")


def spans(directory):
    files = sorted(directory.glob("span-*.jsonl"))
    if not 2 <= len(files) <= 65:
        raise ValueError("span_files")
    groups = []
    for path in files:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024:
            raise ValueError("span_file")
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if not 1 <= len(rows) <= 513:
            raise ValueError("span_count")
        first = rows[0].get("phase")
        role = {"parent-observer": "parent", "evaluator-observer": "evaluator"}.get(first)
        if role is None:
            raise ValueError("span_role")
        for row in rows:
            if (set(row) != {"phase", "seconds"} or row["phase"] not in observer.PHASES
                    or row["phase"] == "observer-cap" or type(row["seconds"]) not in (int, float)
                    or not math.isfinite(row["seconds"]) or not 0 <= row["seconds"] <= 180):
                raise ValueError("span_value")
        allowed = ({"parent-observer", "parent-finished", "parent-review", "slot-roundtrip"} if role == "parent"
                   else observer.PHASES - {"parent-observer", "parent-finished", "parent-review", "slot-roundtrip"})
        if any(row["phase"] not in allowed for row in rows):
            raise ValueError("span_role")
        phases = {}
        for name in sorted({row["phase"] for row in rows}):
            values = [row["seconds"] for row in rows if row["phase"] == name]
            phases[name] = {"count": len(values), "sumSeconds": sum(values),
                            "minSeconds": min(values), "maxSeconds": max(values)}
        groups.append({"role": role, "phases": phases})
    parents = [group for group in groups if group["role"] == "parent"]
    if (len(parents) != 1 or parents[0]["phases"].get("parent-observer", {}).get("count") != 1
            or parents[0]["phases"].get("parent-finished", {}).get("count") != 1):
        raise ValueError("span_parent")
    return {"processGroups": groups, "evaluatorProcesses": len(groups) - 1,
            "nestedSpansAreNotAdditive": True, "rawProcessIdentifiersRetained": False}



def cleanup_guardians(directory):
    # Only numeric registrations written by this diagnostic's own guardian targets.
    files = sorted(directory.glob("guardian-*.json"))
    if len(files) > 64:
        raise ValueError("guardian_count")
    result = {"registered": len(files), "alreadyExited": 0, "groupsKilled": 0,
              "preIsolationProcessesKilled": 0, "identityRejected": 0, "remaining": 0}
    targets = []
    def identity(pid):
        try:
            fields = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[1].split()
            return int(fields[19]), fields[0]
        except FileNotFoundError:
            return None
    for path in files:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 256:
            raise ValueError("guardian_file")
        record = json.loads(path.read_bytes())
        if (set(record) != {"pid", "startTicks"}
                or any(type(record[key]) is not int or record[key] <= 1 for key in record)
                or path.name != "guardian-" + str(record["pid"]) + ".json"
                or record["pid"] in {os.getpid(), os.getppid()}):
            raise ValueError("guardian_record")
        pid, ticks = record["pid"], record["startTicks"]
        current = identity(pid)
        if current is None or current == (ticks, "Z"):
            result["alreadyExited"] += 1
            continue
        if current[0] != ticks:
            result["identityRejected"] += 1
            continue
        try:
            group = os.getpgid(pid)
            # Revalidate immediately before signaling; never signal an unrelated group.
            if identity(pid) != current:
                result["identityRejected"] += 1
                continue
            if group == pid:
                os.killpg(group, signal.SIGKILL)
                result["groupsKilled"] += 1
            else:
                # Before setsid the guardian cannot have spawned its evaluator yet.
                os.kill(pid, signal.SIGKILL)
                result["preIsolationProcessesKilled"] += 1
            targets.append((pid, ticks))
        except ProcessLookupError:
            result["alreadyExited"] += 1
    deadline = time.monotonic() + 5
    while targets and time.monotonic() < deadline:
        targets = [(pid, ticks) for pid, ticks in targets
                   if (current := identity(pid)) is not None and current[0] == ticks and current[1] != "Z"]
        if targets:
            time.sleep(0.05)
    result["remaining"] = len(targets)
    result["complete"] = result["remaining"] == result["identityRejected"] == 0
    return result


def main():
    os.umask(0o077)
    output = Path(os.environ["RUNNER_TEMP"]) / "guard-prewarm-causal"
    output.mkdir(parents=True, exist_ok=False)
    span_dir = output / "spans"
    span_dir.mkdir()
    summary = {"schema": "guard.prewarm-causal-spans.v1", "base": BASE, "baseTree": BASE_TREE,
               "complete": False, "causalObservationOnly": True, "performanceAcceptance": False,
               "productAndTargetTestChanged": False, "originalBudgetsSeconds": [1.0, 1.8, 2, 15],
               "python": list(sys.version_info[:3])}
    code = 2
    try:
        if sys.version_info[:2] != (3, 10):
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
                   "-p", "scripts.ci.prove_prewarm_spans"]
        environment = dict(os.environ, PREWARM_PROOF_OUTPUT=str(output), PREWARM_PROOF_STAGE="collect",
                           PREWARM_SPAN_DIR=str(span_dir), PYTHONDONTWRITEBYTECODE="1")
        summary["collectionProcess"] = execute(command + ["--collect-only", NODE], output / "collect.log", 120, environment)
        collected = json.loads((output / "collect-plugin.json").read_bytes())
        summary["collection"] = collected
        summary["sourceAfterCollection"] = verify()
        selection(collected)
        if summary["collectionProcess"]["exit"] != 0 or collected["exit"] != 0:
            raise ValueError("collection_process")
        environment["PREWARM_PROOF_STAGE"] = "run"
        summary["testProcess"] = execute(command + ["-p", "scripts.ci.prewarm_span_observer",
            "--junitxml=" + str(output / "junit.xml"), NODE], output / "run.log", 180, environment)
        observed = json.loads((output / "run-plugin.json").read_bytes())
        summary["observed"] = observed
        cases = list(ET.fromstring((output / "junit.xml").read_bytes()).iter("testcase"))
        counts = {"tests": len(cases), "failed": sum(bool(row.findall("failure")) for row in cases),
                  "errors": sum(bool(row.findall("error")) for row in cases),
                  "skipped": sum(bool(row.findall("skipped")) for row in cases)}
        summary["junit"] = counts
        summary["spans"] = spans(span_dir)
        summary["sourceAfter"] = verify()
        selection(observed)
        reports = observed["reports"]
        if (len(reports) != 3 or {row["node"] for row in reports} != {NODE}
                or {row["when"] for row in reports} != {"setup", "call", "teardown"}):
            raise ValueError("phase_count")
        phases = {row["when"]: row for row in reports}
        if any(phases[name]["outcome"] != "passed" for name in ("setup", "teardown")):
            raise ValueError("fixture_failure")
        failed = int(phases["call"]["outcome"] == "failed")
        if phases["call"]["outcome"] not in {"passed", "failed"} or counts != {
            "tests": 1, "failed": failed, "errors": 0, "skipped": 0
        }:
            raise ValueError("result")
        process = summary["testProcess"]
        if (process["exit"] != failed or observed["exit"] != failed or process["timedOut"]
                or any(row["observerIncompleteMarker"] for row in reports)
                or process["reapTimedOut"] or process["observerIncompleteMarker"]):
            raise ValueError("process_result")
        summary["complete"] = True
        code = failed
    except BaseException as error:
        summary["errorClass"] = type(error).__name__ if type(error).__name__ in {
            "ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "KeyError", "ParseError"
        } else "OtherException"
        codes = {"source_entry", "source_identity", "source_parent", "source_base", "source_delta",
                 "source_pin", "source_contents", "interpreter", "selection", "collection_process",
                 "span_files", "span_file", "span_count", "span_role", "span_value", "span_parent",
                 "phase_count", "fixture_failure", "result", "process_result"}
        if type(error) is ValueError and len(error.args) == 1 and error.args[0] in codes:
            summary["errorCode"] = error.args[0]
    finally:
        try:
            summary["guardianCleanup"] = cleanup_guardians(span_dir)
            if not summary["guardianCleanup"]["complete"]:
                summary["complete"], code = False, 2
        except BaseException:
            summary["guardianCleanup"] = {"complete": False, "error": "closed_cleanup_failure"}
            summary["complete"], code = False, 2
        try:
            summary["sourceFinal"] = verify()
        except BaseException:
            summary["complete"], summary["finalSourceValid"], code = False, False, 2
        summary["exit"] = code
        write(output / "summary.json", summary)
        print("PREWARM_CAUSAL_OBSERVATION " + json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raise SystemExit(main())
