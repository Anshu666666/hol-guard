"""Observe fixed native compatibility, test-first regressions and isolated prewarm."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

BASE = "1b51463217211c0f619e82eaf085990372f5e835"
BASE_TREE = "89293e09aca144cd816977eb6301ff85d21a6530"
HTTP = "tests/test_guard_bounded_http_exception_compatibility.py"
LIFECYCLE = "tests/test_guard_daemon_lifecycle_transition.py"
EXPIRY = "tests/test_guard_oauth_cached_expiry_compatibility.py"
RETRY = "tests/test_guard_sync_retry_clock_isolation.py"
PREWARM = "tests/test_guard_hook_process_runner.py"
PREWARM_CASE = "test_prewarmed_runner_does_not_hide_a_second_worker_queue"
LIFECYCLE_CASE = "test_failed_start_retains_ownership_when_serve_join_returns_a_live_thread"
SCRIPT = "scripts/ci/prove_native_compatibility.py"
PINS = {
    HTTP: "a0d8a20f4e17694feccacaa8a2cec3af0c8901ac",
    LIFECYCLE: "05db6d62a4cf734c77370daa148cb90fc26149d7",
    EXPIRY: "b4d3f8554c99b0d45efc5e6efb3f702f41c3917d",
    RETRY: "6bc5c265d8df32b7d4cdcc0cb0a735cbf2170bbf",
    PREWARM: "7b99972cdf5d6018eadcba60fefbe790bc4efda0",
    "tests/test_guard_sync_http_error_message.py": "41530f3f9caa5932a3cc03c5e835567cbae4073b",
    "src/codex_plugin_scanner/guard/daemon/bounded_http.py": "452b3abe834f0c9e81023bda5bcc5ae2fb3801bd",
    "src/codex_plugin_scanner/guard/runtime/runner.py": "a5a305dc90c684c4d7b01be3e35f0bdb36a91468",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
}
CHANGED = {EXPIRY, RETRY, SCRIPT, ".github/workflows/ci.yml"}
SELECTIONS = {
    "compatibility": [HTTP, LIFECYCLE],
    "regressions": [EXPIRY, RETRY],
    "prewarm": [PREWARM + "::" + PREWARM_CASE],
}
EXPIRY_IDS = {
    "test_cached_access_token_accepts_equivalent_utc_expiry": [
        "future-z", "future-offset", "outside-refresh-skew",
    ],
    "test_cached_access_token_keeps_expiry_and_skew_refusals": [
        "malformed", "expired", "expires-now", "inside-skew", "at-skew", "missing",
    ],
    "test_real_oauth_resolver_uses_unexpired_cache_before_refresh": ["future-z", "future-offset"],
    "test_real_oauth_resolver_keeps_required_refresh_boundary": [
        "malformed", "expired", "inside-skew", "at-skew", "missing", "force-z", "force-offset",
    ],
}
RETRY_IDS = [
    "test_urlopen_json_retries_cloudflare_502_with_default_retry_after",
    "test_urlopen_retries_cloudflare_524_with_retry_after_header",
]
_CALLS = {}
_ITEMS = []
_REPORTS = []
_DESELECTED = _COLLECTION_ERRORS = _INTERNAL_ERRORS = 0
SAFE_CODES = {
    "source_entry", "source_identity", "source_parent", "source_base", "source_delta",
    "source_pin", "source_contents", "interpreter", "collection_process", "selection",
    "selection_changed", "phase_incomplete", "junit_identity", "junit_counts",
    "fixture_failure", "unexpected_result", "process_result",
}


def key(value):
    return json.dumps(value, separators=(",", ":"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expected(phase):
    values = []
    if phase == "compatibility":
        errors = [
            ("TimeoutError", None, 1, 0, False), ("BrokenPipeError", None, 0, 1, False),
            ("ConnectionAbortedError", None, 0, 1, False), ("ConnectionResetError", None, 0, 1, False),
            ("_PlainOSError", errno.EPIPE, 0, 1, False), ("_PlainOSError", errno.ECONNABORTED, 0, 1, False),
            ("_PlainOSError", errno.ECONNRESET, 0, 1, False), ("_PlainOSError", errno.ETIMEDOUT, 0, 1, False),
            ("ValueError", None, 0, 0, True),
        ]
        for context in ("native", "python310"):
            values.extend([["active", context, *case] for case in errors])
            values.extend([["missing", context], ["parent", context]])
        values.extend([["lifecycle", True], ["lifecycle", False], ["lifecycle-stop"], ["lifecycle-serve"]])
    elif phase == "regressions":
        values.extend([["expiry", function, identity] for function, ids in EXPIRY_IDS.items() for identity in ids])
        values.extend([["retry", identity] for identity in RETRY_IDS])
    else:
        values.append(["prewarm"])
    return {key(value) for value in values}


def signature(item):
    name = getattr(item, "originalname", None) or item.name
    params = getattr(getattr(item, "callspec", None), "params", {})
    file = item.nodeid.split("::", 1)[0]
    if file == HTTP:
        context = params.get("handler_context")
        if name == "test_active_request_error_keeps_metrics_and_parent_fallback":
            error = params["error"]
            return ["active", context, type(error).__name__, getattr(error, "errno", None),
                    params["timeouts"], params["aborts"], params["uses_parent"]]
        if name == "test_missing_active_error_still_reaches_parent":
            return ["missing", context]
        if name == "test_parent_handler_failure_is_not_suppressed":
            return ["parent", context]
    if file == LIFECYCLE:
        if name == LIFECYCLE_CASE:
            return ["lifecycle", params["record_notes"]]
        if name == "test_stop_during_capacity_activation_prevents_successful_start":
            return ["lifecycle-stop"]
        if name == "test_serve_base_exception_is_contained_when_stop_races_serve_loop":
            return ["lifecycle-serve"]
    if file == EXPIRY and name in EXPIRY_IDS:
        return ["expiry", name, item.callspec.id]
    if file == RETRY and name == "test_retry_fixtures_do_not_capture_an_unrelated_worker_sleep":
        return ["retry", params["case_name"]]
    if file == PREWARM and name == PREWARM_CASE:
        return ["prewarm"]
    return ["unexpected"]


def pytest_collection_finish(session):
    allowed = expected(os.environ["NATIVE_COMPAT_PHASE"])
    for item in session.items:
        value = signature(item)
        _ITEMS.append({"node": item.nodeid, "nodeSha256": digest(item.nodeid.encode()),
                       "signature": value if key(value) in allowed else ["unexpected"]})


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
    names = {"AssertionError", "AttributeError", "RuntimeError", "_RefreshReached", "TimeoutError"}
    record = {"exceptionClass": type(error).__name__ if type(error).__name__ in names else "OtherException"}
    terminal = error.__traceback__
    for _ in range(64):
        if terminal is None:
            break
        if terminal.tb_next is None:
            code = terminal.tb_frame.f_code
            try:
                relative = str(Path(code.co_filename).resolve().relative_to(Path.cwd().resolve()))
            except (ValueError, OSError):
                break
            if relative in PINS:
                record["sourceBlob"] = PINS[relative]
                record["line"] = terminal.tb_lineno
            if (relative == PREWARM and code.co_name == PREWARM_CASE
                    and item.nodeid == PREWARM + "::" + PREWARM_CASE):
                for name in ("elapsed", "timing_scale"):
                    value = terminal.tb_frame.f_locals.get(name)
                    if type(value) in (int, float) and math.isfinite(value) and 0 <= value < 10000:
                        record[name] = value
            break
        terminal = terminal.tb_next
    _CALLS[(item.nodeid, call.when)] = record


def pytest_runtest_logreport(report):
    _REPORTS.append({"node": report.nodeid, "nodeSha256": digest(report.nodeid.encode()),
                     "when": report.when, "outcome": report.outcome,
                     **(_CALLS.get((report.nodeid, report.when), {}) if report.failed else {})})


def pytest_sessionfinish(session, exitstatus):
    output = os.environ.get("NATIVE_COMPAT_OUTPUT")
    stage = os.environ.get("NATIVE_COMPAT_STAGE")
    if output and stage in {"collect", "run"}:
        write(Path(output) / (stage + "-plugin.json"),
              {"exit": int(exitstatus), "items": _ITEMS, "reports": _REPORTS,
               "deselected": _DESELECTED, "collectionErrors": _COLLECTION_ERRORS,
               "internalErrors": _INTERNAL_ERRORS})


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def git(*arguments):
    return subprocess.check_output(["git", *arguments], stderr=subprocess.PIPE, timeout=20)


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def inventory(ref):
    values = {}
    for row in git("ls-tree", "-rz", ref).split(b"\0"):
        if not row:
            continue
        meta, raw = row.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("source_entry")
        values[raw.decode()] = (mode, sha)
    return values


def verify():
    head = os.environ["EXPECTED_DIAGNOSTIC_SHA"]
    tree = os.environ["EXPECTED_DIAGNOSTIC_TREE"]
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
    if changed != CHANGED or len(original) != 4088 or len(current) != 4091:
        raise ValueError("source_delta")
    if any(current.get(name) != ("100644", sha) for name, sha in PINS.items()):
        raise ValueError("source_pin")
    for name, (mode, sha) in current.items():
        path = Path(name)
        info = path.lstat().st_mode
        valid = stat.S_ISLNK(info) if mode == "120000" else (
            stat.S_ISREG(info) and bool(info & 0o111) == (mode == "100755")
        )
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        if not valid or blob(data) != sha:
            raise ValueError("source_contents")
    if any(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        raise ValueError("source_contents")
    return {"head": head, "tree": tree, "baseFiles": 4088, "checkedFiles": 4091, "mismatches": 0}


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
    return {"exit": code, "timedOut": timed_out, "reapTimedOut": reap_timeout,
            "seconds": time.monotonic() - started, "outputSha256": digest(path.read_bytes())}


def closed(receipt):
    return {name: [{key: value for key, value in row.items() if key != "node"} for row in receipt[name]]
            for name in ("items", "reports")} | {
                name: receipt[name] for name in ("exit", "deselected", "collectionErrors", "internalErrors")
            }


def validate_selection(receipt, phase):
    items = receipt["items"]
    signatures = [key(row["signature"]) for row in items]
    nodes = [row["node"] for row in items]
    if (len(nodes) != len(set(nodes)) or len(signatures) != len(set(signatures))
            or set(signatures) != expected(phase)
            or receipt["deselected"] or receipt["collectionErrors"] or receipt["internalErrors"]):
        raise ValueError("selection")
    return sorted(items, key=lambda row: row["node"])


def prove(phase):
    output = Path(os.environ["NATIVE_COMPAT_OUTPUT"])
    output.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "guard.native-compatibility-observation.v1", "phase": phase,
               "base": BASE, "baseTree": BASE_TREE, "complete": False, "tier": "E2",
               "python": list(sys.version_info[:3]), "productOverlays": False,
               "testOnlyOverlays": [EXPIRY, RETRY], "rawOutputPublished": False,
               "testThresholdsChanged": False, "expectedRedObserved": False,
               "timingScope": "Process seconds include setup/cleanup; elapsed/timing_scale appear only from a failing prewarm assertion frame."}
    code = 2
    try:
        if sys.version_info[:2] != (3, 10):
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
                   "-p", "scripts.ci.prove_native_compatibility"]
        environment = dict(os.environ, NATIVE_COMPAT_PHASE=phase, NATIVE_COMPAT_STAGE="collect",
                           PYTHONDONTWRITEBYTECODE="1")
        summary["collectionProcess"] = execute(command + ["--collect-only", *SELECTIONS[phase]],
                                                output / "collect.log", 120, environment)
        collected = json.loads((output / "collect-plugin.json").read_bytes())
        summary["collection"] = closed(collected)
        summary["sourceAfterCollection"] = verify()
        items = validate_selection(collected, phase)
        if summary["collectionProcess"]["exit"] != 0 or summary["collectionProcess"]["timedOut"]:
            raise ValueError("collection_process")
        environment["NATIVE_COMPAT_STAGE"] = "run"
        summary["testProcess"] = execute(command + ["--junitxml=" + str(output / "junit.xml"), *SELECTIONS[phase]],
                                         output / "run.log", 180, environment)
        observed = json.loads((output / "run-plugin.json").read_bytes())
        summary["observed"] = closed(observed)
        junit_bytes = (output / "junit.xml").read_bytes()
        root = ET.fromstring(junit_bytes)
        cases = list(root.iter("testcase"))
        counts = {"tests": len(cases), "failed": sum(bool(x.findall("failure")) for x in cases),
                  "errors": sum(bool(x.findall("error")) for x in cases),
                  "skipped": sum(bool(x.findall("skipped")) for x in cases)}
        summary["junit"] = {"counts": counts, "sha256": digest(junit_bytes)}
        junit_nodes = sorted(x.get("classname", "").replace(".", "/") + ".py::" + x.get("name", "") for x in cases)
        summary["junit"]["identitiesMatch"] = junit_nodes == [row["node"] for row in items]
        summary["sourceAfter"] = verify()
        if validate_selection(observed, phase) != items:
            raise ValueError("selection_changed")
        if not summary["junit"]["identitiesMatch"]:
            raise ValueError("junit_identity")
        reports = observed["reports"]
        if len(reports) != len(items) * 3 or {x["node"] for x in reports} != {x["node"] for x in items}:
            raise ValueError("phase_incomplete")
        failures = set()
        for item in items:
            group = [row for row in reports if row["node"] == item["node"]]
            if len(group) != 3 or {row["when"] for row in group} != {"setup", "call", "teardown"}:
                raise ValueError("phase_incomplete")
            phases = {row["when"]: row for row in group}
            if any(phases[name]["outcome"] != "passed" for name in ("setup", "teardown")):
                raise ValueError("fixture_failure")
            if phases["call"]["outcome"] == "failed":
                failures.add(key(item["signature"]))
            elif phases["call"]["outcome"] != "passed":
                raise ValueError("unexpected_result")
        if counts != {"tests": len(items), "failed": len(failures), "errors": 0, "skipped": 0}:
            raise ValueError("junit_counts")
        actual = summary["testProcess"]["exit"]
        if (actual not in {0, 1} or observed["exit"] != actual or summary["testProcess"]["timedOut"]
                or (actual == 0) != (len(failures) == 0)):
            raise ValueError("process_result")
        expected_failures = {
            key(["expiry", "test_cached_access_token_accepts_equivalent_utc_expiry", "future-z"]),
            key(["expiry", "test_real_oauth_resolver_uses_unexpired_cache_before_refresh", "future-z"]),
            *(key(["retry", identity]) for identity in RETRY_IDS),
        } if phase == "regressions" else set()
        red_origins = {
            key(["expiry", "test_cached_access_token_accepts_equivalent_utc_expiry", "future-z"]):
                ("AssertionError", PINS[EXPIRY], 74),
            key(["expiry", "test_real_oauth_resolver_uses_unexpired_cache_before_refresh", "future-z"]):
                ("_RefreshReached", PINS[EXPIRY], 59),
            key(["retry", RETRY_IDS[0]]):
                ("AssertionError", PINS["tests/test_guard_sync_http_error_message.py"], 144),
            key(["retry", RETRY_IDS[1]]):
                ("AssertionError", PINS["tests/test_guard_sync_http_error_message.py"], 176),
        }
        observed_origins = {
            key(item["signature"]): tuple(row.get(field) for field in ("exceptionClass", "sourceBlob", "line"))
            for item in items for row in reports
            if row["node"] == item["node"] and row["when"] == "call" and row["outcome"] == "failed"
        }
        origins_match = phase != "regressions" or all(
            observed_origins.get(identity) == origin for identity, origin in red_origins.items()
        )
        summary["expectedFailureOriginsMatched"] = origins_match
        summary["expectedResultMatched"] = failures == expected_failures and origins_match
        summary["expectedRedObserved"] = phase == "regressions" and summary["expectedResultMatched"] and actual == 1
        summary["complete"] = True
        code = actual
        if phase != "prewarm" and not summary["expectedResultMatched"]:
            code = 2
    except BaseException as error:
        summary["complete"] = False
        summary["exceptionClass"] = type(error).__name__ if type(error).__name__ in {
            "ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "KeyError", "ParseError"
        } else "OtherException"
        if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in SAFE_CODES:
            summary["failureCode"] = error.args[0]
        code = 2
    finally:
        try:
            summary["sourceFinal"] = verify()
        except BaseException:
            summary["complete"] = False
            summary["expectedRedObserved"] = False
            summary["finalSourceValid"] = False
            code = 2
        summary["exit"] = code
        write(output / "summary.json", summary)
        print("NATIVE_COMPATIBILITY " + json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=tuple(SELECTIONS))
    raise SystemExit(prove(parser.parse_args().phase))
