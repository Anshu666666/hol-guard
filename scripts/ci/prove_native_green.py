"""Validate fixed native expiry and retry behavior with original adjacent controls."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

BASE = "067ef53ae802a02ac1e4b85fb5d831bd0a7c8b6c"
BASE_TREE = "fc0959675cf3010ed59f8d17dc1d00c3d1e12df9"
HTTP = "tests/test_guard_sync_http_error_message.py"
EXECUTION = "tests/test_policy_execution_outcome.py"
EXPIRY = "tests/test_guard_oauth_cached_expiry_compatibility.py"
RETRY = "tests/test_guard_sync_retry_clock_isolation.py"
SCRIPT = "scripts/ci/prove_native_green.py"
PINS = {
    HTTP: "d143f526e60d51b438cac27692130efd7c84ea37",
    EXECUTION: "3a9f2b924d00e06249d3f539f675397fa8564f0f",
    EXPIRY: "b4d3f8554c99b0d45efc5e6efb3f702f41c3917d",
    RETRY: "6bc5c265d8df32b7d4cdcc0cb0a735cbf2170bbf",
    "src/codex_plugin_scanner/guard/runtime/runner.py": "042a1c4e8c3f857105ff4beeff6e2f5424b29470",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
}
CHANGED = {SCRIPT, ".github/workflows/ci.yml"}
SELECTIONS = {"validation": [EXPIRY, RETRY, HTTP, EXECUTION]}
HTTP_IDS = [
    "test_sync_http_error_message_reads_guard_cloud_err_field",
    "test_sync_http_error_message_prefers_guard_error_msg_over_top_level_error",
    "test_sync_http_error_message_reads_guard_error_msg_field",
    "test_sync_http_error_message_reads_legacy_error_field",
    "test_sync_http_error_message_falls_back_to_raw_body",
    "test_sync_http_error_message_falls_back_to_http_reason",
    "test_urlopen_json_retries_cloudflare_502_with_default_retry_after",
    "test_urlopen_retries_cloudflare_524_with_retry_after_header",
    "test_fetch_supply_chain_bundle_payload_raises_retryable_unavailable_on_guard_cloud_outage"
]
EXECUTION_IDS = {
    "test_actual_subprocess_completion_survives_receipt_redaction_and_transport": [
        "0-workspace-alpha",
        "7-workspace-alpha",
        "0-11111111-1111-4111-8111-111111111111"
    ],
    "test_dry_run_has_no_execution_outcome": [
        None
    ],
    "test_source_removed_after_real_child_completion_does_not_relabel_the_receipt": [
        None
    ],
    "test_completed_receipt_is_sync_visible_with_witness_at_first_insert_commit": [
        None
    ],
    "test_completed_receipt_envelope_and_event_roll_back_together": [
        None
    ],
    "test_failed_spawn_does_not_claim_completed_execution": [
        None
    ],
    "test_redaction_drops_malformed_completion_witness_as_a_unit": [
        "change0",
        "change1",
        "change2",
        "change3",
        "change4",
        "change5",
        "change6",
        "change7",
        "change8",
        "change9",
        "change10",
        "change11",
        "change12",
        "change13",
        "change14",
        "change15",
        "change16"
    ],
    "test_complete_witness_survives_typed_and_legacy_redaction_but_not_identity_cache": [
        None
    ]
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
    values = [["expiry", function, identity] for function, ids in EXPIRY_IDS.items() for identity in ids]
    values.extend([["retry", identity] for identity in RETRY_IDS])
    values.extend([["http", identity] for identity in HTTP_IDS])
    values.extend([["execution", function, index] for function, ids in EXECUTION_IDS.items() for index in range(len(ids))])
    return {key(value) for value in values}


def signature(item):
    name = getattr(item, "originalname", None) or item.name
    params = getattr(getattr(item, "callspec", None), "params", {})
    file = item.nodeid.split("::", 1)[0]
    if file == EXPIRY and name in EXPIRY_IDS:
        return ["expiry", name, item.callspec.id]
    if file == RETRY and name == "test_retry_fixtures_do_not_capture_an_unrelated_worker_sleep":
        return ["retry", params["case_name"]]
    if file == HTTP and name in HTTP_IDS and not params:
        return ["http", name]
    if file == EXECUTION and name in EXECUTION_IDS:
        identity = getattr(getattr(item, "callspec", None), "id", None)
        if identity in EXECUTION_IDS[name]:
            return ["execution", name, EXECUTION_IDS[name].index(identity)]
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
    if changed != CHANGED or len(original) != 4091 or len(current) != 4092:
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
    return {"head": head, "tree": tree, "baseFiles": 4091, "checkedFiles": 4092, "mismatches": 0}


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
               "testOnlyOverlays": [], "rawOutputPublished": False,
               "testThresholdsChanged": False, "expectedRedObserved": False,
               "timingScope": "Process seconds include setup/cleanup and are not an acceptance measurement."}
    code = 2
    try:
        if sys.version_info[:2] != (3, 10):
            raise ValueError("interpreter")
        summary["sourceBefore"] = verify()
        command = [sys.executable, "-m", "pytest", "-q", "--tb=short", "--color=no",
                   "-p", "scripts.ci.prove_native_green"]
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
        summary["expectedResultMatched"] = not failures and actual == 0
        summary["complete"] = True
        code = actual
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
