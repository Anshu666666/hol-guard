from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import native_slo_stream_diagnostic as diagnostic
from scripts.ci import run_native_stream_phase_diagnostic as driver


def frame() -> dict:
    report = {
        "schema": "hol-guard.resident-stream-request-diagnostic.v1",
        "scope": "explicit_persistent_client_original_frame_operation",
        "operation_succeeded": False,
        "operation_error": "native_resident_live_request_failed",
        "operation_elapsed_us": 301_000,
        "deadline_budget_ms": 2700,
        "payload_bytes": 7,
        "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
        "events": [
            {
                "phase": "authenticate",
                "started_us": 50,
                "duration_us": 250_000,
                "succeeded": False,
                "error_code": "native_client_frame_read_failed",
                "retryable_teardown": False,
                "io_failure": {"operation": "stream_read", "kind": "would_block", "os_code": 35},
            }
        ],
        "maximum_events": 16,
        "dropped_events": 0,
        "original_fatal_code": "native_client_frame_read_failed",
        "unassigned_io_failure": None,
        "detail_incomplete": False,
        "original_operation_result_preserved": True,
        "headline_timing_eligible": False,
        "qualification": False,
        "retries_added": False,
        "deadlines_changed": False,
    }
    return {
        "schema": "hol-guard.resident-stream-diagnostic-frame.v1",
        "frame_sequence": 0,
        "maximum_frames": 128,
        "response_bytes": 8,
        "response_sha256": hashlib.sha256(b"response").hexdigest(),
        "stdout_frame_written": True,
        "report": report,
    }


def capture_with_frame(tmp_path: Path, value: dict | None = None) -> diagnostic.StreamCapture:
    capture = diagnostic.StreamCapture(tmp_path)
    value = frame() if value is None else value
    capture.processes.append(
        {
            "index": 0,
            "raw": bytearray(json.dumps(value).encode() + b"\n"),
            "eof": True,
            "reader_failed": False,
            "dropped_bytes": 0,
            "process": SimpleNamespace(poll=lambda: 0),
        }
    )
    capture.calls.append(
        {
            "process_index": 0,
            "payload_bytes": 7,
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "response_bytes": 8,
            "response_sha256": hashlib.sha256(b"response").hexdigest(),
        }
    )
    return capture


def test_fixed_leaf_and_original_failed_result_round_trip_with_exact_bindings(tmp_path: Path) -> None:
    value = frame()
    assert diagnostic.parse_record(json.dumps(value).encode()) == value
    report = capture_with_frame(tmp_path, value).report()
    assert report["observation_complete"] is True
    assert report["qualification"] is False
    assert report["processes"][0]["records"][0]["report"]["operation_error"] == "native_resident_live_request_failed"
    assert report["missing_bound_frames"] == report["extra_bound_frames"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(secret="private"),
        lambda v: v.update(frame_sequence=True),
        lambda v: v.update(maximum_frames=129),
        lambda v: v["report"].update(qualification=True),
        lambda v: v["report"].update(deadlines_changed=True),
        lambda v: v["report"].update(payload_sha256="private-path"),
        lambda v: v["report"].update(operation_error="raw-exception"),
        lambda v: v["report"].update(events=[{}] * 17),
        lambda v: v["report"]["events"][0].update(phase="raw-phase"),
        lambda v: v["report"]["events"][0]["io_failure"].update(operation="raw-operation"),
        lambda v: v["report"]["events"][0]["io_failure"].update(os_code=True),
    ],
)
def test_unknown_or_unbounded_native_values_are_rejected(mutation) -> None:
    value = frame()
    mutation(value)
    with pytest.raises((ValueError, TypeError)):
        diagnostic.parse_record(json.dumps(value).encode())


@pytest.mark.parametrize("operation", sorted(diagnostic._IO_OPERATIONS))
def test_read_write_setter_and_flush_labels_remain_distinct(operation: str) -> None:
    value = frame()
    value["report"]["events"][0]["io_failure"]["operation"] = operation
    assert (
        diagnostic.parse_record(json.dumps(value).encode())["report"]["events"][0]["io_failure"]["operation"]
        == operation
    )


def test_missing_extra_duplicate_and_partial_frames_remain_incomplete(tmp_path: Path) -> None:
    capture = capture_with_frame(tmp_path)
    capture.calls[0]["payload_sha256"] = "0" * 64
    report = capture.report()
    assert report["missing_bound_frames"] == report["extra_bound_frames"] == 1
    assert report["observation_complete"] is False
    capture = capture_with_frame(tmp_path)
    capture.processes[0]["raw"] *= 2
    assert capture.report()["invalid_records"] == 1
    capture = capture_with_frame(tmp_path)
    capture.processes[0]["raw"] = capture.processes[0]["raw"][:-1]
    assert capture.report()["invalid_records"] == 1


def test_export_limit_and_unobserved_lease_do_not_claim_complete(tmp_path: Path) -> None:
    capture = capture_with_frame(tmp_path)
    limit = {
        "schema": "hol-guard.resident-stream-diagnostic-limit.v1",
        "maximum_frames": 128,
        "dropped_frame_reports": True,
    }
    capture.processes[0]["raw"].extend(json.dumps(limit).encode() + b"\n")
    assert capture.report()["observation_complete"] is False
    value = frame()
    value["report"] = None
    report = capture_with_frame(tmp_path, value).report()
    assert report["missing_request_reports"] == 1
    assert report["observation_complete"] is False


@pytest.mark.parametrize("raises", [False, True])
def test_recording_failure_preserves_original_call_identity_deadline_and_exception(
    tmp_path: Path, monkeypatch, raises: bool
) -> None:
    capture = diagnostic.StreamCapture(tmp_path)
    client = SimpleNamespace(_executable=tmp_path, _process=None)
    payload, response = b"original-payload", b"original-response"
    original_error = RuntimeError("original")
    calls = []

    def operation(actual_client, actual_payload, *, deadline_monotonic):
        calls.append((actual_client, actual_payload, deadline_monotonic))
        if raises:
            raise original_error
        return response

    capture.original_request = operation
    monkeypatch.setattr(diagnostic.hashlib, "sha256", lambda _: (_ for _ in ()).throw(ValueError("diagnostic")))
    if raises:
        with pytest.raises(RuntimeError) as caught:
            capture.request(client, payload, deadline_monotonic=123.456)
        assert caught.value is original_error
    else:
        assert capture.request(client, payload, deadline_monotonic=123.456) is response
    assert len(calls) == 1 and calls[0][0] is client and calls[0][1] is payload and calls[0][2] == 123.456
    assert capture.recording_failures == 1
    assert capture.report()["observation_complete"] is False


def test_partial_patch_installation_restores_original_module(tmp_path: Path, monkeypatch) -> None:
    capture = diagnostic.StreamCapture(tmp_path)
    original = diagnostic.transport.subprocess
    real_enter = capture.stack.enter_context
    entered = 0

    def enter(context):
        nonlocal entered
        entered += 1
        if entered == 2:
            raise RuntimeError("patch failure")
        return real_enter(context)

    monkeypatch.setattr(capture.stack, "enter_context", enter)
    with pytest.raises(RuntimeError):
        capture.__enter__()
    assert diagnostic.transport.subprocess is original


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX executable fixture; native Windows driver has separate controls"
)
def test_actual_child_stderr_is_drained_beyond_retained_bound_without_blocking_stdout(tmp_path: Path) -> None:
    executable = tmp_path / "native-fixture"
    executable.write_text(
        f"#!{sys.executable}\nimport os\nfor _ in range(512): os.write(2,b'x'*4096)\nos.write(1,b'original-response')\n"
    )
    executable.chmod(0o700)
    with diagnostic.StreamCapture(executable) as capture:
        process = capture.spawn(
            (str(executable), "resident-client-stream", "--stdin", str(tmp_path)),
            {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL},
        )
        assert process.stdout is not None and process.stdin is not None
        process.stdin.close()
        try:
            process.wait(timeout=5)
            assert process.stdout.read() == b"original-response"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
    report = capture.report()
    assert report["processes"][0]["retained_stderr_bytes"] == diagnostic.MAX_PROCESS_BYTES
    assert report["dropped_stderr_bytes"] == 2 * 1024 * 1024 - diagnostic.MAX_PROCESS_BYTES
    assert report["processes"][0]["stderr_eof"] is True
    assert report["processes"][0]["child_reaped"] is True
    assert report["observation_complete"] is False


def fake_installed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(driver.sys, "platform", "darwin")
    monkeypatch.setattr(driver.sys, "flags", SimpleNamespace(isolated=1))
    for name in tuple(os.environ):
        if name.startswith(("HOL_GUARD_", "GUARD_", "PYTEST_")) or name == "PYTHONPATH":
            monkeypatch.delenv(name)
    module = tmp_path / "site-packages/codex_plugin_scanner/guard/native_runtime.py"
    monkeypatch.setattr(driver.runtime, "__file__", str(module))
    monkeypatch.setattr(
        driver.importlib.metadata, "distribution", lambda _: SimpleNamespace(locate_file=lambda _: module)
    )
    identity = SimpleNamespace(path=tmp_path, sha256="a" * 64, size=100)
    capabilities = SimpleNamespace(build_sha="b" * 40, target="test", rule_digest="c" * 64)
    monkeypatch.setattr(
        driver.runtime,
        "native_runtime_status",
        lambda: SimpleNamespace(
            mode="auto",
            available=True,
            compatible=True,
            reason="native_ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    monkeypatch.setattr(driver.runtime, "_validate_binary", lambda _: identity)


def test_cleanup_and_identity_failure_do_not_erase_original_workload_failure(tmp_path: Path, monkeypatch) -> None:
    fake_installed(monkeypatch, tmp_path)
    parameters = []

    def workload(runtime, **kwargs):
        parameters.append(kwargs)
        monkeypatch.setattr(driver.runtime, "_validate_binary", lambda _: (_ for _ in ()).throw(RuntimeError("after")))
        raise RuntimeError("original")

    class Capture:
        def __init__(self, runtime):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            raise RuntimeError("cleanup")

        def report(self):
            return {"observation_complete": True, "retained": "fixed-failure"}

    monkeypatch.setattr(driver, "run_slo", workload)
    monkeypatch.setattr(driver, "StreamCapture", Capture)
    monkeypatch.setattr(driver, "failure_evidence", lambda error: {"reason": "original-fixed-code"})
    result = driver.run_probe("b" * 40)
    assert result["original_workload_failure"] == {"reason": "original-fixed-code"}
    assert result["capture"]["retained"] == "fixed-failure"
    assert result["capture_cleanup_failed"] is result["identity_revalidation_failed"] is True
    assert result["observation_complete"] is False
    assert parameters == [
        {
            "warm_iterations": 2,
            "cold_iterations": 2,
            "recovery_iterations": 2,
            "readiness_samples": 2,
            "include_capacity": True,
            "launcher_iterations": 2,
        }
    ]


def test_workflow_is_separately_bound_and_runs_both_original_mac_controls() -> None:
    root = Path(__file__).resolve().parents[1]
    path = Path(
        os.environ.get(
            "NATIVE_STREAM_WORKFLOW_PATH", root / ".github/workflows/native-resident-stream-phase-diagnostics.yml"
        )
    )
    text = path.read_text()
    workflow = yaml.safe_load(text)
    assert "push" in workflow["on"]
    job = workflow["jobs"]["macos-stream-phase"]
    assert {item["runner"] for item in job["strategy"]["matrix"]["include"]} == {"macos-15", "macos-15-intel"}
    assert "resident_startup_diagnostic -- --test-threads=1" in text
    assert "--features diagnostic-phases resident_client -- --test-threads=1" in text
    assert "NATIVE_STREAM_WORKFLOW_PATH=../workflow-src/" in text
    assert "ref: ${{ github.sha }}" in text
    for step in job["steps"]:
        if "uses" in step:
            assert len(step["uses"].rsplit("@", 1)[1]) == 40
    assert "--features diagnostic-phases" in text and "qualification" in text
    assert "run_native_stream_phase_diagnostic.py" in text
