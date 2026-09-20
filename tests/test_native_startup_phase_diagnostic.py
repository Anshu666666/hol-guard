"""Controls for the private Mac startup diagnostic driver, without a Mac workload."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import run_native_startup_phase_diagnostic as driver

PAYLOAD = b'{"operation":"policy_snapshot_push","deadline_budget_ms":2000}'


def native_record() -> dict:
    return {
        "schema": "hol-guard.resident-startup-diagnostic.v2",
        "scope": "single_explicit_managed_client_operation",
        "operation_succeeded": False,
        "operation_error": "native_resident_live_request_failed",
        "operation_elapsed_us": 500,
        "deadline_budget_ms": 2000,
        "payload_bytes": len(PAYLOAD),
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "events": [
            {
                "phase": "authenticate",
                "started_us": 10,
                "duration_us": 490,
                "succeeded": False,
                "error_code": "native_client_frame_read_failed",
                "retryable_teardown": False,
                "io_failure": {"operation": "unspecified", "kind": "unexpected_eof", "os_code": None},
            }
        ],
        "maximum_events": 16,
        "dropped_events": 0,
        "original_fatal_code": "native_client_frame_read_failed",
        "detail_incomplete": False,
        "original_operation_result_preserved": True,
        "headline_timing_eligible": False,
        "qualification": False,
        "retries_added": False,
        "deadlines_changed": False,
    }


def test_diagnostic_retains_leaf_phase_and_exact_payload_reference() -> None:
    record = native_record()
    stderr = json.dumps(record).encode() + b"\nnative_resident_live_request_failed\n"
    assert driver.parse_diagnostic(stderr, PAYLOAD) == record


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(payload="private secret"),
        lambda value: value.update(deadline_budget_ms=3000),
        lambda value: value.update(payload_sha256="0" * 64),
        lambda value: value.update(events=value["events"] * 17),
        lambda value: value.update(qualification=True),
        lambda value: value["events"][0].update(error_code="private secret"),
        lambda value: value["events"][0]["io_failure"].update(path="private path"),
        lambda value: value["events"][0].update(phase=[]),
        lambda value: value["events"][0]["io_failure"].update(kind={}),
        lambda value: value["events"][0]["io_failure"].update(operation="private operation"),
    ],
)
def test_diagnostic_rejects_unbounded_unbound_or_unknown_evidence(mutation) -> None:
    record = native_record()
    mutation(record)
    with pytest.raises(ValueError):
        driver.parse_diagnostic(json.dumps(record).encode(), PAYLOAD)


def test_duplicate_native_report_is_rejected() -> None:
    encoded = json.dumps(native_record()).encode()
    with pytest.raises(ValueError, match="diagnostic_record_count"):
        driver.parse_diagnostic(encoded + b"\n" + encoded, PAYLOAD)


def test_bounded_child_drains_both_streams_and_forwards_exact_input() -> None:
    payload = bytes(range(256)) * 16
    code = "import os,sys; p=sys.stdin.buffer.read(); os.write(2,b'x'*8192); sys.stdout.buffer.write(p)"
    result = driver.run_bounded([sys.executable, "-c", code], payload, dict(os.environ), time.monotonic() + 2)
    assert result.stdout == payload
    assert result.stderr == b"x" * 8192
    assert result.returncode == 0 and result.reaped and not result.timed_out and not result.overflow


def test_expired_absolute_budget_never_spawns(monkeypatch) -> None:
    monkeypatch.setattr(driver.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("expired spawn"))
    result = driver.run_bounded([sys.executable], b"", {}, time.monotonic() - 1)
    assert result.timed_out and result.reaped and result.returncode is None


def test_live_child_deadline_is_not_reset_after_spawn() -> None:
    started = time.monotonic()
    result = driver.run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], b"", {}, started + 0.1)
    assert result.timed_out and result.reaped
    assert time.monotonic() - started < 1.5


def test_excess_stderr_stops_and_reaps_exact_child() -> None:
    code = "import os; os.write(2,b'x'*100000)"
    result = driver.run_bounded([sys.executable, "-c", code], b"", {}, time.monotonic() + 2)
    assert result.overflow and result.reaped and len(result.stderr) == driver._MAX_STDERR


def test_first_payload_uses_real_helper_sequence_once_without_start_or_retry(monkeypatch, tmp_path: Path) -> None:
    calls = []
    identity = SimpleNamespace(sha256="a" * 64)
    capabilities = SimpleNamespace(rule_digest="b" * 64)
    config, extensions, key = {"mode": "prompt"}, {"authority": "actual context"}, b"private-key"
    context = (identity, capabilities, key, config, extensions, object())
    publisher = SimpleNamespace(
        guard_home=tmp_path,
        _wall_clock=lambda: 50.0,
        _monotonic_clock=lambda: 60.0,
        _provision_verifier_key=lambda: calls.append("provision"),
        _publication_context=lambda: calls.append("context") or context,
        start=lambda: pytest.fail("publisher thread must not start"),
    )
    snapshot = {"generation": 1}

    def generate(**kwargs):
        calls.append("generate")
        assert kwargs == dict(
            config=config,
            guard_home=tmp_path,
            runtime_identity=identity.sha256,
            rule_digest=capabilities.rule_digest,
            policy_integrity_key=key,
            issued_at_ms=50000,
            deadline_monotonic=62.0,
            renew_after_generation=None,
            command_extensions=extensions,
        )
        return snapshot

    monkeypatch.setattr(driver, "native_policy_snapshot_v3", generate)
    monkeypatch.setattr(
        driver,
        "_policy_snapshot_push_bytes_v3",
        lambda value: calls.append("encode") or PAYLOAD if value is snapshot else pytest.fail("replaced snapshot"),
    )
    assert driver.first_payload(publisher) == (PAYLOAD, snapshot)
    assert calls == ["provision", "context", "generate", "encode"]


def test_no_state_and_stop_unavailable_do_not_claim_containment(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        driver,
        "run_bounded",
        lambda *_args: driver.ProcessResult(b"", b"native_resident_stop_unavailable\n", 2, False, False, True),
    )
    result = driver.cleanup(Path(sys.executable), tmp_path, {})
    assert result["resident_state_absent"] is True
    assert result["authenticated_stop_succeeded"] is False
    assert result["contained"] is False


def test_successful_stop_requires_state_retirement(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(driver, "run_bounded", lambda *_args: driver.ProcessResult(b"", b"", 0, False, False, True))
    state = tmp_path / "native-runtime" / "resident-v3-test" / "generation-1.json"
    state.parent.mkdir(parents=True)
    state.write_text("{}")
    assert driver.cleanup(Path(sys.executable), tmp_path, {})["contained"] is False
    state.unlink()
    assert driver.cleanup(Path(sys.executable), tmp_path, {})["contained"] is True


@pytest.mark.parametrize("failure_stage", ["close", "payload", "identity", "temporary"])
def test_publisher_failure_cannot_skip_cleanup_or_erase_native_evidence(
    monkeypatch, tmp_path: Path, failure_stage
) -> None:
    expected_module = tmp_path / "site-packages" / "native_runtime.py"
    identity = SimpleNamespace(path=Path(sys.executable), sha256="a" * 64, size=1)
    capabilities = SimpleNamespace(build_sha="b" * 40, target="test", rule_digest="c" * 64)
    status = SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=identity,
        capabilities=capabilities,
    )
    monkeypatch.setattr(driver, "sys", SimpleNamespace(platform="darwin", flags=SimpleNamespace(isolated=True)))
    monkeypatch.setattr(driver.os, "environ", {})
    monkeypatch.setattr(
        driver.importlib.metadata,
        "distribution",
        lambda _name: SimpleNamespace(locate_file=lambda _path: expected_module),
    )
    monkeypatch.setattr(driver.runtime, "__file__", str(expected_module))
    monkeypatch.setattr(driver.runtime, "native_runtime_status", lambda: status)
    identity_checks = 0

    def validate_identity(_path):
        nonlocal identity_checks
        identity_checks += 1
        if identity_checks > 1 and failure_stage == "identity":
            raise RuntimeError("private identity failure must not replace evidence")
        return identity

    monkeypatch.setattr(driver.runtime, "_validate_binary", validate_identity)
    monkeypatch.setattr(driver.runtime, "_isolated_environment", lambda: {})
    monkeypatch.setattr(driver, "GuardStore", lambda _home: object())
    calls = []

    def fail():
        raise RuntimeError("private exception text must not be retained")

    monkeypatch.setattr(
        driver,
        "NativePolicySnapshotPublisher",
        lambda **_kwargs: SimpleNamespace(close=fail if failure_stage == "close" else lambda: None),
    )
    if failure_stage == "temporary":
        original_cleanup = driver.tempfile.TemporaryDirectory.cleanup

        def fail_after_cleanup(temporary):
            original_cleanup(temporary)
            fail()

        monkeypatch.setattr(driver.tempfile.TemporaryDirectory, "cleanup", fail_after_cleanup)
    monkeypatch.setattr(
        driver,
        "first_payload",
        lambda _publisher: (
            fail() if failure_stage == "payload" else (PAYLOAD, {"generation": 1, "policy_digest": "d" * 64})
        ),
    )
    monkeypatch.setattr(
        driver,
        "run_bounded",
        lambda *_args: driver.ProcessResult(b"", json.dumps(native_record()).encode(), 2, False, False, True),
    )
    monkeypatch.setattr(driver, "cleanup", lambda *_args: calls.append("cleanup") or {"contained": True})
    report = driver.run_probe("b" * 40)
    assert calls == ["cleanup"]
    assert report["publisher_close_failed"] is (failure_stage == "close")
    assert report["identity_revalidation_failed"] is (failure_stage == "identity")
    assert report["temporary_cleanup_failed"] is (failure_stage == "temporary")
    assert not report["observation_complete"]
    assert "private exception" not in json.dumps(report)
    if failure_stage != "payload":
        assert report["native"] == native_record()
    else:
        assert report["publication_requests"] == 0


def test_workflow_is_pinned_diagnostic_only_and_uses_isolated_driver() -> None:
    import yaml

    path = Path(
        os.environ.get(
            "NATIVE_STARTUP_WORKFLOW_PATH",
            str(Path(__file__).parents[1] / ".github/workflows/native-resident-startup-phase-diagnostics.yml"),
        )
    )
    workflow = yaml.safe_load(path.read_text())
    expected_branch = os.environ.get("DIAGNOSTIC_DRIVER_BRANCH", "PENDING_DIAGNOSTIC_DRIVER_BRANCH")
    assert expected_branch and not any(character in expected_branch for character in "*?[")
    assert workflow["on"]["push"] == {
        "branches": [expected_branch],
        "paths": [".github/workflows/native-resident-startup-phase-diagnostics.yml"],
    }
    assert "workflow_dispatch" in workflow["on"]
    job = workflow["jobs"]["macos-startup-phase"]
    assert {entry["runner"] for entry in job["strategy"]["matrix"]["include"]} == {"macos-15", "macos-15-intel"}
    for step in job["steps"]:
        if "uses" in step:
            assert len(step["uses"].split("@")[1]) == 40
    source = path.read_text()
    assert os.environ.get("DIAGNOSTIC_SOURCE_SHA", "PENDING_DIAGNOSTIC_SOURCE_SHA") in source
    assert os.environ.get("DIAGNOSTIC_SOURCE_TREE", "PENDING_DIAGNOSTIC_SOURCE_TREE") in source
    assert "--features diagnostic-phases" in source
    assert "'.venv/bin/python', '-I', 'scripts/ci/run_native_startup_phase_diagnostic.py'" in source
    assert "baseline-src" not in source
