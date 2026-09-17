from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from scripts.native_slo_faults import FaultFixture


def _session(tmp_path: Path) -> SimpleNamespace:
    home, workspace = tmp_path / "guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    snapshot = {
        "mode": "enforce",
        "effective_policy": {
            "default_action": "allow",
            "subprocess_action": "allow",
            "risk_actions": {"execution": "allow"},
        },
    }
    worker = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(current_snapshot=lambda: snapshot, is_ready=lambda: True),
        test_oracle=None,
        _review_raw_hook_native=lambda **_kwargs: {"result": {"decision": "allow"}},
    )
    return SimpleNamespace(
        command_authority_fixture={"verified_health": "protected"},
        root=tmp_path,
        guard_home=home,
        workspace=workspace,
        store=SimpleNamespace(add_approval_request=lambda **_kwargs: None),
        daemon=SimpleNamespace(
            _server=SimpleNamespace(
                hook_worker=worker, runtime_hook_scheduler=RuntimeHookScheduler(retained_bytes_limit=1024)
            )
        ),
    )


def test_unavailability_witness_is_not_asserted_until_injected_fault_runs(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_hook_edge

    original = native_hook_edge.native_resident_client_request
    session = _session(tmp_path)
    with FaultFixture(session, "unavailable") as fault:
        assert "native_request_unavailable" not in fault.result()["setup"]
        assert native_hook_edge.native_resident_client_request() is None
        assert fault.result()["setup"]["native_request_unavailable"] is True
        fault.before_case()
        assert "native_request_unavailable" not in fault.result()["setup"]
    assert native_hook_edge.native_resident_client_request is original


def test_byte_fault_exercises_real_scheduler_and_restores_limit(tmp_path: Path) -> None:
    session = _session(tmp_path)
    scheduler = session.daemon._server.runtime_hook_scheduler
    with FaultFixture(session, "queue_bytes") as fault:
        assert "byte_reservation_rejected" not in fault.result()["setup"]
        assert scheduler.reserve_bytes(payload_bytes=100, deadline=time.monotonic() + 1) == (
            None,
            "daemon_hook_queue_bytes",
        )
        assert fault.result()["setup"]["byte_reservation_rejected"] is True
    assert scheduler.stats()["retained_bytes_limit"] == 1024


def test_unknown_fault_has_no_fake_success(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="no witnessed implementation"), FaultFixture(_session(tmp_path), "unknown"):
        pass


@pytest.mark.parametrize("failure", ["client", "error_object", "private_error"])
def test_ordinary_corpus_observes_one_actual_bridge_refusal_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from codex_plugin_scanner.guard import native_hook_edge as bridge
    from codex_plugin_scanner.guard import native_resident_client
    from scripts.native_slo_contract import assert_privacy_safe

    session = _session(tmp_path)
    worker = session.daemon._server.hook_worker
    worker._review_raw_hook_native = bridge.review_raw_hook_native
    calls: list[dict[str, object]] = []
    code = {"value": None}

    def client(**kwargs: object) -> bytes | None:
        calls.append(kwargs)
        if failure == "client":
            code["value"] = "native_client_timed_out"
            return None
        return json.dumps(
            {"error": "snapshot_expired" if failure == "error_object" else "/private/fixture", "retryable": False}
        ).encode()

    monkeypatch.setattr(native_resident_client, "native_resident_client_failure_code", lambda: code["value"])
    monkeypatch.setattr(
        bridge,
        "native_runtime_status",
        lambda: SimpleNamespace(
            mode="auto",
            available=True,
            compatible=True,
            reason="native_ready",
            identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
            capabilities=SimpleNamespace(features=("hook-envelope-v2", "native-resident-client-v1")),
        ),
    )
    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    monkeypatch.setattr(bridge, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(bridge, "record_native_hook_result", lambda route, result: result)
    deadline = time.monotonic() + 3
    arguments = dict(
        payload={"tool_response": "/private/fixture"},
        harness="omp",
        event="PostToolUse",
        guard_home=session.guard_home,
        home_dir=tmp_path,
        cwd=session.workspace,
        source_ref_external_allowed=True,
        observe_mode=False,
        deadline=deadline,
        policy_snapshot={"generation": 1},
    )
    with FaultFixture(session, "normal") as fault:
        assert worker._review_raw_hook_native(**arguments) is None
        assert len(calls) == 1 and calls[0]["deadline_monotonic"] == deadline
        witness = fault.result()["native_bridge"]
        assert witness["observed_calls_capped_at_two"] == 1
        observed = witness["observations"][0]
        assert 0 <= observed["deadline_remaining_ms"] <= 3000
        assert observed["deadline_exhausted_after"] is False
        assert observed["client_failure_before"] == "not_recorded"
        assert observed["client_failure_after"] == (
            "native_client_timed_out" if failure == "client" else "not_recorded"
        )
        assert observed["bridge"]["calls_capped_at_two"]["client"] == 1
        assert observed["bridge"]["client_reply"] == ("none" if failure == "client" else "bytes")
        assert (
            observed["bridge"]["response_error"]
            == {"client": "not_observed", "error_object": "snapshot_expired", "private_error": "other"}[failure]
        )
        assert "/private/fixture" not in json.dumps(assert_privacy_safe(witness))
        fault.before_case()
        assert fault.result()["native_bridge"]["observations"] == []
    assert worker._review_raw_hook_native is bridge.review_raw_hook_native
    assert bridge.native_resident_client_request is client


def test_ordinary_corpus_witness_preserves_return_exception_and_bounded_count(tmp_path: Path) -> None:
    session = _session(tmp_path)
    worker = session.daemon._server.hook_worker
    original = worker._review_raw_hook_native
    with FaultFixture(session, "normal") as fault:
        for _ in range(3):
            assert worker._review_raw_hook_native() == {"result": {"decision": "allow"}}
        witness = fault.result()["native_bridge"]
        assert witness["observed_calls_capped_at_two"] == 2
        assert all(item["deadline_exhausted_after"] is None for item in witness["observations"])
    assert worker._review_raw_hook_native is original
    failure = RuntimeError("private original exception")

    def failed(**_kwargs: object) -> None:
        raise failure

    worker._review_raw_hook_native = failed
    with pytest.raises(RuntimeError) as captured, FaultFixture(session, "normal"):
        worker._review_raw_hook_native()
    assert captured.value is failure and worker._review_raw_hook_native is failed


def test_integrity_fault_observes_the_handler_local_import_without_faking_rejection(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime import hook_payload_reference

    original = hook_payload_reference.hook_payload_reference_size
    with FaultFixture(_session(tmp_path), "integrity") as fault:
        # The real HTTP handler resolves this import when it handles a request.
        from codex_plugin_scanner.guard.runtime.hook_payload_reference import hook_payload_reference_size

        assert "payload_reference_rejected" not in fault.result()["setup"]
        assert hook_payload_reference_size({"tool_output": "benign"}) is None
        assert "payload_reference_rejected" not in fault.result()["setup"]
        with pytest.raises(hook_payload_reference.HookPayloadReferenceError):
            hook_payload_reference_size({"guard_payload_ref": {"version": 1}})
        assert fault.result()["setup"]["payload_reference_rejected"] is True
    assert hook_payload_reference.hook_payload_reference_size is original


@pytest.mark.parametrize("harness", ["claude-code", "codex"])
def test_review_queue_fault_is_witnessed_by_real_persistence_call_and_restored(tmp_path: Path, harness: str) -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
    from codex_plugin_scanner.guard.store import GuardStore

    session = _session(tmp_path)
    session.store = GuardStore(session.guard_home)
    original = session.store.add_approval_request
    # This test starts at the already-decided review/queue boundary. It does not
    # fake a resident result or claim HTTP/installed-native qualification.
    arguments = {
        "harness": harness,
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git diff --output=/tmp/guard-qualification.diff README.md"},
        },
        "native_result": {
            "decision": "deny",
            "minimum_action": "review",
            "policy_action": "review",
            "reason_code": "native_command_review_required",
            "reason": "HOL Guard requires review before this action can execute.",
        },
        "workspace": session.workspace,
        "guard_home": session.guard_home,
    }
    with FaultFixture(session, "review_queue_failed") as fault:
        assert "approval_persistence_failed" not in fault.result()["setup"]
        response = pause_native_pre_tool_for_approval(session.store, **arguments)
        assert fault.result()["setup"]["approval_persistence_failed"] is True
        assert response["reason_code"] == "native_review_queue_failed"
        assert response["policy_action"] == "block"
        assert "approval_request_id" not in response and "approval_url" not in response
        assert session.store.list_approval_requests(status="pending") == []
        fault.before_case()
        assert "approval_persistence_failed" not in fault.result()["setup"]
    assert session.store.add_approval_request == original
    # Restoration must actually persist and retrieve an approval, rather than
    # merely restoring a function-shaped object.
    restored = pause_native_pre_tool_for_approval(session.store, **arguments)
    assert restored["policy_action"] == "review"
    request_id = restored["approval_request_id"]
    assert session.store.get_approval_request(request_id)["policy_action"] == "review"
