"""Distinguish bridge refusal stages without replacing their real contracts."""

from __future__ import annotations

import hashlib
import json
import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_edge as bridge
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from scripts.native_slo_bridge_witness import native_bridge_witness


def _edge():
    receipt = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "source-request-1",
        "request_digest": "a" * 64,
        "harness": "omp",
        "event_name": "PostToolUse",
        "payload_kind": "source_file_ref",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "source_full_scan_allow",
        "workspace_bound": True,
        "source_ref_external_allowed": True,
        "reviewed_output_sha256": "b" * 64,
        "observe_mode": False,
        "deadline_budget_ms": 3000,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "omp",
        "event_name": "PostToolUse",
        "payload_kind": "source_file_ref",
        "receipt": receipt,
        "result": {
            key: receipt[key]
            for key in ("decision", "model_output_action", "policy_action", "reason_code", "reviewed_output_sha256")
        },
    }


@pytest.fixture
def real_bridge(tmp_path, monkeypatch):
    status = SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="c" * 64),
        capabilities=SimpleNamespace(features=("hook-envelope-v2", "native-resident-client-v1")),
    )
    captured = []

    def client(**kwargs):
        captured.append(kwargs)
        return json.dumps(_edge()).encode()

    monkeypatch.setattr(bridge, "native_runtime_status", lambda: status)
    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    monkeypatch.setattr(bridge, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(bridge, "native_record_resident_success", lambda *args, **kwargs: None)
    monkeypatch.setattr(bridge, "record_native_hook_result", lambda route, result: result)
    kwargs = dict(
        payload={"guard_source_ref": {"private": "never copied"}},
        harness="omp",
        event="PostToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=True,
        observe_mode=False,
        deadline=123.456,
        policy_snapshot={"generation": 1},
    )
    return status, kwargs, captured


def test_real_bridge_retains_result_receipt_and_exact_one_original_call(real_bridge):
    _, kwargs, captured = real_bridge
    expected = _edge()
    originals = {
        name: getattr(bridge, name)
        for name in (
            "native_runtime_status",
            "_encode_hook_envelope",
            "native_resident_client_request",
            "_decode_edge",
            "receipt_matches_edge",
            "native_record_resident_failure",
        )
    }
    with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        result = bridge.review_raw_hook_native(**kwargs)
    assert result == expected
    assert len(captured) == 1 and captured[0]["deadline_monotonic"] == kwargs["deadline"]
    assert json.loads(captured[0]["payload"])["raw_payload"] == kwargs["payload"]
    assert observed["calls_capped_at_two"] == dict(status=1, encode=1, client=1, decode=1, receipt=1, failure=0)
    assert observed["runtime_admitted"] is True and observed["encoded"] is True
    assert observed["client_output"] == "bytes" and observed["response_kind"] == "edge_object"
    assert observed["decode_accepted"] is observed["receipt_accepted"] is True
    assert observed["recorded_failure"] == "not_observed"
    assert all(getattr(bridge, name) is original for name, original in originals.items())
    assert "never copied" not in json.dumps(observed)


@pytest.mark.parametrize("stage", ["status", "snapshot", "generation", "encode"])
def test_pre_client_refusals_are_distinct_and_never_invent_a_client_attempt(real_bridge, monkeypatch, stage):
    status, kwargs, captured = real_bridge
    if stage == "status":
        status.available = False
        status.reason = "native_unavailable"
    elif stage == "snapshot":
        kwargs["policy_snapshot"] = None
    elif stage == "generation":
        kwargs["policy_snapshot"] = {"generation": True}
    else:
        kwargs["payload"] = {"not_json": object()}
    with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        assert bridge.review_raw_hook_native(**kwargs) is None
    assert captured == [] and observed["calls_capped_at_two"]["client"] == 0
    assert observed["client_output"] == "not_observed"
    if stage == "status":
        assert observed["runtime_admitted"] is False and observed["status_reason"] == "native_unavailable"
    elif stage == "snapshot":
        assert observed["snapshot"] == "missing"
    elif stage == "generation":
        assert observed["snapshot"] == "invalid_generation"
    else:
        assert observed["encoded"] is False and observed["calls_capped_at_two"]["encode"] == 1


@pytest.mark.parametrize("failure", ["client", "json", "error_object", "edge_shape", "receipt"])
def test_successful_transport_decode_and_receipt_failures_are_distinct(real_bridge, monkeypatch, failure):
    _, kwargs, _ = real_bridge
    value = _edge()
    if failure == "receipt":
        value["result"]["reviewed_output_sha256"] = "d" * 64
    if failure == "edge_shape":
        value["unexpected_private_field"] = "private"
    output = {
        "client": None,
        "json": b"invalid-private-json",
        "error_object": b'{"error":"snapshot_expired","retryable":false}',
    }.get(failure, json.dumps(value).encode())
    monkeypatch.setattr(bridge, "native_resident_client_request", lambda **kwargs: output)
    with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        assert bridge.review_raw_hook_native(**kwargs) is None
    assert observed["calls_capped_at_two"]["client"] == observed["calls_capped_at_two"]["failure"] == 1
    assert observed["recorded_failure"] == (
        "native_hook_edge_unavailable" if failure == "client" else "native_hook_edge_invalid_response"
    )
    assert observed["calls_capped_at_two"]["decode"] == (0 if failure in {"client", "json"} else 1)
    assert observed["client_output"] == ("none" if failure == "client" else "bytes")
    if failure == "error_object":
        assert observed["response_kind"] == "error_object" and observed["response_error"] == "snapshot_expired"
        assert observed["response_retryable"] is False and observed["receipt_accepted"] is None
    if failure == "receipt":
        assert observed["receipt_accepted"] is False and observed["decode_accepted"] is False
    if failure == "edge_shape":
        assert observed["response_kind"] == "edge_object" and observed["receipt_accepted"] is None
    assert "private" not in json.dumps(observed)


def test_other_threads_do_not_create_witness_calls_or_overwrite_current_call(real_bridge):
    _, kwargs, captured = real_bridge
    with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        thread = threading.Thread(target=lambda: bridge.review_raw_hook_native(**kwargs))
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert set(observed["calls_capped_at_two"].values()) == {0}
        assert bridge.review_raw_hook_native(**kwargs) == _edge()
    assert len(captured) == 2 and observed["calls_capped_at_two"]["client"] == 1


def test_exact_exception_and_all_original_bindings_restored(real_bridge, monkeypatch):
    _, kwargs, _ = real_bridge
    error = OSError("private failure text")

    def client(**kwargs):
        raise error

    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    original_decode = bridge._decode_edge
    with pytest.raises(OSError) as raised, native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        bridge.review_raw_hook_native(**kwargs)
    assert raised.value is error
    assert observed["calls_capped_at_two"]["client"] == 1 and observed["client_output"] == "not_observed"
    assert bridge.native_resident_client_request is client and bridge._decode_edge is original_decode
    assert "private failure" not in json.dumps(observed)


def test_counts_and_untrusted_error_fields_have_finite_projection(real_bridge, monkeypatch):
    monkeypatch.setattr(bridge, "_decode_edge", lambda payload: None)
    with native_bridge_witness(None) as observed:
        for _ in range(4):
            bridge._decode_edge({"error": "secret" * 10000, "retryable": "private"})
    assert observed["calls_capped_at_two"]["decode"] == 2
    assert observed["response_error"] == "other" and observed["response_retryable"] is None
    assert len(json.dumps(observed)) < 1024 and "secret" not in json.dumps(observed)


@pytest.mark.parametrize("failure", ["getattr", "features"])
def test_diagnostic_status_projection_failure_preserves_exact_original_return(real_bridge, monkeypatch, failure):
    status, _, _ = real_bridge

    class BrokenReason(SimpleNamespace):
        @property
        def reason(self):
            raise ValueError("private observer failure")

    if failure == "getattr":
        status = BrokenReason(**{key: value for key, value in vars(status).items() if key != "reason"})
    else:
        status.capabilities.features = None

    def original():
        return status

    monkeypatch.setattr(bridge, "native_runtime_status", original)
    with native_bridge_witness(None) as observed:
        for _ in range(3):
            assert bridge.native_runtime_status() is status
    assert bridge.native_runtime_status is original
    assert observed["observer_state"] == "partial" and observed["observer_error"] is True
    assert observed["observer_errors_capped_at_two"] == observed["calls_capped_at_two"]["status"] == 2
    assert observed["runtime_admitted"] is None
    assert "private observer" not in json.dumps(observed)


def test_projection_failure_does_not_replace_real_bridge_success(real_bridge, monkeypatch):
    status, kwargs, captured = real_bridge

    class BrokenReason(SimpleNamespace):
        @property
        def reason(self):
            raise RuntimeError("only the diagnostic reads this property")

    status = BrokenReason(**{key: value for key, value in vars(status).items() if key != "reason"})
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: status)
    with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
        assert bridge.review_raw_hook_native(**kwargs) == _edge()
    assert len(captured) == 1 and observed["receipt_accepted"] is observed["decode_accepted"] is True
    assert observed["observer_state"] == "partial" and observed["observer_errors_capped_at_two"] == 1


def _bridge_functions():
    return {
        name: getattr(bridge, name)
        for name in (
            "native_runtime_status",
            "_encode_hook_envelope",
            "native_resident_client_request",
            "_decode_edge",
            "receipt_matches_edge",
            "native_record_resident_failure",
        )
    }


def test_nested_witness_runs_unchanged_without_attributing_to_or_restoring_outer(real_bridge):
    _, kwargs, captured = real_bridge
    originals = _bridge_functions()
    with native_bridge_witness(kwargs["policy_snapshot"]) as outer:
        wrappers = _bridge_functions()
        with native_bridge_witness(kwargs["policy_snapshot"]) as inner:
            assert inner["observer_state"] == "overlap_unavailable"
            assert bridge.review_raw_hook_native(**kwargs) == _edge()
            assert _bridge_functions() == wrappers
        assert set(inner["calls_capped_at_two"].values()) == set(outer["calls_capped_at_two"].values()) == {0}
        assert _bridge_functions() == wrappers
        assert bridge.review_raw_hook_native(**kwargs) == _edge()
    assert len(captured) == 2 and outer["calls_capped_at_two"]["client"] == 1
    assert _bridge_functions() == originals


def test_concurrent_overlap_does_not_wait_or_restore_later_owner(real_bridge):
    _, kwargs, captured = real_bridge
    originals = _bridge_functions()
    entered = threading.Event()
    release = threading.Event()
    thread_observation = []
    thread_errors = []

    def concurrent():
        try:
            with native_bridge_witness(kwargs["policy_snapshot"]) as observed:
                thread_observation.append(observed)
                entered.set()
                assert release.wait(timeout=2)
                assert bridge.review_raw_hook_native(**kwargs) == _edge()
        except BaseException as error:
            thread_errors.append(error)

    thread = threading.Thread(target=concurrent)
    try:
        with native_bridge_witness(kwargs["policy_snapshot"]) as first:
            thread.start()
            assert entered.wait(timeout=2), "overlapping observer must not wait for the owner"
            assert thread_observation[0]["observer_state"] == "overlap_unavailable"
            assert bridge.review_raw_hook_native(**kwargs) == _edge()
        assert _bridge_functions() == originals
        with native_bridge_witness(kwargs["policy_snapshot"]) as second:
            second_wrappers = _bridge_functions()
            release.set()
            thread.join(timeout=2)
            assert not thread.is_alive() and thread_errors == []
            assert _bridge_functions() == second_wrappers
            assert set(second["calls_capped_at_two"].values()) == {0}
            assert bridge.review_raw_hook_native(**kwargs) == _edge()
    finally:
        release.set()
        thread.join(timeout=2)
    assert len(captured) == 3 and _bridge_functions() == originals
    assert first["calls_capped_at_two"]["client"] == second["calls_capped_at_two"]["client"] == 1
    assert set(thread_observation[0]["calls_capped_at_two"].values()) == {0}


def test_nested_exception_preserves_original_exception_and_releases_fixture_owner(real_bridge):
    _, kwargs, _ = real_bridge
    error = RuntimeError("original caller exception")
    originals = _bridge_functions()
    with (
        pytest.raises(RuntimeError) as raised,
        native_bridge_witness(None) as outer,
        native_bridge_witness(None) as inner,
    ):
        raise error
    assert raised.value is error and inner["observer_state"] == "overlap_unavailable"
    assert set(outer["calls_capped_at_two"].values()) == {0}
    assert _bridge_functions() == originals
    with native_bridge_witness(kwargs["policy_snapshot"]) as next_observer:
        assert next_observer["observer_state"] == "available"
        assert bridge.review_raw_hook_native(**kwargs) == _edge()
