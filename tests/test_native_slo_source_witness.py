"""A delivered allow cannot stand in for actual complete source review."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts.native_slo_source_witness import source_review_witness

_DIGEST = "a" * 64
_REQUEST = {"guard_source_ref": {"output_sha256": _DIGEST}}


def _edge(**changes):
    return {
        "authority": "rust",
        "result": {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reason_code": "native_policy_warning",
            "reviewed_output_sha256": _DIGEST,
            **changes,
        },
    }


def test_complete_source_scan_is_witnessed_before_restoring_method() -> None:
    def original(**kwargs):
        return _edge()

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with source_review_witness(worker, _REQUEST):
        worker._review_raw_hook_native()
    assert worker._review_raw_hook_native is original


@pytest.mark.parametrize(
    "result",
    [
        _edge(reason_code="no_output_to_review", reviewed_output_sha256=None),
        _edge(reviewed_output_sha256="b" * 64),
        _edge(decision="deny"),
        _edge(model_output_action="not_applicable"),
        {"authority": "python", "result": _edge()["result"]},
        None,
    ],
)
def test_allowed_no_output_wrong_digest_or_non_native_edge_never_qualifies(result) -> None:
    def original(**kwargs):
        return result

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with (
        pytest.raises(RuntimeError, match="one complete native content review"),
        source_review_witness(worker, _REQUEST),
    ):
        worker._review_raw_hook_native()
    assert worker._review_raw_hook_native is original


@pytest.mark.parametrize("count", [0, 2, 3])
def test_missing_or_multiple_native_decisions_cannot_qualify(count) -> None:
    worker = SimpleNamespace(_review_raw_hook_native=lambda **kwargs: _edge())
    with (
        pytest.raises(RuntimeError, match="one complete native content review"),
        source_review_witness(worker, _REQUEST),
    ):
        for _ in range(count):
            worker._review_raw_hook_native()


def test_non_source_work_does_not_change_native_method() -> None:
    worker = object()
    with source_review_witness(worker, {"tool_response": []}):
        pass


def test_transport_exception_is_preserved_and_wrapper_retired() -> None:
    def original(**kwargs):
        return _edge()

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with pytest.raises(OSError, match="transport"), source_review_witness(worker, _REQUEST):
        raise OSError("transport")
    assert worker._review_raw_hook_native is original


def _failure_diagnostic(worker, request=_REQUEST, **context):
    with pytest.raises(RuntimeError) as raised, source_review_witness(worker, request, **context):
        worker._review_raw_hook_native()
    prefix = "source SLO did not witness one complete native content review: "
    message = str(raised.value)
    assert message.startswith(prefix)
    assert len(message) < 2_048
    return json.loads(message.removeprefix(prefix)), message


def test_failed_native_review_retains_exact_fixed_reason_and_case_scope(monkeypatch) -> None:
    from scripts import native_slo_source_witness as witness

    monkeypatch.setattr(witness, "_client_failure", lambda: "not_recorded")
    worker = SimpleNamespace(
        _review_raw_hook_native=lambda **kwargs: _edge(
            decision="deny", model_output_action="block", reason_code="no_output_to_review", reviewed_output_sha256=None
        )
    )
    diagnostic, _ = _failure_diagnostic(worker, harness="claude-code", size_class="1m")
    elapsed = diagnostic["observations"][0].pop("native_elapsed_ms")
    bridge = diagnostic["observations"][0].pop("bridge")
    assert bridge["scope"] == "original_calls_current_thread"
    assert set(bridge["calls_capped_at_two"].values()) == {0}
    assert type(elapsed) is int and 0 <= elapsed <= 10_000
    assert diagnostic == {
        "harness": "claude-code",
        "size_class": "1m",
        "client_failure_scope": "thread_context_before_after",
        "observed_calls_capped_at_two": 1,
        "observations": [
            {
                "rust_authority": True,
                "decision": "deny",
                "model_output_action": "block",
                "reason_code": "no_output_to_review",
                "reviewed_digest_present": False,
                "reviewed_digest_matches": False,
                "deadline_remaining_ms": None,
                "client_failure_before": "not_recorded",
                "client_failure_after": "not_recorded",
            }
        ],
    }


def test_diagnostics_never_echo_arbitrary_reason_authority_digest_or_context() -> None:
    private = "private-path-and-secret" * 2_000
    worker = SimpleNamespace(
        _review_raw_hook_native=lambda **kwargs: {
            "authority": private,
            "result": {
                "decision": private,
                "model_output_action": private,
                "reason_code": private,
                "reviewed_output_sha256": "b" * 64,
            },
        }
    )
    diagnostic, message = _failure_diagnostic(worker, harness=private, size_class=private)
    assert "private-path" not in message and "b" * 64 not in message and _DIGEST not in message
    assert diagnostic["harness"] == diagnostic["size_class"] == "other"
    observation = diagnostic["observations"][0]
    assert observation["decision"] == observation["model_output_action"] == observation["reason_code"] == "other"
    assert observation["reviewed_digest_present"] is True and observation["reviewed_digest_matches"] is False


def test_missing_native_call_diagnostic_is_distinct_from_failed_native_result() -> None:
    worker = SimpleNamespace(_review_raw_hook_native=lambda **kwargs: _edge())
    with (
        pytest.raises(RuntimeError) as raised,
        source_review_witness(worker, _REQUEST, harness="codex", size_class="250k"),
    ):
        pass
    assert '"observed_calls_capped_at_two":0' in str(raised.value)
    assert '"observations":[]' in str(raised.value)


def test_failure_diagnostic_preserves_owned_budget_without_refreshing_it(monkeypatch) -> None:
    from scripts import native_slo_source_witness as witness

    clock = iter([20.0, 20.75])
    monkeypatch.setattr(witness.time, "monotonic", lambda: next(clock))
    worker = SimpleNamespace(
        _review_raw_hook_native=lambda **kwargs: _edge(
            decision="deny", model_output_action="block", reason_code="no_output_to_review", reviewed_output_sha256=None
        )
    )
    with (
        pytest.raises(RuntimeError) as raised,
        source_review_witness(worker, _REQUEST, harness="claude-code", size_class="5m"),
    ):
        worker._review_raw_hook_native(deadline=20.5)
    diagnostic = json.loads(str(raised.value).split(": ", 1)[1])
    assert diagnostic["observations"][0]["deadline_remaining_ms"] == 500
    assert diagnostic["observations"][0]["native_elapsed_ms"] == 750


def test_client_context_failure_is_retained_without_inventing_a_new_call(monkeypatch) -> None:
    from scripts import native_slo_source_witness as witness

    values = iter(["native_client_stream_failed", "native_client_stream_failed"])
    monkeypatch.setattr(witness.native_resident_client, "native_resident_client_failure_code", lambda: next(values))
    worker = SimpleNamespace(_review_raw_hook_native=lambda **kwargs: None)
    diagnostic, _ = _failure_diagnostic(worker)
    assert diagnostic["client_failure_scope"] == "thread_context_before_after"
    observed = diagnostic["observations"][0]
    assert observed["client_failure_before"] == observed["client_failure_after"] == "native_client_stream_failed"
    assert observed["rust_authority"] is False


@pytest.mark.parametrize(
    "code", ["native_client_timed_out", "native_resident_authentication_failed", None, "private-value" * 1000]
)
def test_client_context_projection_is_closed_and_restores_original_worker(monkeypatch, code) -> None:
    from scripts import native_slo_source_witness as witness

    monkeypatch.setattr(witness.native_resident_client, "native_resident_client_failure_code", lambda: code)

    def original(**kwargs):
        return None

    worker = SimpleNamespace(_review_raw_hook_native=original)
    diagnostic, message = _failure_diagnostic(worker)
    observed = diagnostic["observations"][0]
    expected = "not_recorded" if code is None else code if code in witness._CLIENT_FAILURE_CODES else "other"
    assert observed["client_failure_before"] == observed["client_failure_after"] == expected
    assert "private-value" not in message
    assert worker._review_raw_hook_native is original
