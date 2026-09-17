from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts import native_probe_corpus_witness as witness_module


@pytest.mark.parametrize(
    "reason",
    ["native_degraded_emergency_safe", "native_policy_warning", "output_scan_allow", "native_exact_safe_command"],
)
def test_delivery_projection_preserves_known_reason_without_claiming_native_route(reason, capsys):
    witness = witness_module.InstalledCorpusDeliveryWitness()
    response = {"decision": "allow", "continue": True, "reason_code": reason, "model_output_action": "allow_original"}
    witness.record("claude-code", "PostToolUse", response, allowed=True)
    report = witness.report(expected=1, worker_stats={"routes": {"native_fail_safe": 1}})
    assert report["rows"][0]["reason_code"] == reason
    assert report["rows"][0]["delivered_allowed"] is True
    assert report["aggregate_routes"]["native_fail_safe"] == 1
    assert report["aggregate_routes"]["native_resident"] is None
    assert report["per_request_native_route_proven"] is False
    assert report["cause_proven"] is False
    assert "route" not in report["rows"][0]
    assert response == {
        "decision": "allow",
        "continue": True,
        "reason_code": reason,
        "model_output_action": "allow_original",
    }
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("replace_with_reviewed_excerpt", "replace_with_reviewed_excerpt"),
        ("not_applicable", "not_applicable"),
        ("reviewed_excerpt", "other"),
    ],
)
def test_delivery_projection_uses_real_model_action_without_retaining_excerpt(action, expected):
    witness = witness_module.InstalledCorpusDeliveryWitness()
    witness.record(
        "claude-code",
        "PostToolUse",
        {"model_output_action": action, "reviewed_excerpt": "private reviewed text"},
        allowed=True,
    )
    report = witness.report(expected=1, worker_stats={})
    assert report["rows"][0]["model_action"] == expected
    assert "private reviewed text" not in json.dumps(report)
    assert report["per_request_native_route_proven"] is False


def test_delivery_projection_rejects_private_strings_and_bounds_rows_and_counts():
    private = "C:/Users/example/private-value?credential=unapproved"
    witness = witness_module.InstalledCorpusDeliveryWitness()
    response = {
        "decision": private,
        "reason_code": private,
        "policy_action": private,
        "model_output_action": private,
        "hookSpecificOutput": {"permissionDecision": private},
        "continue": private,
        "message": private,
    }
    for _ in range(33):
        witness.record(private, private, response, allowed=True)
    report = witness.report(
        expected=33,
        worker_stats={"routes": {"native_resident": 33, "native_fail_safe": True, "python_semantic": -1}},
    )
    assert report["expected"] is None and report["responses_seen"] is None
    assert report["truncated"] is True and report["retained"] == 32
    assert len(report["rows"]) == 32
    assert set(report["aggregate_routes"].values()) == {None}
    assert private not in json.dumps(report)
    row = report["rows"][0]
    assert row["harness"] == row["event"] == row["reason_code"] == "other"
    assert row["continue_value"] is None


def test_diagnostic_projection_failure_is_explicit_without_altering_response_validation():
    class InvalidDiagnostic(dict):
        def get(self, *args):
            raise RuntimeError("private error text")

    witness = witness_module.InstalledCorpusDeliveryWitness()
    witness.record("codex", "PreToolUse", InvalidDiagnostic(), allowed=True)
    report = witness.report(expected=1, worker_stats={"routes": {"native_resident": 0}})
    assert report["responses_seen"] == 1
    assert report["retained"] == 0
    assert report["projection_errors"] == 1
    assert report["aggregate_routes"]["native_resident"] == 0
    assert "private error text" not in json.dumps(report)


@pytest.mark.parametrize("emission_fails", [False, True])
def test_failure_witness_preserves_original_exception_and_stays_quiet_on_success(monkeypatch, emission_fails):
    witness = witness_module.InstalledCorpusDeliveryWitness()
    reports = []

    def emit(report):
        reports.append(report)
        if emission_fails:
            raise OSError("diagnostic unavailable")

    monkeypatch.setattr(witness_module, "_emit", emit)
    with witness.aggregate_validation(expected=21, worker_stats={}):
        pass
    assert reports == []
    original = RuntimeError("original aggregate failure")
    with pytest.raises(RuntimeError) as caught, witness.aggregate_validation(expected=21, worker_stats={}):
        raise original
    assert caught.value is original
    assert len(reports) == 1
    assert reports[0]["stage"] == "aggregate_validation"


@pytest.mark.parametrize(
    "observed_routes",
    [
        {"native_resident": 19, "native_fail_safe": 1},
        {"native_resident": 20, "native_fail_safe": 1},
        {"native_resident": 21},
    ],
)
def test_existing_corpus_keeps_requests_predicates_waits_and_passing_receipt_shape(
    tmp_path, monkeypatch, capsys, observed_routes
):
    from ci.native_runtime import probe_native_default_auto as probe

    events, requests, allowed_calls = [], [], []
    routes = probe._ownership_routes()
    expected_pairs = [
        (harness, event)
        for harness, route in sorted(routes.items())
        for event, key in (("PreToolUse", "pre_tool_use"), ("PostToolUse", "post_tool_use"))
        if route[key].startswith("installed_")
    ]
    assert len(expected_pairs) == 21
    stats = {"routes": observed_routes, "total_decisions": 0, "counters": {}}
    metrics, writer = object(), object()
    worker = SimpleNamespace(
        metrics=metrics,
        policy_snapshot_publisher=SimpleNamespace(),
        prepare_workspace_policy=lambda *args, **kwargs: object(),
    )

    class Daemon:
        def __init__(self, *args, **kwargs):
            self._server = SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)

        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    def request(daemon, guard_home, workspace, harness, event, payload):
        assert payload["hook_event_name"] == event
        assert payload == (
            {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "printf guard"}}
            if event == "PreToolUse"
            else {
                "hook_event_name": event,
                "tool_name": "Read",
                "tool_response": [{"type": "text", "text": "guard baseline\n"}],
            }
        )
        requests.append((harness, event))
        return {
            "decision": "allow",
            "reason_code": "native_degraded_emergency_safe" if len(requests) == 7 else "output_scan_allow",
        }

    original_allowed = probe.is_allowed

    def allowed(event, response):
        allowed_calls.append((event, response))
        return original_allowed(event, response)

    def wait_routes(actual, *, expected):
        assert actual is metrics and expected == 21 and requests == expected_pairs
        events.append("wait_routes")
        return stats

    def modes(*args):
        assert events[-1] == "wait_routes"
        events.append("modes")
        return {"unchanged": {"passed": True}}

    def wait_receipts(actual, *, expected):
        assert actual is writer and expected == 21 and events[-1] == "modes"
        events.append("wait_receipts")
        return {
            "receipt_accepted": 21,
            "receipt_processed": 21,
            "receipt_dropped": 0,
            "receipt_durable_pending": 0,
            "receipt_deduped": 0,
            "receipt_failures": 0,
        }

    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "_prepare_empty_command_authority", lambda store: {"verified_health": "protected"})
    monkeypatch.setattr(probe, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(probe, "_installed_hook_request", request)
    monkeypatch.setattr(probe, "is_allowed", allowed)
    monkeypatch.setattr(probe, "wait_for_route_corpus", wait_routes)
    monkeypatch.setattr(probe, "_exercise_mode_invariants", modes)
    monkeypatch.setattr(probe, "wait_for_receipt_corpus", wait_receipts)
    if observed_routes == {"native_resident": 21}:
        result = probe._installed_hook_corpus(tmp_path)
        assert set(result) == {
            "command_authority_fixture",
            "routes",
            "route_count",
            "native_resident_decisions",
            "native_oneshot_decisions",
            "python_semantic_decisions",
            "fail_safe_decisions",
            "reason_code_counts",
            "receipt_metrics",
            "mode_invariants",
        }
        assert result["routes"] == [
            {"harness": harness, "event": event, "route": "native_resident"} for harness, event in expected_pairs
        ]
        assert result["reason_code_counts"] == {"output_scan_allow": 20, "native_degraded_emergency_safe": 1}
        assert capsys.readouterr().err == ""
    else:
        with pytest.raises(RuntimeError) as caught:
            probe._installed_hook_corpus(tmp_path)
        assert str(caught.value) == f"native_default_auto_probe_failed: {stats}"
        report = json.loads(capsys.readouterr().err)
        assert report["expected"] == report["responses_seen"] == report["retained"] == 21
        assert report["aggregate_routes"]["native_resident"] == observed_routes["native_resident"]
        assert report["aggregate_routes"]["native_fail_safe"] == 1
        assert report["aggregate_routes"]["native_oneshot"] is None
        assert report["rows"][6]["reason_code"] == "native_degraded_emergency_safe"
        assert all(row["delivered_allowed"] is True for row in report["rows"])
        assert report["per_request_native_route_proven"] is False
    assert requests == expected_pairs and len(allowed_calls) == 21
    assert events == ["start", "wait_routes", "modes", "wait_receipts", "stop"]
