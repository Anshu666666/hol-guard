"""Preserve failed installed lifecycle boundaries without changing readiness."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from scripts.ci import installed_native_ollama_probe as probe
from scripts.ci import native_ollama_diagnostics as diagnostics
from scripts.native_slo_contract import assert_privacy_safe


def _publisher():
    snapshot = {
        "generation": 7,
        "expires_at_ms": 4_000_000_000_000,
        "command_extensions": {"revision": 1, "managed_revision": 0, "health": "protected"},
        "private_fixture_value": "UNPUBLISHED_POLICY_VALUE",
    }
    return SimpleNamespace(
        _condition=threading.Condition(),
        _snapshot=snapshot,
        _acked=True,
        _closed=False,
        _last_error=None,
        _epoch=9,
        _failure_count=0,
        _retry_not_before_monotonic=None,
        _thread=None,
        current_snapshot=lambda: snapshot,
        is_ready=lambda: True,
    )


@pytest.mark.parametrize(
    "error",
    [
        None,
        "native_policy_snapshot_resident_changed",
        "native_policy_windows_path_open_failed",
        "native_command_program_digest_mismatch",
        "PRIVATE_CREDENTIAL_VALUE",
    ],
)
def test_cached_observation_never_copies_policy_or_unclassified_error(error):
    publisher = _publisher()
    publisher._last_error = error

    def forbidden():
        pytest.fail("diagnostic must not call readiness or snapshot accessors")

    publisher.current_snapshot = publisher.is_ready = forbidden
    value = diagnostics.publisher_state(publisher)
    assert value["capture"] == "sampled" and value["generation"] == 7
    assert value["control_revision"] == 1 and value["acknowledged"] is True
    assert value["last_error"] == (
        "absent" if error is None else "redacted" if error == "PRIVATE_CREDENTIAL_VALUE" else error
    )
    encoded = json.dumps(value)
    assert "PRIVATE_CREDENTIAL_VALUE" not in encoded and "UNPUBLISHED_POLICY_VALUE" not in encoded
    assert publisher._snapshot["private_fixture_value"] == "UNPUBLISHED_POLICY_VALUE"


def test_busy_observation_never_waits_and_retains_bounded_publisher_stack(monkeypatch):
    calls = []
    frame = object()
    publisher = _publisher()
    publisher._condition = SimpleNamespace(acquire=lambda **kwargs: calls.append(kwargs) or False)
    publisher._thread = SimpleNamespace(ident=19, is_alive=lambda: True)
    locations = [{"origin": "native_policy_snapshot_publisher._publish_once", "line": 405}]
    monkeypatch.setattr(diagnostics.sys, "_current_frames", lambda: {19: frame})

    def stack(observed):
        assert observed is frame
        return locations

    monkeypatch.setattr(diagnostics, "startup_code_locations", stack)
    value = diagnostics.publisher_state(publisher, with_stack=True)
    assert calls == [{"blocking": False}]
    assert value == {"capture": "busy", "publisher_alive": True, "stack": locations}


@pytest.mark.parametrize(
    ("present", "elapsed", "raised", "okay"),
    [(False, 0.001, False, False), (True, 0.4, False, True), (True, 0.401, False, False), (False, 0.002, True, False)],
)
def test_readiness_observes_one_unchanged_prepare_call_and_exact_deadline(monkeypatch, present, elapsed, raised, okay):
    publisher = _publisher()
    publisher._last_error = "native_policy_snapshot_resident_changed" if not present else None
    publisher._acked = present
    clock = [10.0]
    calls = []

    def prepare(workspace, *, deadline):
        calls.append((workspace, deadline))
        assert deadline == 10.4
        clock[0] += elapsed
        if raised:
            raise OSError("UNPUBLISHED_EXCEPTION_VALUE")
        return {"generation": 7} if present else None

    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    worker = SimpleNamespace(prepare_workspace_policy=prepare, policy_snapshot_publisher=publisher)
    session = SimpleNamespace(daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)), workspace="fixture")
    progress = diagnostics.OllamaProbeProgress()
    progress.at(phase="updated", step="ready")
    if okay:
        assert probe.ready_binding(session, 1, progress=progress) == publisher._snapshot
    else:
        with pytest.raises(OSError if raised else AssertionError):
            probe.ready_binding(session, 1, progress=progress)
    assert calls == [("fixture", 10.4)]
    observation = progress.evidence()["readiness"][0]
    assert observation["phase"] == "updated" and observation["expected_revision"] == 1
    assert observation["returned_snapshot"] is present
    assert observation["within_budget"] is (elapsed <= 0.4)
    assert observation["raised"] is raised
    assert observation["elapsed_ms"] == elapsed * 1000
    assert "UNPUBLISHED" not in json.dumps(progress.evidence())


def test_failure_output_keeps_phase_and_completed_cases(monkeypatch, tmp_path, capsys):
    expected = tmp_path / "expected.json"
    expected.write_text("{}")
    monkeypatch.setattr(probe.sys, "argv", ["probe", "--expected", str(expected)])

    def run(_expected, *, progress):
        progress.record_case({"phase": "initial", "case": "push_inactive", "route": "native_resident"})
        progress.at(phase="enabled", step="ready")
        raise AssertionError("installed_ollama_native_readiness_failed")

    monkeypatch.setattr(probe, "run_probe", run)
    assert probe.main() == 1
    value = json.loads(capsys.readouterr().out)
    assert value["reason"] == "installed_ollama_native_readiness_failed"
    assert value["progress"]["phase"] == "enabled" and value["progress"]["step"] == "ready"
    assert value["progress"]["completed_case_count"] == 1
    assert value["progress"]["completed_cases"][0]["case"] == "push_inactive"
    assert value["progress"]["observations_authorize_readiness"] is False


def test_lifecycle_retains_completed_initial_cases_when_enabled_ack_fails(monkeypatch):
    publisher = _publisher()
    publisher._snapshot["command_extensions"]["revision"] = 0
    calls = []
    closed = []

    def prepare(_workspace, *, deadline):
        calls.append(deadline)
        return publisher._snapshot if publisher._acked else None

    worker = SimpleNamespace(prepare_workspace_policy=prepare, policy_snapshot_publisher=publisher, test_oracle=None)

    class Session:
        store = object()
        workspace = "fixture"
        daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
        readiness_ms = 1.0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(True)

    def commit(*_args, **_kwargs):
        publisher._acked = False
        publisher._last_error = "native_policy_snapshot_resident_changed"
        return 1

    monkeypatch.setattr(probe, "artifact_identity", lambda _expected: (object(), {}))
    monkeypatch.setattr(probe, "AdapterSession", lambda *_args, **_kwargs: Session())
    monkeypatch.setattr(probe, "prepare_fixture_authority", lambda _store: "fixture-password")
    monkeypatch.setattr(probe, "commit_controls", commit)
    monkeypatch.setattr(
        probe,
        "review_case",
        lambda _session, phase, case, _snapshot: (
            {"phase": phase, "case": case.name, "route": "native_resident"},
            None,
        ),
    )
    progress = diagnostics.OllamaProbeProgress()
    with pytest.raises(AssertionError, match="installed_ollama_native_readiness_failed"):
        probe.run_probe({}, progress=progress)
    evidence = progress.evidence()
    assert len(calls) == 2 and closed == [True]
    assert evidence["phase"] == "enabled" and evidence["step"] == "ready"
    assert evidence["completed_case_count"] == 2
    assert [case["case"] for case in evidence["completed_cases"]] == ["push_inactive", "rm_inactive"]
    assert [attempt["returned_snapshot"] for attempt in evidence["readiness"]] == [True, False]
    assert evidence["readiness"][-1]["after"]["last_error"] == "native_policy_snapshot_resident_changed"


def test_outer_installed_aggregate_retains_code_locations_and_error_fields(monkeypatch):
    progress = diagnostics.OllamaProbeProgress()
    locations = [{"origin": "native_policy_snapshot_publisher._publish_once", "line": 405}]
    monkeypatch.setattr(
        diagnostics,
        "publisher_state",
        lambda *_args, **_kwargs: {
            "capture": "sampled",
            "last_error": "native_policy_snapshot_resident_changed",
            "stack": locations,
        },
    )
    progress.observe_readiness(
        object(), revision=1, before={}, elapsed_ms=400, returned_snapshot=False, within_budget=True, raised=False
    )
    aggregate = assert_privacy_safe({"native": {"progress": progress.evidence()}})
    nested = aggregate["native"]["progress"]
    assert nested["publisher_stack"] == locations
    assert nested["publisher_stack_attempt"] == 0
    assert nested["readiness"][0]["after"]["last_error"] == "native_policy_snapshot_resident_changed"


def test_progress_rejects_unbounded_or_private_context():
    progress = diagnostics.OllamaProbeProgress()
    with pytest.raises(ValueError):
        progress.at(step="ready", phase="unclassified_private_context")
    with pytest.raises(ValueError):
        progress.at(step="review", case="/private/user/context")
    for _ in range(32):
        progress.record_case({"case": "bounded"})
    with pytest.raises(ValueError, match="progress_limit"):
        progress.record_case({"case": "overflow"})
