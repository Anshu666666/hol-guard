from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import live_process_identity
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as recovery_cli
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import user_recovery as recovery_module
from codex_plugin_scanner.guard.daemon.user_recovery import (
    AuthorizationDecision,
    ProcessIdentity,
    ProtectionResult,
    ReadyResult,
    RecoveryHooks,
    ServiceInspection,
    StartResult,
    StopResult,
    UserRecoveryCoordinator,
)


def _current_owner_marker() -> str:
    return f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user"


def _identity(guard_home: Path, *, pid: int = 41, generation: str = "generation-1") -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        generation=generation,
        runtime="runtime-1",
        guard_home=guard_home,
        user=_current_owner_marker(),
        start_marker=f"start-{generation}",
    )


def _pending_snapshot(phase: str) -> dict[str, object]:
    return {
        "schema": "hol-guard-recovery.v1",
        "capabilities": ["diagnostics", "inspect", "restart", "status"],
        "operationId": "12121212-1212-4212-8212-121212121212",
        "sequence": 2,
        "startedAt": "2026-09-20T12:00:00+00:00",
        "updatedAt": "2026-09-20T12:00:01+00:00",
        "phase": phase,
        "activeElapsedMs": 1000,
        "workerActive": True,
        "retryAllowed": False,
        "outcome": "pending",
        "reasonCode": "healthy",
        "service": "ready",
        "protection": "unknown",
        "requiresHumanAction": False,
        "checks": [],
    }


def _coordinator(
    tmp_path: Path,
    service: ServiceInspection,
    *,
    posture: str = "on",
    protection_posture=None,
    authorize: AuthorizationDecision | None = None,
    authorize_hook=None,
    stop_process=None,
    process_dead=None,
    start_process=None,
    verify_ready=None,
    protection_health=None,
    inspect_service=None,
    recovery_lock=None,
    start_lock=None,
    update_busy=None,
    calls: list[str] | None = None,
    clock=None,
    active_budget_seconds: float = 60.0,
    lock_timeout_seconds: float = 0.0,
    load_snapshot=None,
    persist_snapshot=None,
    use_default_stop_process: bool = False,
) -> UserRecoveryCoordinator:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    observed = calls if calls is not None else []

    def inspect(_home: Path, _state: object) -> ServiceInspection:
        observed.append("inspect")
        if inspect_service is not None:
            return inspect_service()
        return service

    hooks = RecoveryHooks(
        clock=clock or (lambda: 100.0),
        wall_clock=lambda: __import__("datetime").datetime(2026, 9, 20, tzinfo=__import__("datetime").timezone.utc),
        load_state=lambda _home: {"state": "fixture"},
        inspect_service=inspect,
        protection_posture=protection_posture or (lambda _home: posture),
        authorize=authorize_hook or (lambda _home: authorize if authorize is not None else True),
        update_busy=update_busy or (lambda _home: False),
        recovery_lock=recovery_lock or (lambda *_args: nullcontext()),
        start_lock=start_lock or (lambda *_args: nullcontext()),
        stop_process=(
            None
            if use_default_stop_process
            else (stop_process or (lambda _identity, _remaining: StopResult(True)))
        ),
        process_dead=process_dead or (lambda _identity: True),
        start_process=start_process or (lambda _home, _remaining: StartResult(True)),
        verify_ready=verify_ready or (lambda _home, identity, _remaining: ReadyResult(True, identity)),
        protection_health=protection_health
        or (lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy")),
        load_snapshot=load_snapshot,
        persist_snapshot=persist_snapshot,
    )
    return UserRecoveryCoordinator(
        guard_home,
        hooks=hooks,
        active_budget_seconds=active_budget_seconds,
        lock_timeout_seconds=lock_timeout_seconds,
    )


def test_inspection_is_read_only_and_classifies_missing_service(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
    )

    snapshot = coordinator.inspect()

    assert snapshot["operationId"] is None
    assert snapshot["phase"] == "checking"
    assert snapshot["reasonCode"] == "service_missing"
    assert snapshot["service"] == "unavailable"
    assert calls == ["inspect"]


def test_healthy_service_reconnects_without_stop_or_start(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )
    events: list[dict[str, object]] = []

    result = coordinator.restart("11111111-1111-4111-8111-111111111111", emit=events.append)

    assert result["phase"] == "complete"
    assert result["outcome"] == "reconnected"
    assert result["service"] == "ready"
    assert result["protection"] == "verified"
    assert "stop" not in calls
    assert "start" not in calls
    assert [event["phase"] for event in events] == ["checking", "checking", "reconnecting", "verifying", "complete"]


def test_dashboard_session_failure_preserves_healthy_daemon(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        verify_ready=lambda *_args: ReadyResult(False, identity, "session_invalid"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("15151515-1515-4515-8515-151515151515")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "session_invalid"
    assert result["service"] == "ready"
    assert result["workerActive"] is False
    assert calls.count("stop") == 0
    assert calls.count("start") == 0


def test_reconnect_rejects_readiness_identity_replacement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    expected = _identity(guard_home, pid=41, generation="generation-1")
    replacement = _identity(guard_home, pid=42, generation="generation-2")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", expected, True, True, True),
        calls=calls,
        verify_ready=lambda *_args: ReadyResult(True, replacement),
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, replacement),
    )

    result = coordinator.restart("16161616-1616-4616-8616-161616161616")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is True
    assert "protection" not in calls
    assert "stop" not in calls
    assert "start" not in calls
    assert str(guard_home) not in recovery_module._ACTIVE_BY_HOME


def test_start_rejects_readiness_identity_replacement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    started = _identity(guard_home, pid=41, generation="generation-1")
    replacement = _identity(guard_home, pid=42, generation="generation-2")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True, started),
        verify_ready=lambda *_args: ReadyResult(True, replacement),
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
    )

    result = coordinator.restart("17171717-1717-4717-8717-171717171717")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert result["workerActive"] is True
    assert calls.count("start") == 1
    assert "protection" not in calls
    active = recovery_module._ACTIVE_BY_HOME.get(str(guard_home))
    assert active is not None
    assert active.unresolved_identity == started


def test_reconnected_daemon_reports_protection_attention_separately(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        protection_health=lambda *_args: ProtectionResult("needs_attention", "protection_unhealthy"),
    )

    result = coordinator.restart("18181818-1818-4818-8818-181818181818")

    assert result["phase"] == "complete"
    assert result["service"] == "ready"
    assert result["protection"] == "needs_attention"
    assert result["requiresHumanAction"] is True


def test_same_generation_session_reconnect_uses_remaining_budget(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    observed_remaining: list[float] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        active_budget_seconds=0.5,
        verify_ready=lambda _home, _identity, remaining: observed_remaining.append(remaining)
        or ReadyResult(True, identity),
    )

    result = coordinator.restart("19191919-1919-4919-8919-191919191919")

    assert result["phase"] == "complete"
    assert result["service"] == "ready"
    assert observed_remaining and 0.0 < observed_remaining[0] <= 0.5


def test_mapping_inspection_preserves_explicit_dashboard_session_failure(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)

    inspection = recovery_module._coerce_service(
        {
            "service": "ready",
            "reason_code": "session_invalid",
            "identity": {
                "pid": identity.pid,
                "generation": identity.generation,
                "runtime": identity.runtime,
                "guard_home": str(identity.guard_home),
                "user": identity.user,
                "start_marker": identity.start_marker,
            },
            "process_running": True,
            "authenticated": True,
            "dashboard_ready": False,
        },
        guard_home,
        None,
    )

    assert inspection.service == "ready"
    assert inspection.reason_code == "session_invalid"
    assert inspection.authenticated is True
    assert inspection.dashboard_ready is False


def test_default_inspector_session_failure_preserves_healthy_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    probe_calls: list[ProcessIdentity] = []
    mutations: list[str] = []

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    def probe(_home: Path, *, session_timeout: float) -> tuple[dict[str, object], str]:
        assert 0.0 < session_timeout <= 1.0
        probe_calls.append(identity)
        return {**state, "daemon_url": "http://127.0.0.1:5474"}, "session_invalid"

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(recovery_module, "_identity_os_evidence_matches", lambda _identity: True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
        probe,
    )
    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            clock=lambda: 100.0,
            wall_clock=lambda: __import__("datetime").datetime(
                2026, 9, 20, tzinfo=__import__("datetime").timezone.utc
            ),
            load_state=lambda _home: state,
            protection_posture=lambda _home: "on",
            authorize=lambda _home: True,
            update_busy=lambda _home: False,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            stop_process=lambda *_args: mutations.append("stop") or StopResult(True),
            start_process=lambda *_args: mutations.append("start") or StartResult(True, identity),
            protection_health=lambda *_args: ProtectionResult("verified", "healthy"),
        ),
    )

    result = coordinator.restart("20202020-2020-4020-8020-202020202020")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "session_invalid"
    assert result["service"] == "ready"
    assert len(probe_calls) == 3
    assert all(item == identity for item in probe_calls)
    assert mutations == []


@pytest.mark.parametrize("mismatch", ("start", "owner"))
def test_default_inspector_rejects_reused_pid_without_os_identity_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(
        live_process_identity,
        "process_start_token",
        lambda _pid: "start-reused" if mismatch == "start" else identity.start_marker,
    )
    monkeypatch.setattr(
        live_process_identity,
        "process_owner_marker",
        lambda _pid: "uid:other" if mismatch == "owner" else identity.user,
    )

    inspection = recovery_module._default_inspect_service(guard_home, state)

    assert inspection.service == "unavailable"
    assert inspection.reason_code == "identity_unverified"
    assert inspection.identity == identity


def test_default_inspector_rechecks_os_generation_after_session_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    start_markers = iter((identity.start_marker, "start-reused"))
    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(
        live_process_identity,
        "process_start_token",
        lambda _pid: next(start_markers),
    )
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
        lambda _home, **_kwargs: ({**state, "daemon_url": "http://127.0.0.1:5474"}, "healthy"),
    )

    inspection = recovery_module._default_inspect_service(guard_home, state)

    assert inspection.service == "unavailable"
    assert inspection.reason_code == "identity_unverified"
    assert inspection.identity == identity


def test_owned_unresponsive_service_is_stopped_then_started(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda _identity, _remaining: calls.append("stop") or StopResult(True),
        start_process=lambda _home, _remaining: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("22222222-2222-4222-8222-222222222222")

    assert result["phase"] == "complete"
    assert result["outcome"] == "restarted"
    assert calls.count("stop") == 1
    assert calls.count("start") == 1


def test_identity_conflict_never_mutates_the_process(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "endpoint_conflict", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("33333333-3333-4333-8333-333333333333")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "endpoint_conflict"
    assert calls == ["inspect", "inspect"]


def test_missing_process_start_token_refuses_stop_at_mutation_boundary(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(41, "generation-1", "runtime-1", guard_home, _current_owner_marker(), None)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("45454545-4545-4454-8454-454545454545")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_wrong_process_owner_refuses_stop_at_mutation_boundary(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(42, "generation-owner", "runtime-1", guard_home, "different-user", "start-owner")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("46464646-4646-4464-8464-464646464646")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_missing_authenticated_os_token_does_not_adopt_reused_pid_generation(
    tmp_path: Path, monkeypatch
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(43, "generation-state", "runtime-1", guard_home, _current_owner_marker(), None)
    retire_calls: list[dict[str, object]] = []

    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: "windows:live-generation")

    def retire(pid: int, **kwargs: object) -> bool:
        retire_calls.append({"pid": pid, **kwargs})
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    result = coordinator._stop_process(identity, 1.0)

    assert result is False
    assert retire_calls == []


def test_target_process_owner_marker_must_match_authenticated_state(
    tmp_path: Path, monkeypatch
) -> None:
    identity = _identity(tmp_path / "guard-home", pid=43)
    retire_calls: list[dict[str, object]] = []

    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: "uid:foreign")
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda pid, **kwargs: retire_calls.append({"pid": pid, **kwargs}) or True,
    )

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    assert coordinator._stop_process(identity, 1.0) is False
    assert retire_calls == []


def test_wrong_runtime_and_home_refuse_stop_before_signal(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = ProcessIdentity(44, "generation-1", "runtime-1", guard_home, _current_owner_marker(), "start-1")
    changed = ProcessIdentity(
        44,
        "generation-1",
        "runtime-2",
        tmp_path / "other-home",
        _current_owner_marker(),
        "start-1",
    )
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        calls=calls,
        inspect_service=lambda: next(inspections),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, changed),
    )

    result = coordinator.restart("48484848-4848-4484-8484-484848484848")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_generation_change_before_escalation_is_rejected_by_stop_boundary(
    tmp_path: Path, monkeypatch
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(45, "generation-1", "runtime-1", guard_home, _current_owner_marker(), "start-1")
    observed: dict[str, object] = {}

    def retire(
        pid: int,
        *,
        expected_guard_home: Path,
        expected_start_marker: str | None = None,
        **_kwargs: object,
    ) -> bool:
        observed.update(
            pid=pid,
            guard_home=expected_guard_home,
            start_marker=expected_start_marker,
        )
        return False

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    result = coordinator._stop_process(identity, 1.0)

    assert result is False
    assert observed == {
        "pid": identity.pid,
        "guard_home": guard_home,
        "start_marker": identity.start_marker,
    }


def test_generation_change_after_confirmed_stop_refuses_replacement_start(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = _identity(guard_home)
    changed = ProcessIdentity(
        target.pid,
        "generation-2",
        target.runtime,
        guard_home,
        target.user,
        "start-generation-2",
    )
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, target),
    )

    result = coordinator.restart("47474747-4747-4474-8474-474747474747")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]


def test_protection_off_after_start_lock_prevents_start(tmp_path: Path) -> None:
    state = {"posture": "on"}
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["posture"] = "off"
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        protection_posture=lambda _home: state["posture"],
        start_lock=start_lock,
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("49494949-4949-4494-8494-494949494949")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert "start" not in calls


def test_protection_off_after_stop_lock_prevents_stop(tmp_path: Path) -> None:
    state = {"posture": "on"}
    identity = _identity(tmp_path / "guard-home")
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["posture"] = "off"
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        protection_posture=lambda _home: state["posture"],
        start_lock=start_lock,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("4a4a4a4a-4a4a-44a4-84a4-4a4a4a4a4a4a")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert "stop" not in calls
    assert "start" not in calls


def test_approval_invalidated_after_recovery_lock_prevents_start(tmp_path: Path) -> None:
    state = {"approved": True}
    calls: list[str] = []
    validation_calls: list[str] = []
    proof_prompt_calls: list[str] = []

    def authorize(_home: Path) -> AuthorizationDecision:
        validation_calls.append("validate")
        if len(validation_calls) == 1:
            proof_prompt_calls.append("prompt")
            return AuthorizationDecision(True)
        return AuthorizationDecision(False, True, "approval_required")

    @contextmanager
    def recovery_lock(*_args: object):
        state["approved"] = False
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize_hook=authorize,
        recovery_lock=recovery_lock,
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4b4b4b4b-4b4b-44b4-84b4-4b4b4b4b4b4b")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"
    assert "start" not in calls
    assert validation_calls == ["validate", "validate"]
    assert proof_prompt_calls == ["prompt"]


def test_update_ownership_changed_after_start_lock_prevents_start(tmp_path: Path) -> None:
    state = {"busy": False}
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["busy"] = True
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_lock=start_lock,
        update_busy=lambda _home: state["busy"],
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4c4c4c4c-4c4c-44c4-84c4-4c4c4c4c4c4c")

    assert result["phase"] == "waiting_for_owner"
    assert result["reasonCode"] == "update_busy"
    assert "start" not in calls


def test_explicitly_disabled_protection_prevents_launch(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        posture="off",
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("44444444-4444-4444-8444-444444444444")

    assert coordinator.inspect()["retryAllowed"] is False
    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert result["protection"] == "off"
    assert "start" not in calls


def test_unknown_protection_posture_prevents_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        posture="unknown",
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("77777777-7777-4777-8777-777777777777")

    assert coordinator.inspect()["retryAllowed"] is False
    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "unknown"
    assert "start" not in calls


def test_uncertain_exit_keeps_retry_disabled_and_does_not_start_replacement(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(False, "worker_exit_unconfirmed"),
        process_dead=lambda _identity: False,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("55555555-5555-4555-8555-555555555555")

    assert result["phase"] == "timed_out_waiting"
    assert result["reasonCode"] == "worker_exit_unconfirmed"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert "start" not in calls


def test_unresolved_timeout_reconciles_before_a_second_stop(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    dead = {"value": False}
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(False, "worker_exit_unconfirmed"),
        process_dead=lambda _identity: dead["value"],
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    first = coordinator.restart("55555555-5555-4555-8555-555555555555")
    second = coordinator.restart("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    assert first["phase"] == "timed_out_waiting"
    assert second["phase"] == "timed_out_waiting"
    assert second["operationId"] == first["operationId"]
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]

    dead["value"] = True
    reconciled = coordinator.restart("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

    assert reconciled["phase"] == "complete"
    assert reconciled["workerActive"] is False
    assert [call for call in calls if call in {"stop", "start"}] == ["stop", "stop", "start"]


def test_deadline_expiry_before_stop_does_not_mutate(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []

    @contextmanager
    def recovery_lock(*_args: object):
        clock["value"] = 101.0
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=2.0,
        recovery_lock=lambda *_args: recovery_lock(),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is False
    assert not any(call in {"stop", "start"} for call in calls)


def test_deadline_expiry_after_confirmed_stop_does_not_start_replacement(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []

    def stop(_identity: ProcessIdentity, remaining: float) -> StopResult:
        assert remaining > 0.0
        calls.append("stop")
        clock["value"] = 101.0
        return StopResult(True)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=2.0,
        stop_process=stop,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is False
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]


def test_helper_timeouts_are_never_greater_than_remaining_budget(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    observed: dict[str, float] = {}
    identity = _identity(tmp_path / "guard-home")

    @contextmanager
    def recovery_lock(_home: Path, timeout: float):
        observed["recovery_lock"] = timeout
        yield

    @contextmanager
    def start_lock(_home: Path, timeout: float):
        observed["start_lock"] = timeout
        yield

    def stop(_identity: ProcessIdentity, remaining: float) -> StopResult:
        observed["stop"] = remaining
        return StopResult(True)

    def start(_home: Path, remaining: float) -> StartResult:
        observed["start"] = remaining
        return StartResult(True, identity)

    def ready(_home: Path, _identity: ProcessIdentity | None, remaining: float) -> ReadyResult:
        observed["ready"] = remaining
        return ReadyResult(True, identity)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=10.0,
        recovery_lock=recovery_lock,
        start_lock=start_lock,
        stop_process=stop,
        start_process=start,
        verify_ready=ready,
    )

    result = coordinator.restart("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

    assert result["phase"] == "complete"
    assert observed
    assert all(0.0 <= timeout <= 1.0 for timeout in observed.values())


def test_approval_wait_does_not_consume_recovery_budget(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    observed: dict[str, float] = {}
    started_identity = _identity(tmp_path / "guard-home")

    def authorize(_home: Path) -> bool:
        clock["value"] = 1000.0
        return True

    @contextmanager
    def recovery_lock(_home: Path, timeout: float):
        observed["recovery_lock"] = timeout
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=10.0,
        authorize_hook=authorize,
        recovery_lock=recovery_lock,
        start_process=lambda *_args: StartResult(True, started_identity),
    )

    result = coordinator.restart("abababab-abab-4aba-8aba-abababababab")

    assert result["phase"] == "complete"
    assert observed["recovery_lock"] == 1.0


def test_unavailable_pending_snapshot_fails_closed_before_mutation(tmp_path: Path) -> None:
    calls: list[str] = []

    def unavailable(_home: Path):
        raise RuntimeError("recovery_state_invalid")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        load_snapshot=unavailable,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("cdcdcdcd-cdcd-4cdc-8cdc-cdcdcdcdcdcd")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert result["workerActive"] is True
    assert not any(call in {"stop", "start"} for call in calls)


def test_stale_read_only_receipt_reconnects_fresh_ready_service(tmp_path: Path) -> None:
    for phase in ("checking", "reconnecting"):
        phase_home = tmp_path / phase
        phase_home.mkdir()
        identity = _identity(phase_home / "guard-home")
        calls: list[str] = []
        coordinator = _coordinator(
            phase_home,
            ServiceInspection("ready", "healthy", identity, True, True, True),
            calls=calls,
            process_dead=lambda _identity: False,
            load_snapshot=lambda _home, phase=phase: _pending_snapshot(phase),
            stop_process=lambda *_args, calls=calls: calls.append("stop") or StopResult(True),
            start_process=lambda *_args, calls=calls, identity=identity: calls.append("start")
            or StartResult(True, identity),
        )

        request_id = (
            "15151515-1515-4515-8515-151515151515"
            if phase == "checking"
            else "16161616-1616-4616-8616-161616161616"
        )
        result = coordinator.restart(request_id)

        assert result["phase"] == "complete"
        assert result["outcome"] == "reconnected"
        assert not any(call in {"stop", "start"} for call in calls)


def test_stale_checking_receipt_allows_fresh_missing_service_start(tmp_path: Path) -> None:
    calls: list[str] = []
    identity = _identity(tmp_path / "guard-home")
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, True),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("checking"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("17171717-1717-4717-8717-171717171717")

    assert result["phase"] == "complete"
    assert result["outcome"] == "started"
    assert calls.count("start") == 1
    assert "stop" not in calls


def test_stale_verifying_receipt_blocks_missing_identity(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, True),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("verifying"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("18181818-1818-4818-8818-181818181818")

    assert result["phase"] == "waiting_for_owner"
    assert result["workerActive"] is True
    assert not any(call in {"stop", "start"} for call in calls)


def test_unrelated_recovery_lock_failure_is_safe_and_does_not_persist(tmp_path: Path) -> None:
    persisted: list[dict[str, object]] = []

    def broken_lock(*_args):
        raise RuntimeError("lock_backend_unavailable")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        recovery_lock=broken_lock,
        persist_snapshot=lambda _home, snapshot: persisted.append(snapshot),
    )

    result = coordinator.restart("efefefef-efef-4efe-8efe-efefefefefef")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert persisted == []


def test_started_worker_remains_active_when_readiness_times_out(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    identity = _identity(tmp_path / "guard-home")

    def verify_ready(_home, _identity, _remaining):
        clock["value"] = 101.0
        return ReadyResult(False, identity, "startup_failed")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        start_process=lambda _home, _remaining: StartResult(True, identity),
        verify_ready=verify_ready,
    )

    result = coordinator.restart("dededede-dede-4ded-8ded-dededededede")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False


def test_default_stop_passes_remaining_to_bounded_retirement(tmp_path: Path, monkeypatch) -> None:
    identity = _identity(tmp_path / "guard-home")
    captured: dict[str, object] = {}

    def retire(pid: int, **kwargs: object) -> bool:
        captured["pid"] = pid
        captured.update(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    # The fixture normally injects a stop hook; exercise the coordinator's
    # production default directly so the manager timeout contract is covered.
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )
    result = coordinator._stop_process(identity, 0.25)

    assert result is True
    assert captured == {
        "pid": identity.pid,
        "expected_guard_home": coordinator.guard_home,
        "expected_creation_time": None,
        "expected_start_marker": identity.start_marker,
        "timeout": 0.25,
    }


def test_started_worker_timeout_blocks_second_request_until_proven_dead(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    identity = _identity(tmp_path / "guard-home")
    dead = {"value": False}
    calls: list[str] = []
    starts = {"count": 0}

    def start(_home: Path, _remaining: float) -> StartResult:
        calls.append("start")
        starts["count"] += 1
        return StartResult(True, identity)

    def verify_ready(_home: Path, current: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        if starts["count"] == 1:
            clock["value"] = 101.0
            return ReadyResult(False, current or identity, "deadline_exceeded")
        return ReadyResult(True, current or identity)

    def process_dead(current: ProcessIdentity) -> bool:
        assert current == identity
        return dead["value"]

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        start_process=start,
        verify_ready=verify_ready,
        process_dead=process_dead,
    )

    first = coordinator.restart("19191919-1919-4919-8919-191919191919")
    second = coordinator.restart("20202020-2020-4020-8020-202020202020")

    assert first["phase"] == "failed"
    assert first["reasonCode"] == "deadline_exceeded"
    assert first["workerActive"] is True
    assert second["operationId"] == first["operationId"]
    assert [call for call in calls if call == "start"] == ["start"]

    dead["value"] = True
    reconciled = coordinator.restart("21212121-2121-4121-8121-212121212121")

    assert reconciled["phase"] == "complete"
    assert reconciled["outcome"] == "started"
    assert [call for call in calls if call == "start"] == ["start", "start"]


def test_cross_process_unresolved_stop_receipt_blocks_second_stop_until_proven_dead(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        ready_path = Path(sys.argv[3])
        release_path = Path(sys.argv[4])
        log_path = Path(sys.argv[5])
        dead_path = Path(sys.argv[6])
        dead_check_log = Path(sys.argv[7])
        request_id = sys.argv[8]
        lock_timeout = float(sys.argv[9])
        identity = ProcessIdentity(
            pid=41,
            generation="target-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user",
            start_marker="start-target",
        )

        def persist(home, snapshot):
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            cli._persist_snapshot(home, snapshot)

        def stop(_identity, _remaining):
            if role == "owner":
                ready_path.write_text("ready", encoding="utf-8")
                return StopResult(False, "worker_exit_unconfirmed")
            return StopResult(True)

        def process_dead(_identity):
            if (
                _identity.pid != 41
                or _identity.generation != "target-generation"
                or _identity.start_marker != "start-target"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{_identity.pid} {_identity.generation} {_identity.start_marker}\\n")
            return dead_path.exists()

        hooks = RecoveryHooks(
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=lambda _home, _state: ServiceInspection(
                "unavailable", "service_unresponsive", identity, True
            ),
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=lambda _home, _remaining: StartResult(True, identity),
            verify_ready=lambda _home, current, _remaining: ReadyResult(True, current),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=5.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            while not release_path.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "11111111-1111-4111-8111-111111111111"
    contender_id = "22222222-2222-4222-8222-222222222222"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(persisted_log),
            str(worker_dead),
            str(dead_check_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(persisted_log),
                str(worker_dead),
                str(dead_check_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender " not in persisted_log.read_text(encoding="utf-8")

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(persisted_log),
                str(worker_dead),
                str(dead_check_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        assert "contender stopping" in persisted_log.read_text(encoding="utf-8")
        assert all(
            line == "41 target-generation start-target"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "3"


def test_cli_stopping_receipt_blocks_retry_when_timeout_persistence_fails(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    mutation_log = tmp_path / "mutation.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        owner_ready = Path(sys.argv[3])
        release_owner = Path(sys.argv[4])
        worker_dead = Path(sys.argv[5])
        dead_check_log = Path(sys.argv[6])
        mutation_log = Path(sys.argv[7])
        persisted_log = Path(sys.argv[8])
        request_id = sys.argv[9]
        lock_timeout = float(sys.argv[10])
        identity = ProcessIdentity(
            pid=41,
            generation="target-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user",
            start_marker="start-target",
        )

        def persist(home, snapshot):
            with persisted_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            if role == "owner" and snapshot["phase"] in {"timed_out_waiting", "failed"}:
                raise OSError("simulated final snapshot write failure")
            cli._persist_snapshot(home, snapshot)

        def process_dead(current):
            if (
                current.pid != 41
                or current.generation != "target-generation"
                or current.start_marker != "start-target"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{current.pid} {current.generation} {current.start_marker}\\n")
            return worker_dead.exists()

        def stop(_identity, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} stop\\n")
            if role == "owner":
                owner_ready.write_text("ready", encoding="utf-8")
                return StopResult(False, "worker_exit_unconfirmed")
            return StopResult(True)

        hooks = RecoveryHooks(
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=lambda _home, _state: ServiceInspection(
                "unavailable", "service_unresponsive", identity, True
            ),
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=lambda _home, _remaining: StartResult(True, identity),
            verify_ready=lambda _home, current, _remaining: ReadyResult(True, current),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=5.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            while not release_owner.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "31313131-3131-4313-8313-313131313131"
    contender_id = "32323232-3232-4323-8323-323232323232"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(worker_dead),
            str(dead_check_log),
            str(mutation_log),
            str(persisted_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]
        persisted = recovery_cli._load_latest_snapshot(guard_home)
        assert persisted is not None
        assert persisted["phase"] == "stopping"

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender stop" not in mutation_log.read_text(encoding="utf-8")
        assert recovery_cli._load_latest_snapshot(guard_home)["phase"] == "stopping"

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        assert "contender stop" in mutation_log.read_text(encoding="utf-8")
        assert all(
            line == "41 target-generation start-target"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "2"


def test_cli_started_worker_receipt_blocks_second_start_until_proven_dead(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    mutation_log = tmp_path / "mutation.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        owner_ready = Path(sys.argv[3])
        release_owner = Path(sys.argv[4])
        worker_dead = Path(sys.argv[5])
        dead_check_log = Path(sys.argv[6])
        mutation_log = Path(sys.argv[7])
        persisted_log = Path(sys.argv[8])
        request_id = sys.argv[9]
        lock_timeout = float(sys.argv[10])
        clock = {"value": 100.0}
        identity = ProcessIdentity(
            pid=42,
            generation="started-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user",
            start_marker="start-started",
        )

        def persist(home, snapshot):
            with persisted_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            cli._persist_snapshot(home, snapshot)

        def inspect(_home, _state):
            if role == "owner":
                return ServiceInspection("unavailable", "service_missing")
            return ServiceInspection("unavailable", "service_unresponsive", identity, True)

        def process_dead(current):
            if (
                current.pid != 42
                or current.generation != "started-generation"
                or current.start_marker != "start-started"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{current.pid} {current.generation} {current.start_marker}\\n")
            return worker_dead.exists()

        def start(_home, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} start\\n")
            return StartResult(True, identity)

        def stop(_identity, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} stop\\n")
            return StopResult(True)

        def ready(_home, current, _remaining):
            if role == "owner":
                clock["value"] = 101.0
                return ReadyResult(False, identity, "startup_failed")
            return ReadyResult(True, current or identity)

        hooks = RecoveryHooks(
            clock=lambda: clock["value"],
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=inspect,
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=start,
            verify_ready=ready,
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=1.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            owner_ready.write_text("ready", encoding="utf-8")
            while not release_owner.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "41414141-4141-4414-8414-414141414141"
    contender_id = "42424242-4242-4424-8424-424242424242"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(worker_dead),
            str(dead_check_log),
            str(mutation_log),
            str(persisted_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]
        persisted = recovery_cli._load_latest_snapshot(guard_home)
        assert persisted is not None
        assert persisted["phase"] == "failed"
        assert persisted["workerActive"] is True

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender " not in mutation_log.read_text(encoding="utf-8")
        assert recovery_cli._load_latest_snapshot(guard_home)["phase"] == "failed"

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        mutation = mutation_log.read_text(encoding="utf-8")
        assert "contender stop" in mutation
        assert "contender start" in mutation
        assert all(
            line == "42 started-generation start-started"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "3"


def test_required_authorization_releases_before_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize=AuthorizationDecision(False, True, "approval_required"),
        calls=calls,
    )

    result = coordinator.restart("66666666-6666-4666-8666-666666666666")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"
    assert result["workerActive"] is False
    assert calls == ["inspect"]


def test_missing_authorization_hook_fails_closed(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    hooks = RecoveryHooks(
        load_state=lambda _home: None,
        inspect_service=lambda *_args: ServiceInspection("unavailable", "service_missing"),
        protection_posture=lambda _home: "on",
        update_busy=lambda _home: False,
    )

    result = UserRecoveryCoordinator(guard_home, hooks=hooks).restart("77777777-7777-4777-8777-777777777777")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"


def test_recovery_lock_is_acquired_before_start_lock(tmp_path: Path) -> None:
    calls: list[str] = []

    @contextmanager
    def lock(name: str):
        calls.append(f"enter:{name}")
        try:
            yield
        finally:
            calls.append(f"exit:{name}")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        recovery_lock=lambda *_args: lock("recovery"),
        start_lock=lambda *_args: lock("start"),
        start_process=lambda *_args: StartResult(True, _identity(tmp_path / "guard-home")),
    )

    result = coordinator.restart("88888888-8888-4888-8888-888888888888")

    assert result["phase"] == "complete"
    assert calls.index("enter:recovery") < calls.index("enter:start")
    assert calls.index("exit:start") < calls.index("exit:recovery")


def test_generation_change_immediately_before_stop_never_mutates(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    original = _identity(guard_home)
    replacement = _identity(guard_home, generation="generation-2")
    inspections = 0
    calls: list[str] = []

    def inspect() -> ServiceInspection:
        nonlocal inspections
        inspections += 1
        identity = replacement if inspections >= 4 else original
        return ServiceInspection("unavailable", "service_unresponsive", identity, True)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", original, True),
        inspect_service=inspect,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("99999999-9999-4999-8999-999999999999")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_default_update_probe_uses_existing_update_owner(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    monkeypatch.setattr(dashboard_update, "dashboard_update_in_progress", lambda home: home == guard_home)

    coordinator = UserRecoveryCoordinator(guard_home)

    assert coordinator._update_busy() is True
