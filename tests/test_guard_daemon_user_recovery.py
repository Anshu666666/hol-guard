from __future__ import annotations

from contextlib import contextmanager, nullcontext
from pathlib import Path

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


def _identity(guard_home: Path, *, pid: int = 41, generation: str = "generation-1") -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        generation=generation,
        runtime="runtime-1",
        guard_home=guard_home,
        user="test-user",
        start_marker=f"start-{generation}",
    )


def _coordinator(
    tmp_path: Path,
    service: ServiceInspection,
    *,
    posture: str = "on",
    authorize: AuthorizationDecision | None = None,
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
        clock=lambda: 100.0,
        wall_clock=lambda: __import__("datetime").datetime(2026, 9, 20, tzinfo=__import__("datetime").timezone.utc),
        load_state=lambda _home: {"state": "fixture"},
        inspect_service=inspect,
        protection_posture=lambda _home: posture,
        authorize=lambda _home: authorize if authorize is not None else True,
        update_busy=update_busy or (lambda _home: False),
        recovery_lock=recovery_lock or (lambda *_args: nullcontext()),
        start_lock=start_lock or (lambda *_args: nullcontext()),
        stop_process=stop_process or (lambda _identity, _remaining: StopResult(True)),
        process_dead=process_dead or (lambda _identity: True),
        start_process=start_process or (lambda _home, _remaining: StartResult(True)),
        verify_ready=verify_ready or (lambda _home, identity, _remaining: ReadyResult(True, identity)),
        protection_health=protection_health
        or (lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy")),
    )
    return UserRecoveryCoordinator(guard_home, hooks=hooks)


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

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert result["protection"] == "off"
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
