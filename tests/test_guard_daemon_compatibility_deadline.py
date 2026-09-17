"""Compatibility admission shares the original accepted-connection budget."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview, HookProcessRunner
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler_contracts import RuntimeHookAdmission
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler_types import RuntimeHookLane


@dataclass
class Clock:
    now: float = 100.4

    def __call__(self) -> float:
        return self.now


@dataclass
class CompatibilityCase:
    handler: daemon_server._GuardDaemonHandler
    scheduler: RuntimeHookScheduler
    clock: Clock
    home: Path
    admission_deadlines: list[float] = field(default_factory=list)
    runner_deadlines: list[float] = field(default_factory=list)
    responses: list[dict[str, object]] = field(default_factory=list)
    return_at: float | None = None

    def invoke(self, event: str, *, outer_deadline: float | None = 104.0) -> None:
        self.handler._handle_runtime_hook_compatibility_cli(
            {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "echo bounded"}},
            {},
            hook_env={},
            default_harness="pi",
            home_dir=str(self.home),
            guard_home=str(self.home),
            workspace=str(self.home),
            deadline=outer_deadline,
        )

    def assert_released(self) -> None:
        stats = self.scheduler.stats()
        assert stats["active"] == stats["queued"] == stats["retained_bytes"] == 0


@pytest.fixture
def compatibility_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[CompatibilityCase]:
    # No server start, store, worker process or socket I/O: retain the real
    # socket-identity deadline lookup and real scheduler admission/permit code.
    clock = Clock()
    monkeypatch.setattr(daemon_server, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(daemon_server, "_native_mode_requires_rust", lambda: False)
    scheduler = RuntimeHookScheduler(active_limit=1, monotonic=clock)
    server = object.__new__(daemon_server._GuardDaemonHttpServer)
    server.request_capacity_lock = threading.Lock()
    server.runtime_hook_process_scheduler = scheduler
    runner = object.__new__(HookProcessRunner)
    server.hook_process_runner = runner
    with socket.socket() as request:
        server.request_accepted_at = {id(request): 100.0}
        handler = object.__new__(daemon_server._GuardDaemonHandler)
        handler.server = server
        handler.request = request
        case = CompatibilityCase(handler, scheduler, clock, tmp_path)
        original_acquire = scheduler.acquire

        def acquire(
            *,
            harness: str,
            client_key: str,
            lane: RuntimeHookLane,
            payload_bytes: int,
            deadline: float,
        ) -> RuntimeHookAdmission:
            case.admission_deadlines.append(deadline)
            return original_acquire(
                harness=harness,
                client_key=client_key,
                lane=lane,
                payload_bytes=payload_bytes,
                deadline=deadline,
            )

        def review(**kwargs: object) -> HookProcessReview:
            deadline = kwargs["deadline"]
            assert isinstance(deadline, float)
            case.runner_deadlines.append(deadline)
            if case.return_at is not None:
                clock.now = case.return_at
            return HookProcessReview({"decision": "allow"}, None)

        def fallback(*_args: object, reason_code: str, **_kwargs: object) -> dict[str, object]:
            # Isolate deadline selection/discard from configuration reads and
            # harness-specific rendering; this marker is not a wire contract.
            return {"test_fallback": reason_code}

        def observe_load(*, queue_p95_ms: float, queued: int) -> None:
            assert queue_p95_ms == 0.0
            assert queued == 0

        monkeypatch.setattr(scheduler, "acquire", acquire)
        monkeypatch.setattr(runner, "review", review)
        monkeypatch.setattr(runner, "observe_load", observe_load)
        monkeypatch.setattr(handler, "_write_json", case.responses.append)
        monkeypatch.setattr(handler, "_runtime_hook_fail_safe_response", fallback)
        yield case
        assert server.request_accepted_at == {id(request): 100.0}
        case.assert_released()


@pytest.mark.parametrize(("event", "expected"), [("PreToolUse", 101.45), ("PostToolUse", 102.75)])
@pytest.mark.parametrize("outer_deadline", [None, 104.0])
def test_compatibility_budget_starts_at_connection_acceptance(
    compatibility_case: CompatibilityCase, event: str, expected: float, outer_deadline: float | None
) -> None:
    compatibility_case.invoke(event, outer_deadline=outer_deadline)
    assert compatibility_case.admission_deadlines == [expected]
    assert compatibility_case.runner_deadlines == [expected]
    assert compatibility_case.responses == [{"decision": "allow"}]
    assert compatibility_case.scheduler.stats()["completed"] == 1


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_earlier_outer_deadline_is_preserved(compatibility_case: CompatibilityCase, event: str) -> None:
    compatibility_case.invoke(event, outer_deadline=101.3)
    assert compatibility_case.admission_deadlines == [101.3]
    assert compatibility_case.runner_deadlines == [101.3]
    assert compatibility_case.responses == [{"decision": "allow"}]


@pytest.mark.parametrize(("event", "expiry"), [("PreToolUse", 101.45), ("PostToolUse", 102.75)])
def test_expired_acceptance_budget_never_starts_runner(
    compatibility_case: CompatibilityCase, event: str, expiry: float
) -> None:
    compatibility_case.clock.now = expiry
    compatibility_case.invoke(event)
    assert compatibility_case.admission_deadlines == [expiry]
    assert compatibility_case.runner_deadlines == []
    assert compatibility_case.responses == [{"test_fallback": "daemon_hook_deadline_exhausted"}]
    assert compatibility_case.scheduler.stats()["admitted"] == 0


@pytest.mark.parametrize(("event", "expiry"), [("PreToolUse", 101.45), ("PostToolUse", 102.75)])
@pytest.mark.parametrize("late_by", [0.0, 0.001])
def test_payload_at_or_after_anchored_deadline_is_discarded(
    compatibility_case: CompatibilityCase, event: str, expiry: float, late_by: float
) -> None:
    compatibility_case.return_at = expiry + late_by
    compatibility_case.invoke(event)
    assert compatibility_case.runner_deadlines == [expiry]
    assert compatibility_case.responses == [{"test_fallback": "daemon_hook_process_deadline_exhausted"}]
    assert compatibility_case.scheduler.stats()["completed"] == 1


@pytest.mark.parametrize(("event", "expiry"), [("PreToolUse", 101.45), ("PostToolUse", 102.75)])
def test_payload_before_anchored_deadline_is_retained(
    compatibility_case: CompatibilityCase, event: str, expiry: float
) -> None:
    compatibility_case.return_at = expiry - 0.001
    compatibility_case.invoke(event)
    assert compatibility_case.runner_deadlines == [expiry]
    assert compatibility_case.responses == [{"decision": "allow"}]
