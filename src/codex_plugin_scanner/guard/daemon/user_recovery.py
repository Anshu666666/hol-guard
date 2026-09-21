"""Narrow, user-requested Guard daemon recovery coordination.

This module owns the decision sequence for the new recovery operation.  It is
deliberately separate from hook recovery and runtime repair: inspection is
read-only, and a replacement is attempted only after the current process has
been identified and its exit has been confirmed.
"""

from __future__ import annotations

import inspect as _inspect
import os
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, cast

from .user_recovery_contract import (
    CAPABILITIES,
    CHECK_IDS,
    REASON_CODES,
    RecoveryContractError,
    validate_recovery_snapshot,
)

Clock = Callable[[], float]
WallClock = Callable[[], datetime]
Hook = Callable[..., object]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Private identity evidence for one daemon generation.

    These fields never appear in a public snapshot.  A recovery target must
    retain the same PID, generation, runtime, and Guard home between the
    initial inspection and the stop decision.
    """

    pid: int
    generation: str
    runtime: str
    guard_home: Path
    user: str | None = None
    start_marker: str | None = None


@dataclass(frozen=True, slots=True)
class ServiceInspection:
    """Private result from the authenticated service/process probe."""

    service: str
    reason_code: str
    identity: ProcessIdentity | None = None
    process_running: bool = False
    authenticated: bool = False
    dashboard_ready: bool = False
    protection: str = "unknown"
    checks: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Result of the existing local administrative authorization policy."""

    allowed: bool
    requires_human_action: bool = False
    reason_code: str = "approval_required"


@dataclass(frozen=True, slots=True)
class StopResult:
    """Result of an ownership-checked stop attempt."""

    exit_confirmed: bool
    reason_code: str = "healthy"


@dataclass(frozen=True, slots=True)
class StartResult:
    """Result of launching the already-selected installed runtime."""

    started: bool
    identity: ProcessIdentity | None = None
    reason_code: str = "startup_failed"


@dataclass(frozen=True, slots=True)
class ReadyResult:
    """Authenticated readiness result after a reconnect or start."""

    ready: bool
    identity: ProcessIdentity | None = None
    reason_code: str = "startup_failed"


@dataclass(frozen=True, slots=True)
class ProtectionResult:
    """Fresh protection-health evidence, kept separate from connectivity."""

    state: str
    reason_code: str = "unknown"


@dataclass(frozen=True, slots=True)
class RecoveryHooks:
    """Deterministic seams for Core lifecycle and focused unit tests.

    ``None`` values use the narrow existing daemon helpers.  Hook callables
    may accept the arguments documented by their use below or fewer positional
    arguments; this keeps small test doubles readable without exposing extra
    state through the public DTO.
    """

    clock: Clock | None = None
    wall_clock: WallClock | None = None
    load_state: Hook | None = None
    inspect_service: Hook | None = None
    protection_posture: Hook | None = None
    update_busy: Hook | None = None
    authorize: Hook | None = None
    recovery_lock: Hook | None = None
    start_lock: Hook | None = None
    stop_process: Hook | None = None
    process_dead: Hook | None = None
    start_process: Hook | None = None
    verify_ready: Hook | None = None
    protection_health: Hook | None = None
    persist_snapshot: Hook | None = None


@dataclass(slots=True)
class _Inspection:
    service: ServiceInspection
    protection_posture: str
    update_busy: bool


@dataclass(slots=True)
class _Operation:
    operation_id: uuid.UUID
    request_id: uuid.UUID
    started_monotonic: float
    started_at: str
    sequence: int = -1
    latest: dict[str, object] | None = None
    events: list[dict[str, object]] = field(default_factory=list)


_OPERATIONS_LOCK = RLock()
_ACTIVE_BY_HOME: dict[str, _Operation] = {}
_ACTIVE_BY_ID: dict[str, _Operation] = {}
_COMPLETED_BY_ID: dict[str, _Operation] = {}
_MAX_COMPLETED_OPERATIONS = 64


def _manager():
    from . import manager

    return manager


def _call_hook(hook: Hook, *args: object) -> object:
    """Call a seam with the largest positional prefix it accepts."""

    try:
        signature = _inspect.signature(hook)
    except (TypeError, ValueError):
        return hook(*args)
    for count in range(len(args), -1, -1):
        try:
            signature.bind(*args[:count])
        except TypeError:
            continue
        return hook(*args[:count])
    return hook(*args)


def _normal_reason(value: object, fallback: str = "unknown") -> str:
    return value if isinstance(value, str) and value in REASON_CODES else fallback


def _normal_service(value: object) -> str:
    return value if isinstance(value, str) and value in {"unknown", "unavailable", "ready"} else "unknown"


def _normal_protection(value: object) -> str:
    return (
        value
        if isinstance(value, str) and value in {"unknown", "verified", "needs_attention", "off"}
        else "unknown"
    )


def _normal_check_result(value: object) -> str:
    return value if isinstance(value, str) and value in {"pass", "fail", "unknown"} else "unknown"


def _safe_path(value: object) -> Path | None:
    if not isinstance(value, (str, Path)):
        return None
    try:
        return Path(value).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _identity_from_value(value: object, guard_home: Path) -> ProcessIdentity | None:
    if isinstance(value, ProcessIdentity):
        return value
    if not isinstance(value, Mapping):
        return None
    pid = value.get("pid")
    if type(pid) is not int or pid <= 0:
        return None
    generation = value.get("generation", value.get("state_id"))
    runtime = value.get("runtime", value.get("runtime_fingerprint"))
    candidate_home = _safe_path(value.get("guard_home")) or guard_home
    if not isinstance(generation, str) or not generation or not isinstance(runtime, str) or not runtime:
        return None
    user = value.get("user", value.get("uid"))
    start_marker = value.get("start_marker", value.get("process_start_marker"))
    return ProcessIdentity(
        pid=pid,
        generation=generation,
        runtime=runtime,
        guard_home=candidate_home,
        user=str(user) if user is not None else _current_user_marker(),
        start_marker=(str(start_marker) if start_marker is not None else None),
    )


def _current_user_marker() -> str:
    if hasattr(os, "geteuid"):
        return f"uid:{os.geteuid()}"
    return "current-user"


def _identity_matches(left: ProcessIdentity | None, right: ProcessIdentity | None, guard_home: Path) -> bool:
    if left is None or right is None:
        return False
    try:
        homes_match = left.guard_home.resolve() == right.guard_home.resolve() == guard_home.resolve()
    except (OSError, RuntimeError):
        homes_match = left.guard_home == right.guard_home == guard_home
    if not homes_match or left.pid != right.pid or left.generation != right.generation or left.runtime != right.runtime:
        return False
    if left.start_marker is not None and right.start_marker is not None and left.start_marker != right.start_marker:
        return False
    return not (left.user is not None and right.user is not None and left.user != right.user)


def _coerce_service(value: object, guard_home: Path, state: Mapping[str, object] | None) -> ServiceInspection:
    if isinstance(value, ServiceInspection):
        return value
    if value is None:
        return ServiceInspection("unknown", "unknown")
    if isinstance(value, bool):
        return ServiceInspection(
            "ready" if value else "unavailable",
            "healthy" if value else "service_unresponsive",
            _identity_from_value(state, guard_home) if value else None,
            process_running=value,
            authenticated=value,
            dashboard_ready=value,
        )
    if not isinstance(value, Mapping):
        return ServiceInspection("unknown", "unknown")
    identity = _identity_from_value(value.get("identity", state), guard_home)
    service = _normal_service(value.get("service"))
    healthy = value.get("healthy") is True
    if service == "unknown" and healthy:
        service = "ready"
    if service == "unknown" and value.get("process_running") is False:
        service = "unavailable"
    reason = _normal_reason(value.get("reason_code", value.get("reasonCode")))
    if reason == "unknown" and service == "ready":
        reason = "healthy"
    if reason == "unknown" and service == "unavailable":
        reason = "service_unresponsive"
    return ServiceInspection(
        service=service,
        reason_code=reason,
        identity=identity,
        process_running=value.get("process_running") is True or identity is not None,
        authenticated=value.get("authenticated") is True or service == "ready",
        dashboard_ready=value.get("dashboard_ready") is True or service == "ready",
        protection=_normal_protection(value.get("protection")),
        checks=tuple(_coerce_checks(value.get("checks"))),
    )


def _coerce_checks(value: object) -> list[dict[str, str]]:
    if not isinstance(value, (list, tuple)):
        return []
    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            continue
        check_id = item.get("id")
        if check_id not in CHECK_IDS or check_id in seen:
            continue
        seen.add(cast(str, check_id))
        checks.append(
            {
                "id": cast(str, check_id),
                "result": _normal_check_result(item.get("result")),
                "reasonCode": _normal_reason(item.get("reasonCode")),
            }
        )
    return checks


def _coerce_authorization(value: object) -> AuthorizationDecision:
    if isinstance(value, AuthorizationDecision):
        return value
    if value is True:
        return AuthorizationDecision(True)
    if isinstance(value, Mapping):
        allowed = value.get("allowed") is True
        required = value.get("requires_human_action") is True or value.get("requiresHumanAction") is True
        return AuthorizationDecision(
            allowed, required, _normal_reason(value.get("reason_code", value.get("reasonCode")), "approval_required")
        )
    return AuthorizationDecision(False, True, "approval_required")


def _coerce_stop(value: object) -> StopResult:
    if isinstance(value, StopResult):
        return value
    if value is True:
        return StopResult(True)
    if isinstance(value, Mapping):
        confirmed = value.get("exit_confirmed") is True or value.get("confirmed_exit") is True
        return StopResult(
            confirmed, _normal_reason(value.get("reason_code", value.get("reasonCode")), "worker_exit_unconfirmed")
        )
    return StopResult(False, "worker_exit_unconfirmed")


def _coerce_start(value: object) -> StartResult:
    if isinstance(value, StartResult):
        return value
    if isinstance(value, str) and value:
        return StartResult(True)
    if value is True:
        return StartResult(True)
    if isinstance(value, Mapping):
        started = value.get("started") is True
        return StartResult(
            started,
            _identity_from_value(value.get("identity"), Path.cwd()),
            _normal_reason(value.get("reason_code", value.get("reasonCode")), "startup_failed"),
        )
    return StartResult(False, None, "startup_failed")


def _coerce_ready(value: object) -> ReadyResult:
    if isinstance(value, ReadyResult):
        return value
    if value is True:
        return ReadyResult(True)
    if isinstance(value, Mapping):
        return ReadyResult(
            value.get("ready") is True,
            _identity_from_value(value.get("identity"), Path.cwd()),
            _normal_reason(
                value.get("reason_code", value.get("reasonCode")),
                "healthy" if value.get("ready") is True else "startup_failed",
            ),
        )
    return ReadyResult(False, None, "startup_failed")


def _coerce_protection(value: object) -> ProtectionResult:
    if isinstance(value, ProtectionResult):
        return value
    if value is True:
        return ProtectionResult("verified", "healthy")
    if value is False:
        return ProtectionResult("needs_attention", "unknown")
    if isinstance(value, str):
        return ProtectionResult(_normal_protection(value), "healthy" if value == "verified" else "unknown")
    if isinstance(value, Mapping):
        state = _normal_protection(value.get("state", value.get("protection")))
        return ProtectionResult(state, _normal_reason(value.get("reason_code", value.get("reasonCode"))))
    return ProtectionResult("unknown", "unknown")


def _timestamp(value: object) -> str:
    current = value if isinstance(value, datetime) else _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.isoformat()


class UserRecoveryCoordinator:
    """Coordinate one bounded, identity-safe user recovery attempt."""

    def __init__(
        self,
        guard_home: Path,
        *,
        home_dir: Path | None = None,
        hooks: RecoveryHooks | None = None,
        dependencies: RecoveryHooks | None = None,
        active_budget_seconds: float = 60.0,
        lock_timeout_seconds: float = 0.0,
    ) -> None:
        self.guard_home = Path(guard_home).expanduser().resolve()
        self.home_dir = Path(home_dir).expanduser().resolve() if home_dir is not None else None
        self.hooks = hooks or dependencies or RecoveryHooks()
        self.active_budget_seconds = max(0.0, float(active_budget_seconds))
        self.lock_timeout_seconds = max(0.0, float(lock_timeout_seconds))

    # Public aliases keep the facade useful to the future CLI/native adapters
    # without moving lifecycle decisions into either adapter.
    def inspect_recovery(self) -> dict[str, object]:
        return self.inspect()

    def begin(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        return self.restart(request_id=request_id, emit=emit)

    def recover(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        return self.restart(request_id=request_id, emit=emit)

    def inspect(self) -> dict[str, object]:
        """Return read-only classification without creating files or processes."""

        with _OPERATIONS_LOCK:
            active = _ACTIVE_BY_HOME.get(str(self.guard_home))
            if active is not None and active.latest is not None:
                return dict(active.latest)
        inspection = self._inspect()
        return self._snapshot(
            operation_id=None,
            sequence=0,
            started_at=self._now_timestamp(),
            phase="checking",
            active_elapsed_ms=0,
            worker_active=False,
            retry_allowed=not inspection.update_busy and inspection.protection_posture == "on",
            outcome="pending",
            reason_code=self._inspection_reason(inspection),
            service=inspection.service.service,
            protection=self._inspection_protection(inspection),
            requires_human_action=inspection.protection_posture == "off"
            or inspection.service.reason_code
            in {"identity_unverified", "runtime_mismatch", "endpoint_conflict", "multiple_instances"},
            checks=self._checks(inspection),
        )

    def status(self, operation_id: str | uuid.UUID) -> dict[str, object]:
        parsed = self._parse_uuid(operation_id, field="operation_id")
        with _OPERATIONS_LOCK:
            operation = _ACTIVE_BY_ID.get(str(parsed)) or _COMPLETED_BY_ID.get(str(parsed))
            if operation is None or operation.latest is None:
                raise KeyError(str(parsed))
            return dict(operation.latest)

    def diagnostics(self, operation_id: str | uuid.UUID) -> dict[str, object]:
        """Return a bounded privacy-safe report for one known operation."""

        parsed = self._parse_uuid(operation_id, field="operation_id")
        with _OPERATIONS_LOCK:
            operation = _ACTIVE_BY_ID.get(str(parsed)) or _COMPLETED_BY_ID.get(str(parsed))
            if operation is None or operation.latest is None:
                raise KeyError(str(parsed))
            events = list(operation.events) or [dict(operation.latest)]
        from .recovery_diagnostics import build_recovery_diagnostics

        return build_recovery_diagnostics(events)

    export_diagnostics = diagnostics

    def restart(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        parsed_request = self._parse_uuid(request_id, field="request_id") if request_id is not None else uuid.uuid4()
        home_key = str(self.guard_home)
        with _OPERATIONS_LOCK:
            active = _ACTIVE_BY_HOME.get(home_key)
            if active is not None:
                if active.request_id == parsed_request or active.latest is None:
                    return dict(active.latest or {})
                return dict(active.latest)
            operation = _Operation(
                operation_id=parsed_request,
                request_id=parsed_request,
                started_monotonic=self._clock() if self.hooks.clock else time.monotonic(),
                started_at=self._now_timestamp(),
            )
            _ACTIVE_BY_HOME[home_key] = operation
            _ACTIVE_BY_ID[str(operation.operation_id)] = operation
        try:
            return self._run(operation, emit)
        finally:
            with _OPERATIONS_LOCK:
                _ACTIVE_BY_HOME.pop(home_key, None)
                _ACTIVE_BY_ID.pop(str(operation.operation_id), None)
                _COMPLETED_BY_ID[str(operation.operation_id)] = operation
                while len(_COMPLETED_BY_ID) > _MAX_COMPLETED_OPERATIONS:
                    _COMPLETED_BY_ID.pop(next(iter(_COMPLETED_BY_ID)))

    def _run(self, operation: _Operation, emit: Hook | None) -> dict[str, object]:
        initial = self._inspect()
        self._emit(operation, emit, phase="checking", inspection=initial, worker_active=True, retry_allowed=False)
        if initial.protection_posture != "on":
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=initial,
                reason_code="protection_off" if initial.protection_posture == "off" else "unknown",
                requires_human_action=True,
            )
        if initial.update_busy:
            return self._finish_action(
                operation,
                emit,
                phase="waiting_for_owner",
                inspection=initial,
                reason_code="update_busy",
                worker_active=False,
                retry_allowed=False,
            )
        decision = self._authorize()
        if decision.requires_human_action and not decision.allowed:
            return self._finish_action(
                operation,
                emit,
                phase="awaiting_approval",
                inspection=initial,
                reason_code=decision.reason_code,
                worker_active=False,
                retry_allowed=False,
                requires_human_action=True,
            )
        if not decision.allowed:
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=initial,
                reason_code=decision.reason_code,
                worker_active=False,
                retry_allowed=False,
                requires_human_action=True,
            )
        remaining = self._remaining(operation)
        if remaining <= 0.0:
            return self._timeout(operation, emit, initial)
        try:
            with self._recovery_lock(remaining):
                current = self._inspect()
                self._emit(
                    operation, emit, phase="checking", inspection=current, worker_active=True, retry_allowed=False
                )
                if current.protection_posture != "on":
                    return self._finish_action(
                        operation,
                        emit,
                        phase="needs_action",
                        inspection=current,
                        reason_code="protection_off" if current.protection_posture == "off" else "unknown",
                        requires_human_action=True,
                    )
                if current.update_busy:
                    return self._finish_action(
                        operation,
                        emit,
                        phase="waiting_for_owner",
                        inspection=current,
                        reason_code="update_busy",
                        worker_active=False,
                        retry_allowed=False,
                    )
                if current.service.service == "ready":
                    return self._reconnect(operation, emit, current)
                if current.service.reason_code not in {"service_missing", "service_unresponsive"}:
                    return self._finish_action(
                        operation,
                        emit,
                        phase="needs_action",
                        inspection=current,
                        reason_code=current.service.reason_code,
                        requires_human_action=True,
                    )
                if current.service.reason_code == "service_unresponsive":
                    return self._replace(operation, emit, current)
                return self._start_missing(operation, emit, current)
        except (TimeoutError, RuntimeError, OSError):
            return self._finish_action(
                operation,
                emit,
                phase="waiting_for_owner",
                inspection=initial,
                reason_code="operation_busy",
                worker_active=False,
                retry_allowed=False,
            )

    def _reconnect(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        self._emit(
            operation, emit, phase="reconnecting", inspection=inspection, worker_active=True, retry_allowed=False
        )
        ready = self._verify_ready(inspection.service.identity, self._remaining(operation))
        if not ready.ready:
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code=ready.reason_code,
                requires_human_action=ready.reason_code in {"session_invalid", "approval_required"},
            )
        return self._verify_protection(
            operation,
            emit,
            inspection,
            ready.identity or inspection.service.identity,
            outcome="reconnected",
        )

    def _replace(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        with self._start_lock_scope(self._remaining(operation), already_held=False):
            target = inspection.service.identity
            if target is None:
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=inspection,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            rechecked = self._inspect()
            if not _identity_matches(target, rechecked.service.identity, self.guard_home):
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=rechecked,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            # A final read immediately before the stop protects against PID
            # reuse or generation changes while the progress event is emitted.
            before_stop = self._inspect()
            if not _identity_matches(target, before_stop.service.identity, self.guard_home):
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=before_stop,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            self._emit(
                operation, emit, phase="stopping", inspection=before_stop, worker_active=True, retry_allowed=False
            )
            try:
                stop = _coerce_stop(self._stop_process(target, self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                stop = StopResult(False, "worker_exit_unconfirmed")
            if not stop.exit_confirmed:
                try:
                    exited = bool(_call_hook(self._process_dead, target))
                except (OSError, RuntimeError, TimeoutError):
                    exited = False
                if not exited:
                    return self._timeout(operation, emit, before_stop)
            return self._start_after_stop(operation, emit, before_stop, outcome="restarted")

    def _start_missing(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        with self._start_lock_scope(self._remaining(operation), already_held=False):
            rechecked = self._inspect()
            if rechecked.service.service == "ready":
                return self._reconnect(operation, emit, rechecked)
            if rechecked.service.reason_code != "service_missing":
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=rechecked,
                    reason_code=rechecked.service.reason_code,
                    requires_human_action=True,
                )
            self._emit(operation, emit, phase="starting", inspection=rechecked, worker_active=True, retry_allowed=False)
            try:
                started = _coerce_start(self._start_process(self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                started = StartResult(False, None, "startup_failed")
            if not started.started:
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=rechecked,
                    reason_code=started.reason_code,
                    requires_human_action=True,
                )
            return self._start_after_stop(operation, emit, rechecked, outcome="started", started=started)

    def _start_after_stop(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
        *,
        outcome: str,
        started: StartResult | None = None,
    ) -> dict[str, object]:
        if started is None:
            self._emit(
                operation, emit, phase="starting", inspection=inspection, worker_active=True, retry_allowed=False
            )
            try:
                started = _coerce_start(self._start_process(self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                started = StartResult(False, None, "startup_failed")
            if not started.started:
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=inspection,
                    reason_code=started.reason_code,
                    requires_human_action=True,
                )
        self._emit(
            operation, emit, phase="reconnecting", inspection=inspection, worker_active=True, retry_allowed=False
        )
        identity = started.identity if started is not None else None
        try:
            ready = self._verify_ready(identity, self._remaining(operation))
        except (ImportError, OSError, RuntimeError, TimeoutError, TypeError, ValueError):
            ready = ReadyResult(False, None, "startup_failed")
        if not ready.ready:
            return self._finish_action(
                operation,
                emit,
                phase="failed",
                inspection=inspection,
                reason_code=ready.reason_code,
                service="unknown",
                protection="unknown",
                requires_human_action=True,
            )
        return self._verify_protection(
            operation,
            emit,
            inspection,
            ready.identity or identity,
            outcome=outcome,
        )

    def _verify_protection(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
        identity: ProcessIdentity | None,
        *,
        outcome: str,
    ) -> dict[str, object]:
        self._emit(operation, emit, phase="verifying", inspection=inspection, worker_active=True, retry_allowed=False)
        try:
            protection = _coerce_protection(self._protection_health(identity, self._remaining(operation)))
        except (OSError, RuntimeError, TimeoutError):
            protection = ProtectionResult("unknown", "unknown")
        checks = self._checks(inspection)
        self._set_check(checks, "authenticated_service", "pass", "healthy")
        self._set_check(checks, "dashboard_ready", "pass", "healthy")
        self._set_check(
            checks,
            "protection_health",
            "pass"
            if protection.state == "verified"
            else ("fail" if protection.state == "needs_attention" else "unknown"),
            protection.reason_code,
        )
        final = self._emit(
            operation,
            emit,
            phase="complete",
            inspection=inspection,
            reason_code="healthy",
            service="ready",
            protection=protection.state,
            outcome=outcome,
            worker_active=False,
            retry_allowed=True,
            requires_human_action=protection.state == "needs_attention",
            checks=checks,
        )
        return final

    def _finish_action(
        self,
        operation: _Operation,
        emit: Hook | None,
        *,
        phase: str,
        inspection: _Inspection,
        reason_code: str,
        worker_active: bool = False,
        retry_allowed: bool = True,
        requires_human_action: bool = False,
        service: str | None = None,
        protection: str | None = None,
        outcome: str = "not_recovered",
        checks: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        return self._emit(
            operation,
            emit,
            phase=phase,
            inspection=inspection,
            reason_code=reason_code,
            service=service or inspection.service.service,
            protection=protection or self._inspection_protection(inspection),
            outcome=outcome,
            worker_active=worker_active,
            retry_allowed=retry_allowed,
            requires_human_action=requires_human_action,
            checks=checks,
        )

    def _timeout(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        return self._finish_action(
            operation,
            emit,
            phase="timed_out_waiting",
            inspection=inspection,
            reason_code="worker_exit_unconfirmed",
            service="unknown",
            protection="unknown",
            worker_active=True,
            retry_allowed=False,
            requires_human_action=True,
        )

    def _emit(
        self,
        operation: _Operation,
        emit: Hook | None,
        *,
        phase: str,
        inspection: _Inspection,
        worker_active: bool,
        retry_allowed: bool,
        reason_code: str | None = None,
        service: str | None = None,
        protection: str | None = None,
        outcome: str = "pending",
        requires_human_action: bool = False,
        checks: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        operation.sequence += 1
        snapshot = self._snapshot(
            operation_id=operation.operation_id,
            sequence=operation.sequence,
            started_at=operation.started_at,
            phase=phase,
            active_elapsed_ms=int(max(0.0, self._clock() - operation.started_monotonic) * 1000),
            worker_active=worker_active,
            retry_allowed=retry_allowed,
            outcome=outcome,
            reason_code=reason_code or self._inspection_reason(inspection),
            service=service or inspection.service.service,
            protection=protection or self._inspection_protection(inspection),
            requires_human_action=requires_human_action,
            checks=checks if checks is not None else self._checks(inspection),
        )
        operation.latest = snapshot
        operation.events.append(snapshot)
        if self.hooks.persist_snapshot is not None:
            _call_hook(self.hooks.persist_snapshot, self.guard_home, snapshot)
        if emit is not None:
            with suppress(Exception):
                _call_hook(emit, snapshot)
        return snapshot

    def _snapshot(
        self,
        *,
        operation_id: uuid.UUID | None,
        sequence: int,
        started_at: str,
        phase: str,
        active_elapsed_ms: int,
        worker_active: bool,
        retry_allowed: bool,
        outcome: str,
        reason_code: str,
        service: str,
        protection: str,
        requires_human_action: bool,
        checks: list[dict[str, str]],
    ) -> dict[str, object]:
        now = self._now_timestamp()
        payload: dict[str, object] = {
            "schema": "hol-guard-recovery.v1",
            "capabilities": sorted(CAPABILITIES),
            "operationId": str(operation_id) if operation_id is not None else None,
            "sequence": max(0, int(sequence)),
            "startedAt": started_at,
            "updatedAt": now,
            "phase": phase,
            "activeElapsedMs": max(0, int(active_elapsed_ms)),
            "workerActive": bool(worker_active),
            "retryAllowed": bool(retry_allowed),
            "outcome": outcome,
            "reasonCode": _normal_reason(reason_code),
            "service": _normal_service(service),
            "protection": _normal_protection(protection),
            "requiresHumanAction": bool(requires_human_action),
            "checks": _coerce_checks(checks),
        }
        try:
            return validate_recovery_snapshot(payload, allow_inspection=operation_id is None)
        except RecoveryContractError:
            # Internal callers should never expose an invalid event.  Fall back
            # to a conservative, contract-valid unknown snapshot if a test hook
            # supplied an unsupported value.
            payload["phase"] = "needs_action"
            payload["outcome"] = "not_recovered"
            payload["service"] = "unknown"
            payload["protection"] = "unknown"
            payload["reasonCode"] = "unknown"
            payload["workerActive"] = False
            payload["retryAllowed"] = False
            payload["requiresHumanAction"] = True
            payload["checks"] = []
            return validate_recovery_snapshot(payload, allow_inspection=operation_id is None)

    def _inspect(self) -> _Inspection:
        state = self._load_state()
        posture = self._protection_posture()
        update_busy = self._update_busy()
        service = self._inspect_service(state)
        return _Inspection(service, posture, update_busy)

    def _load_state(self) -> Mapping[str, object] | None:
        hook = self.hooks.load_state
        if hook is not None:
            value = _call_hook(hook, self.guard_home)
            return value if isinstance(value, Mapping) else None
        try:
            value = _manager().load_authenticated_daemon_state(self.guard_home)
        except (OSError, RuntimeError, ValueError):
            return None
        return value if isinstance(value, Mapping) else None

    def _inspect_service(self, state: Mapping[str, object] | None) -> ServiceInspection:
        if self.hooks.inspect_service is not None:
            return _coerce_service(
                _call_hook(self.hooks.inspect_service, self.guard_home, state), self.guard_home, state
            )
        return _default_inspect_service(self.guard_home, state)

    def _protection_posture(self) -> str:
        if self.hooks.protection_posture is not None:
            value = _call_hook(self.hooks.protection_posture, self.guard_home)
            return value if isinstance(value, str) and value in {"on", "off", "unknown"} else "unknown"
        try:
            from .recovery_lifecycle import guard_recovery_is_disabled

            return "off" if guard_recovery_is_disabled(self.guard_home) else "on"
        except (OSError, RuntimeError, ValueError):
            return "unknown"

    def _update_busy(self) -> bool:
        if self.hooks.update_busy is not None:
            return _call_hook(self.hooks.update_busy, self.guard_home) is True
        try:
            from .dashboard_update import dashboard_update_in_progress

            return bool(dashboard_update_in_progress(self.guard_home))
        except (OSError, RuntimeError, ValueError):
            return True

    def _authorize(self) -> AuthorizationDecision:
        if self.hooks.authorize is None:
            # T02 does not own the proof transport. A trusted CLI/native
            # caller must provide the existing lifecycle authorization.
            return AuthorizationDecision(False, True, "approval_required")
        return _coerce_authorization(_call_hook(self.hooks.authorize, self.guard_home))

    @contextmanager
    def _recovery_lock(self, remaining: float):
        if self.hooks.recovery_lock is not None:
            lock = _call_hook(self.hooks.recovery_lock, self.guard_home, min(remaining, self.lock_timeout_seconds))
            with cast(Any, lock):
                yield
            return
        with _manager()._guard_daemon_recovery_lock(
            self.guard_home,
            timeout_seconds=min(remaining, self.lock_timeout_seconds),
        ):
            yield

    @contextmanager
    def _start_lock(self, remaining: float):
        if self.hooks.start_lock is not None:
            lock = _call_hook(self.hooks.start_lock, self.guard_home, remaining)
            with cast(Any, lock):
                yield
            return
        deadline = self._clock() + max(0.0, remaining)
        with _manager()._guard_daemon_start_lock(self.guard_home, deadline=deadline):
            yield

    @contextmanager
    def _start_lock_scope(self, remaining: float, *, already_held: bool):
        if already_held:
            with nullcontext():
                yield
            return
        with self._start_lock(remaining):
            yield

    def _stop_process(self, identity: ProcessIdentity, remaining: float) -> object:
        if self.hooks.stop_process is not None:
            return _call_hook(self.hooks.stop_process, identity, remaining)
        manager = _manager()
        if identity.start_marker is not None:
            from ..live_process_identity import process_start_token

            if process_start_token(identity.pid) != identity.start_marker:
                return StopResult(False, "worker_exit_unconfirmed")
        expected_creation_time = None
        if identity.start_marker is not None and identity.start_marker.startswith("windows:"):
            try:
                expected_creation_time = int(identity.start_marker.removeprefix("windows:"))
            except ValueError:
                return StopResult(False, "worker_exit_unconfirmed")
        return manager._retire_guard_daemon_pid(
            identity.pid,
            expected_guard_home=self.guard_home,
            expected_creation_time=expected_creation_time,
        )

    def _process_dead(self, identity: ProcessIdentity) -> object:
        if self.hooks.process_dead is not None:
            return _call_hook(self.hooks.process_dead, identity)
        return _manager()._guard_daemon_pid_is_proven_dead(identity.pid)

    def _start_process(self, remaining: float) -> object:
        if self.hooks.start_process is not None:
            return _call_hook(self.hooks.start_process, self.guard_home, remaining)
        manager = _manager()
        # A verified dead generation may leave a signed tombstone.  Clearing
        # that one record is the narrow state transition needed before a fresh
        # start; no runtime selector or hook configuration is changed.
        if self._load_state() is not None:
            manager.clear_guard_daemon_state(self.guard_home)
        return manager.ensure_guard_daemon(
            self.guard_home,
            home_dir=self.home_dir,
            start_timeout=max(0.0, remaining),
        )

    def _verify_ready(self, identity: ProcessIdentity | None, remaining: float) -> ReadyResult:
        if self.hooks.verify_ready is not None:
            return _coerce_ready(_call_hook(self.hooks.verify_ready, self.guard_home, identity, remaining))
        service = _default_inspect_service(self.guard_home, self._load_state())
        return ReadyResult(
            service.service == "ready" and service.authenticated and service.dashboard_ready,
            service.identity,
            "healthy" if service.service == "ready" else service.reason_code,
        )

    def _protection_health(self, identity: ProcessIdentity | None, remaining: float) -> object:
        if self.hooks.protection_health is not None:
            return _call_hook(self.hooks.protection_health, self.guard_home, identity, remaining)
        if identity is None or remaining <= 0:
            return ProtectionResult("unknown", "unknown")
        from ..approvals import _canonical_managed_installs_for_health, _live_hook_verification
        from ..runtime.protection_health_runtime import build_runtime_protection_health
        from ..store import GuardStore

        store = GuardStore(self.guard_home, prime_policy_integrity=False)
        managed_installs = _canonical_managed_installs_for_health(store.list_managed_installs())
        runtime_state = store.get_runtime_state()
        health = build_runtime_protection_health(
            store=store,
            runtime_state=runtime_state,
            managed_installs=managed_installs,
            hook_verification=_live_hook_verification(managed_installs, store),
            trust_status=store.get_cached_policy_trust_status(),
            now=_utc_now(),
        )
        state = health.get("state")
        if state == "protected":
            return ProtectionResult("verified", "healthy")
        if state in {"partial", "degraded"}:
            return ProtectionResult("needs_attention", "unknown")
        return ProtectionResult("unknown", "unknown")

    def _clock(self) -> float:
        return (self.hooks.clock or time.monotonic)()

    def _now_timestamp(self) -> str:
        return _timestamp((self.hooks.wall_clock or _utc_now)())

    def _remaining(self, operation: _Operation) -> float:
        return max(0.0, self.active_budget_seconds - (self._clock() - operation.started_monotonic))

    def _inspection_reason(self, inspection: _Inspection) -> str:
        if inspection.protection_posture == "off":
            return "protection_off"
        if inspection.update_busy:
            return "update_busy"
        return _normal_reason(inspection.service.reason_code)

    def _inspection_protection(self, inspection: _Inspection) -> str:
        if inspection.protection_posture == "off":
            return "off"
        return _normal_protection(inspection.service.protection)

    def _checks(self, inspection: _Inspection) -> list[dict[str, str]]:
        checks = _coerce_checks(inspection.service.checks)
        self._set_check(
            checks,
            "update_idle",
            "fail" if inspection.update_busy else "pass",
            "update_busy" if inspection.update_busy else "healthy",
        )
        posture_result = (
            "fail"
            if inspection.protection_posture == "off"
            else ("pass" if inspection.protection_posture == "on" else "unknown")
        )
        self._set_check(
            checks, "protection_posture", posture_result, "protection_off" if posture_result == "fail" else "healthy"
        )
        identity_result = "pass" if inspection.service.identity is not None else "unknown"
        self._set_check(checks, "process_identity", identity_result, inspection.service.reason_code)
        self._set_check(checks, "runtime_identity", identity_result, inspection.service.reason_code)
        self._set_check(
            checks,
            "authenticated_service",
            "pass" if inspection.service.authenticated else "unknown",
            inspection.service.reason_code,
        )
        self._set_check(
            checks,
            "dashboard_ready",
            "pass" if inspection.service.dashboard_ready else "unknown",
            inspection.service.reason_code,
        )
        protection = self._inspection_protection(inspection)
        self._set_check(
            checks,
            "protection_health",
            "pass" if protection == "verified" else ("fail" if protection == "needs_attention" else "unknown"),
            inspection.service.reason_code,
        )
        return checks

    @staticmethod
    def _set_check(checks: list[dict[str, str]], check_id: str, result: str, reason_code: str) -> None:
        entry = {"id": check_id, "result": _normal_check_result(result), "reasonCode": _normal_reason(reason_code)}
        for index, check in enumerate(checks):
            if check["id"] == check_id:
                checks[index] = entry
                return
        checks.append(entry)

    @staticmethod
    def _parse_uuid(value: str | uuid.UUID, *, field: str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, str):
            try:
                parsed = uuid.UUID(value)
            except ValueError as error:
                raise ValueError(f"{field} must be a UUID") from error
            if str(parsed) != value.lower():
                raise ValueError(f"{field} must be a canonical UUID")
            return parsed
        raise ValueError(f"{field} must be a UUID")


def _default_inspect_service(guard_home: Path, state: Mapping[str, object] | None) -> ServiceInspection:
    manager = _manager()
    if state is None:
        try:
            inventory = manager._running_guard_daemon_processes_for_guard_home(guard_home)
        except (OSError, RuntimeError, ValueError):
            inventory = []
        if len(inventory) > 1:
            return ServiceInspection("unavailable", "multiple_instances")
        if inventory:
            return ServiceInspection("unavailable", "identity_unverified")
        return ServiceInspection("unavailable", "service_missing")
    identity = _identity_from_value(state, guard_home)
    if identity is None:
        return ServiceInspection("unavailable", "identity_unverified")
    if _safe_path(state.get("guard_home")) not in {None, guard_home.resolve()}:
        return ServiceInspection("unavailable", "identity_unverified", identity, process_running=True)
    try:
        if not manager._guard_daemon_state_matches_current_runtime(dict(state)):
            return ServiceInspection("unavailable", "runtime_mismatch", identity, process_running=True)
        if not manager._guard_daemon_pid_is_running(identity.pid):
            return ServiceInspection("unavailable", "service_missing", identity)
        command_identity = manager._guard_daemon_pid_command_identity(identity.pid, expected_guard_home=guard_home)
        if command_identity is False:
            return ServiceInspection("unavailable", "endpoint_conflict", identity, process_running=True)
        if command_identity is not True:
            return ServiceInspection("unavailable", "identity_unverified", identity, process_running=True)
        from .live_identity import verified_live_guard_daemon_identity

        live = verified_live_guard_daemon_identity(guard_home)
    except (OSError, RuntimeError, ValueError):
        live = None
    if live is None:
        return ServiceInspection("unavailable", "service_unresponsive", identity, process_running=True)
    return ServiceInspection(
        "ready",
        "healthy",
        _identity_from_value(live, guard_home) or identity,
        process_running=True,
        authenticated=True,
        dashboard_ready=True,
    )


def inspect_recovery(guard_home: Path, **kwargs: object) -> dict[str, object]:
    """Functional facade for read-only capability inspection."""

    return UserRecoveryCoordinator(guard_home, **cast(dict[str, Any], kwargs)).inspect()


def restart_guard(guard_home: Path, request_id: str | uuid.UUID | None = None, **kwargs: object) -> dict[str, object]:
    """Functional facade for one bounded user recovery attempt."""

    return UserRecoveryCoordinator(guard_home, **cast(dict[str, Any], kwargs)).restart(request_id=request_id)


RecoveryCoordinator = UserRecoveryCoordinator
CoordinatorHooks = RecoveryHooks

__all__ = [
    "AuthorizationDecision",
    "CoordinatorHooks",
    "ProcessIdentity",
    "ProtectionResult",
    "ReadyResult",
    "RecoveryCoordinator",
    "RecoveryHooks",
    "ServiceInspection",
    "StartResult",
    "StopResult",
    "UserRecoveryCoordinator",
    "inspect_recovery",
    "restart_guard",
]
