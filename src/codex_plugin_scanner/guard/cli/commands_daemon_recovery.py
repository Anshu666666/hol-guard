"""Strict CLI adapter for user-requested daemon recovery."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import TextIO

from ..daemon.user_recovery import RecoveryHooks, UserRecoveryCoordinator
from ..daemon.user_recovery_contract import (
    RecoveryContractError,
    encode_recovery_event,
    validate_recovery_snapshot,
)
from ..native_command_control_authority_io import read_private_state, write_private_state

_STATE_NAME = "daemon-user-recovery.json"
_MAX_STATE_BYTES = 16 * 1024


def _uuid(value: object, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{field}_invalid") from error


def _persist_snapshot(guard_home: Path, snapshot: object) -> None:
    validated = validate_recovery_snapshot(snapshot, allow_inspection=False)
    payload = encode_recovery_event(validated)
    write_private_state(guard_home, _STATE_NAME, payload, _MAX_STATE_BYTES)


def _load_snapshot(guard_home: Path, operation_id: uuid.UUID) -> dict[str, object]:
    payload = read_private_state(guard_home, _STATE_NAME, _MAX_STATE_BYTES)
    if payload is None:
        raise KeyError(str(operation_id))
    try:
        decoded = json.loads(payload)
        snapshot = validate_recovery_snapshot(decoded, allow_inspection=False)
    except (json.JSONDecodeError, UnicodeDecodeError, RecoveryContractError) as error:
        raise RuntimeError("recovery_state_invalid") from error
    if snapshot["operationId"] != str(operation_id):
        raise KeyError(str(operation_id))
    return snapshot


def _write_json(payload: dict[str, object], stream: TextIO) -> None:
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def _restart_exit_code(snapshot: dict[str, object]) -> int:
    if snapshot["phase"] == "complete":
        return 0
    if snapshot["phase"] == "waiting_for_owner" or snapshot["workerActive"] is True:
        return 3
    if snapshot["requiresHumanAction"] is True or snapshot["phase"] in {"awaiting_approval", "needs_action"}:
        return 2
    return 1


def _write_human(snapshot: dict[str, object], stream: TextIO) -> None:
    stream.write(
        "HOL Guard recovery\n"
        f"  Operation: {snapshot['operationId']}\n"
        f"  Phase: {snapshot['phase']}\n"
        f"  Service: {snapshot['service']}\n"
        f"  Protection: {snapshot['protection']}\n"
        f"  Result: {snapshot['outcome']} ({snapshot['reasonCode']})\n"
    )
    stream.flush()


def dispatch_daemon_recovery(
    args: object,
    *,
    guard_home: Path,
    home_dir: Path | None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Dispatch the frozen recovery protocol without legacy fallbacks."""

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    command = getattr(args, "daemon_recovery_command", None)
    try:
        if command == "inspect":
            snapshot = UserRecoveryCoordinator(guard_home, home_dir=home_dir).inspect()
            _write_json(snapshot, out)
            return 0
        if command == "status":
            operation_id = _uuid(getattr(args, "operation_id", None), field="operation_id")
            snapshot = _load_snapshot(guard_home, operation_id)
            _write_json(snapshot, out)
            return 0
        if command == "restart":
            request_value = getattr(args, "request_id", None)
            request_id = _uuid(request_value, field="request_id") if request_value else uuid.uuid4()
            hooks = RecoveryHooks(
                authorize=lambda *_args: True,
                persist_snapshot=_persist_snapshot,
            )
            coordinator = UserRecoveryCoordinator(guard_home, home_dir=home_dir, hooks=hooks)
            emit = (lambda snapshot: _write_json(snapshot, out)) if getattr(args, "json_lines", False) else None
            snapshot = coordinator.restart(request_id=request_id, emit=emit)
            if emit is None:
                _write_human(snapshot, out)
            return _restart_exit_code(snapshot)
        raise ValueError("daemon_recovery_command_invalid")
    except (KeyError, OSError, RuntimeError, ValueError, RecoveryContractError) as error:
        err.write(f"HOL Guard recovery failed: {error}\n")
        err.flush()
        return 2


__all__ = ["dispatch_daemon_recovery"]
