from __future__ import annotations

import argparse
import io
import json
import sys
import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.cli.approval_gate_prompt import consume_desktop_lifecycle_stdin
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement


def _snapshot(operation_id: uuid.UUID, *, phase: str = "complete") -> dict[str, object]:
    terminal = phase == "complete"
    return {
        "schema": "hol-guard-recovery.v1",
        "capabilities": ["diagnostics", "inspect", "restart", "status"],
        "operationId": str(operation_id),
        "sequence": 1,
        "startedAt": "2026-09-20T12:00:00+00:00",
        "updatedAt": "2026-09-20T12:00:01+00:00",
        "phase": phase,
        "activeElapsedMs": 1000,
        "workerActive": False,
        "retryAllowed": terminal,
        "outcome": "restarted" if terminal else "not_recovered",
        "reasonCode": "healthy" if terminal else "approval_required",
        "service": "ready" if terminal else "unknown",
        "protection": "verified" if terminal else "unknown",
        "requiresHumanAction": not terminal,
        "checks": (
            [{"id": "protection_health", "result": "pass", "reasonCode": "healthy"}]
            if terminal
            else []
        ),
    }


def test_restart_lifecycle_gate_is_strict() -> None:
    args = argparse.Namespace(
        guard_command="daemon",
        daemon_command="recovery",
        daemon_recovery_command="restart",
        dry_run=False,
    )
    requirement = lifecycle_gate_requirement(args)
    assert requirement is not None
    assert requirement.action == "daemon.restart"
    assert requirement.subject == "local-daemon"


def test_private_status_survives_a_new_dispatch(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    cli._persist_snapshot(tmp_path, _snapshot(operation_id))
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 0
    assert json.loads(output.getvalue())["operationId"] == str(operation_id)


def test_status_rejects_cross_operation_lookup(tmp_path: Path) -> None:
    cli._persist_snapshot(tmp_path, _snapshot(uuid.uuid4()))
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(uuid.uuid4())),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert "recovery failed" in error.getvalue()


def test_restart_rejects_invalid_request_id_without_mutation(tmp_path: Path) -> None:
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id="not-a-uuid", json_lines=True),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert not (tmp_path / "native-command-control-authority" / cli._STATE_NAME).exists()


def test_direct_restart_dispatch_fails_closed_without_lifecycle_authorization(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id=str(operation_id), json_lines=False),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 2
    assert "awaiting_approval" in output.getvalue()


def test_status_returns_zero_for_a_valid_human_action_snapshot(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    cli._persist_snapshot(tmp_path, _snapshot(operation_id, phase="awaiting_approval"))
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=io.StringIO(),
    )
    assert result == 0


def test_restart_exit_codes_distinguish_human_action_and_owned_work() -> None:
    operation_id = uuid.uuid4()
    approval = _snapshot(operation_id, phase="awaiting_approval")
    busy = dict(approval, phase="waiting_for_owner", requiresHumanAction=False)
    assert cli._restart_exit_code(approval) == 2
    assert cli._restart_exit_code(busy) == 3


def _proof_stdin(monkeypatch: object, payload: bytes) -> None:
    stream = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)  # type: ignore[attr-defined]


def test_recovery_stdin_uses_totp_instead_of_password(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":null,"totpCode":" 123456 "}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=True)
    assert proof is not None
    assert proof.password is None
    assert proof.totp_code == "123456"


def test_recovery_stdin_uses_password_without_totp(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"correct horse","totpCode":null}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=False)
    assert proof is not None
    assert proof.password == "correct horse"
    assert proof.totp_code is None


def test_recovery_stdin_rejects_conflicting_or_unbounded_proof(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"one","totpCode":"123456"}')
    with pytest.raises(ApprovalGateError, match="never both"):
        consume_desktop_lifecycle_stdin(totp_enabled=True)
    _proof_stdin(monkeypatch, b"x" * (4 * 1024 + 1))
    with pytest.raises(ApprovalGateError, match="exceeded"):
        consume_desktop_lifecycle_stdin(totp_enabled=False)


@pytest.mark.parametrize("payload", [b"", b"not-json", b"{}", b'{"password":null,"totpCode":null}'])
def test_recovery_stdin_rejects_missing_or_malformed_proof(
    monkeypatch: object, payload: bytes
) -> None:
    _proof_stdin(monkeypatch, payload)
    with pytest.raises(ApprovalGateError):
        consume_desktop_lifecycle_stdin(totp_enabled=False)
