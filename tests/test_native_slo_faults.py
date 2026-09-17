from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from scripts.native_slo_faults import FaultFixture


def _session(tmp_path: Path) -> SimpleNamespace:
    home, workspace = tmp_path / "guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    snapshot = {
        "mode": "enforce",
        "effective_policy": {
            "default_action": "allow",
            "subprocess_action": "allow",
            "risk_actions": {"execution": "allow"},
        },
    }
    worker = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(current_snapshot=lambda: snapshot, is_ready=lambda: True),
        test_oracle=None,
        _review_raw_hook_native=lambda **_kwargs: {"result": {"decision": "allow"}},
    )
    return SimpleNamespace(
        root=tmp_path,
        guard_home=home,
        workspace=workspace,
        store=SimpleNamespace(add_approval_request=lambda **_kwargs: None),
        daemon=SimpleNamespace(
            _server=SimpleNamespace(
                hook_worker=worker, runtime_hook_scheduler=RuntimeHookScheduler(retained_bytes_limit=1024)
            )
        ),
    )


def test_unavailability_witness_is_not_asserted_until_injected_fault_runs(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_hook_edge

    original = native_hook_edge.native_resident_client_request
    session = _session(tmp_path)
    with FaultFixture(session, "unavailable") as fault:
        assert "native_request_unavailable" not in fault.result()["setup"]
        assert native_hook_edge.native_resident_client_request() is None
        assert fault.result()["setup"]["native_request_unavailable"] is True
        fault.before_case()
        assert "native_request_unavailable" not in fault.result()["setup"]
    assert native_hook_edge.native_resident_client_request is original


def test_byte_fault_exercises_real_scheduler_and_restores_limit(tmp_path: Path) -> None:
    session = _session(tmp_path)
    scheduler = session.daemon._server.runtime_hook_scheduler
    with FaultFixture(session, "queue_bytes") as fault:
        assert "byte_reservation_rejected" not in fault.result()["setup"]
        assert scheduler.reserve_bytes(payload_bytes=100, deadline=time.monotonic() + 1) == (
            None,
            "daemon_hook_queue_bytes",
        )
        assert fault.result()["setup"]["byte_reservation_rejected"] is True
    assert scheduler.stats()["retained_bytes_limit"] == 1024


def test_unknown_revocation_has_no_fake_success(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="no witnessed implementation"), FaultFixture(_session(tmp_path), "revoked"):
        pass
