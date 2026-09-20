"""Real original await function, guarded source, and signed readback controls."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _RUST_SNAPSHOT_STATE_NAME
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _write_v3_snapshot_file
from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_workspace_lifecycle as lifecycle
from tests.native_policy_snapshot_test_fixtures import _ack, _status

from predicate.bindings import Registry
from predicate.capture import Capture
from predicate.hooks import OwnedHooks


def prepared(tmp_path: Path, monkeypatch: Any) -> tuple[Any, Any, Path, dict[str, Any]]:
    store = GuardStore(tmp_path / "home")
    atomic_write_settings(
        store.guard_home / "config.toml",
        'mode = "enforce"\nprotection_posture = "protected"\ndefault_action = "allow"\nsubprocess_action = "allow"\n',
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: _ack(kw["payload"])
    )
    publisher._provision_verifier_key()
    publisher.register_workspace(workspace)
    publisher._input_fingerprint = publisher._current_input_fingerprint()
    publisher._publish_once()
    snapshot = publisher.current_snapshot()
    assert snapshot is not None
    # Owned Python-written MAC fixture; this is not native persistence evidence.
    _write_v3_snapshot_file(store.guard_home, _RUST_SNAPSHOT_STATE_NAME, snapshot)
    worker = object.__new__(HookWorker)
    worker.policy_snapshot_publisher, worker.store, worker._publish_native_policy = publisher, store, True
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setenv("HOL_GUARD_NATIVE_MODE", "force")
    session = SimpleNamespace(store=store, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    return session, publisher, workspace, snapshot


def registry() -> Registry:
    source = Path(lifecycle.__file__).resolve().parents[1]
    result = Registry(source, Path(__file__).resolve().parents[1] / "source-bindings.json")
    result.add(sys._getframe(1).f_code, "control")
    return result


def invoke(session: Any, workspace: Path, snapshot: dict[str, Any], **kwargs: Any) -> Any:
    return lifecycle.await_ack(
        session,
        minimum=kwargs.get("minimum", snapshot["generation"]),
        action=kwargs.get("action", "allow"),
        strict=kwargs.get("strict", True),
        workspace=workspace,
        deadline=kwargs.get("deadline", time.monotonic() + 2),
    )


def test_actual_signed_readbacks_all_original_positive_calls(tmp_path: Path, monkeypatch: Any) -> None:
    session, publisher, workspace, snapshot = prepared(tmp_path, monkeypatch)
    capture, sites = Capture(session), registry()
    sites.add(invoke.__code__, "control")
    original_time = lifecycle.time
    try:
        with OwnedHooks(capture, sites) as hooks:
            result = invoke(session, workspace, snapshot)
        assert result == snapshot and hooks.restored and lifecycle.time is original_time
        report = capture.freeze()
        assert report["observation_complete"] is True, report
        stages = [row["stage"] for row in report["rows"]]
        assert stages.count("prepare") == 1
        assert stages.count("last_error") == stages.count("wait_ready") == 1
        assert stages.count("current_snapshot_binding") == 1
        assert stages.count("current_snapshot") == 2
        assert stages.count("authenticated_readback") == stages.count("readback_matches") == 1
        clocks = [r for r in report["rows"] if r["stage"] == "original_clock"]
        assert len(clocks) == 1 and clocks[0]["site"].endswith(":69")
    finally:
        publisher.close()


@pytest.mark.parametrize("failure", ["minimum", "action", "strict", "readback", "withdrawn", "deadline"])
def test_original_refusals_and_skipped_final_predicates(tmp_path: Path, monkeypatch: Any, failure: str) -> None:
    session, publisher, workspace, snapshot = prepared(tmp_path, monkeypatch)
    capture, sites = Capture(session), registry()
    sites.add(invoke.__code__, "control")
    kwargs: dict[str, Any] = {"deadline": time.monotonic() - 0.01}
    if failure == "minimum":
        kwargs["minimum"] = snapshot["generation"] + 1
    elif failure == "action":
        kwargs["action"] = "block"
    elif failure == "strict":
        atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "balanced"\n')
        publisher.request_publish()
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        _write_v3_snapshot_file(publisher.guard_home, _RUST_SNAPSHOT_STATE_NAME, snapshot)
    elif failure == "readback":
        # An independently valid signed later authority mismatches the older
        # acknowledged Python snapshot; no forged MAC is used.
        old = snapshot
        atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "balanced"\n')
        publisher.request_publish()
        publisher._publish_once()
        newer = publisher.current_snapshot()
        assert newer is not None and newer["generation"] > old["generation"]
        _write_v3_snapshot_file(publisher.guard_home, _RUST_SNAPSHOT_STATE_NAME, newer)
        publisher._snapshot = old
    elif failure == "withdrawn":
        publisher._acked = False
    try:
        with OwnedHooks(capture, sites), pytest.raises(RuntimeError, match="authenticated acknowledgment deadline"):
            invoke(session, workspace, snapshot, **kwargs)
        report = capture.freeze()
        assert report["observation_complete"] is True, report
        direct_final = [r for r in report["rows"] if r["stage"] == "current_snapshot" and r["site"].endswith(":68")]
        clocks = [r["site"] for r in report["rows"] if r["stage"] == "original_clock"]
        assert any(s.endswith(":72") for s in clocks)
        assert bool(direct_final) is (failure == "deadline")
        assert any(s.endswith(":69") for s in clocks) is (failure == "deadline")
    finally:
        publisher.close()


def test_getter_counts_equal_unobserved_original_and_observed(tmp_path: Path, monkeypatch: Any) -> None:
    session, publisher, workspace, snapshot = prepared(tmp_path, monkeypatch)
    counts: dict[str, int] = {}
    sites = registry()
    sites.add(invoke.__code__, "control")
    for name in ("current_snapshot", "current_snapshot_binding", "wait_until_ready", "register_workspace"):
        original = getattr(NativePolicySnapshotPublisher, name)

        def counted(self: Any, *args: Any, _original: Any = original, _name: str = name, **kwargs: Any) -> Any:
            counts[_name] = counts.get(_name, 0) + 1
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(NativePolicySnapshotPublisher, name, counted)
        sites.add(counted.__code__, "control")
    try:
        assert invoke(session, workspace, snapshot) == snapshot
        baseline = counts.copy()
        counts.clear()
        capture = Capture(session)
        with OwnedHooks(capture, sites):
            assert invoke(session, workspace, snapshot) == snapshot
        assert (
            counts
            == baseline
            == {"register_workspace": 1, "wait_until_ready": 1, "current_snapshot_binding": 1, "current_snapshot": 2}
        )
        assert capture.freeze()["observation_complete"] is True
    finally:
        publisher.close()


def test_owned_background_identity_and_nonowned_forwarding(tmp_path: Path, monkeypatch: Any) -> None:
    import threading

    session, publisher, _workspace, _snapshot = prepared(tmp_path / "a", monkeypatch)
    _other_session, other, _other_workspace, _other_snapshot = prepared(tmp_path / "b", monkeypatch)
    capture, sites = Capture(session), registry()
    errors = []

    def work() -> None:
        try:
            publisher.request_publish()
            other.request_publish()
        except BaseException as error:
            errors.append(error)

    sites.add(work.__code__, "control")
    try:
        with OwnedHooks(capture, sites):
            thread = threading.Thread(target=work)
            thread.start()
            thread.join(2)
        assert not thread.is_alive() and not errors
        assert publisher._acked is False and other._acked is False
        rows = capture.freeze()["rows"]
        assert len(rows) == 1 and rows[0]["stage"] == "request_publish" and rows[0]["await"] is None
    finally:
        publisher.close()
        other.close()


def test_actual_prepare_exception_and_restore_identity(tmp_path: Path, monkeypatch: Any) -> None:
    session, publisher, workspace, snapshot = prepared(tmp_path, monkeypatch)
    error = RuntimeError("PRIVATE_EXCEPTION")
    calls = []

    def failing(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append((self, args, kwargs))
        raise error

    monkeypatch.setattr(HookWorker, "prepare_workspace_policy", failing)
    sites = registry()
    sites.add(invoke.__code__, "control")
    capture = Capture(session)
    try:
        with OwnedHooks(capture, sites) as hooks, pytest.raises(RuntimeError) as caught:
            invoke(session, workspace, snapshot)
        assert caught.value is error and len(calls) == 1 and hooks.restored
        assert HookWorker.prepare_workspace_policy is failing
        assert capture.rows[0]["outcome"] == "exception"
        assert "PRIVATE_EXCEPTION" not in str(capture.freeze())
    finally:
        publisher.close()


def test_lost_hint_fault_still_masks_only_metadata(tmp_path: Path, monkeypatch: Any) -> None:
    from scripts.native_slo_workspace_lifecycle_faults import LostMetadataHints

    session, publisher, workspace, _snapshot = prepared(tmp_path, monkeypatch)
    capture, sites = Capture(session), registry()
    try:
        with OwnedHooks(capture, sites), LostMetadataHints(publisher) as fault:
            before = publisher._current_input_fingerprint()
            atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "balanced"\n')
            assert publisher._current_input_fingerprint()[0] == before[0]
            assert publisher._configuration_input_changed() is True
        assert fault.report()["actual_changed_hint_observed"] is True
        assert fault.report()["content_capture_replaced"] is False
    finally:
        publisher.close()


def test_authority_withdrawal_during_actual_readback_refuses_final_fence(tmp_path: Path, monkeypatch: Any) -> None:
    session, publisher, workspace, snapshot = prepared(tmp_path, monkeypatch)
    original = lifecycle._authenticated_readback
    calls = []

    def withdraw(store: Any) -> Any:
        result = original(store)
        calls.append(store)
        publisher._acked = False
        return result

    monkeypatch.setattr(lifecycle, "_authenticated_readback", withdraw)
    sites = registry()
    sites.add(invoke.__code__, "control")
    sites.add(withdraw.__code__, "control")
    capture = Capture(session)
    try:
        with OwnedHooks(capture, sites), pytest.raises(RuntimeError, match="authenticated acknowledgment deadline"):
            invoke(session, workspace, snapshot, deadline=time.monotonic() - 0.01)
        report = capture.freeze()
        assert len(calls) == 1 and report["observation_complete"] is True
        final = [r for r in report["rows"] if r["stage"] == "current_snapshot" and r["site"].endswith(":68")]
        assert len(final) == 1 and final[0]["returned"] == {"kind": "none"}
        assert not any(r["stage"] == "original_clock" and r["site"].endswith(":69") for r in report["rows"])
    finally:
        publisher.close()
