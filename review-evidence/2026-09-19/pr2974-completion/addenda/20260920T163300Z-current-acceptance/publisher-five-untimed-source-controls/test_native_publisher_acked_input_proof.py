"""Untimed source controls for post-ACK input reconciliation; no native process."""

from pathlib import Path
import time
from types import SimpleNamespace

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _RUST_SNAPSHOT_STATE_NAME
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _write_v3_snapshot_file
from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_workspace_lifecycle_faults import LostMetadataHints
from scripts.native_slo_workspace_lifecycle import await_ack

from .native_policy_snapshot_test_fixtures import _ack, _status


def _publisher(tmp_path: Path, *, publish: bool = True) -> tuple[NativePolicySnapshotPublisher, Path, list[bytes]]:
    home = tmp_path / "home"
    store = GuardStore(home)
    atomic_write_settings(
        home / "config.toml",
        'mode = "enforce"\nprotection_posture = "protected"\n'
        'default_action = "allow"\nsubprocess_action = "allow"\n',
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    calls: list[bytes] = []

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client)
    publisher._provision_verifier_key()
    publisher.register_workspace(workspace)
    if publish:
        publisher._input_fingerprint = publisher._current_input_fingerprint()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
    return publisher, workspace, calls


def test_real_overlay_is_in_full_acknowledged_effective_policy(tmp_path: Path) -> None:
    publisher, workspace, calls = _publisher(tmp_path)
    try:
        before = publisher.current_snapshot()
        assert before is not None
        atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
        assert publisher._configuration_input_changed()
        publisher.request_publish()
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None and snapshot["generation"] > before["generation"]
        assert snapshot["mode"] == "enforce"
        assert snapshot["effective_policy"]["default_action"] == "allow"
        assert snapshot["effective_policy"]["subprocess_action"] == "allow"
        assert snapshot["effective_policy"]["sandbox_analysis"] == "strict"
        assert len(calls) == 2
    finally:
        publisher.close()


def test_real_run_initial_ack_remains_ready_at_following_reconciliation(tmp_path: Path, monkeypatch) -> None:
    publisher, _workspace, calls = _publisher(tmp_path, publish=False)
    observed = []
    original = publisher._policy_input_changed

    def changed(paths=None):
        ready_before = publisher.is_ready()
        prior_marker = publisher._database_policy_fingerprint
        result = original(paths)
        observed.append({
            "paths": [Path(p).name for p in sorted(paths or ())],
            "ready_before": ready_before,
            "ready_after": publisher.is_ready(),
            "changed": result,
            "database_marker_changed": prior_marker != publisher._database_policy_fingerprint,
        })
        return result

    class StopAtSecondWait:
        calls = 0
        ready = None

        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 2:
                self.ready = publisher.is_ready()
                publisher.close()
            return False

        def clear(self):
            pass

        def set(self):
            pass

    event = StopAtSecondWait()
    monkeypatch.setattr(publisher, "_policy_input_changed", changed)
    monkeypatch.setattr(publisher, "_publish_event", event)
    try:
        publisher._run()
        assert len(calls) == 1
        assert event.ready is True, observed
    finally:
        publisher.close()


def test_same_already_published_overlay_metadata_revokes_ack(tmp_path: Path) -> None:
    publisher, workspace, calls = _publisher(tmp_path)
    try:
        prior = publisher._input_fingerprint
        atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
        publisher.request_publish()
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None and snapshot["effective_policy"]["sandbox_analysis"] == "strict"
        current = publisher._current_input_fingerprint()
        assert prior is not None
        before, after = dict(prior[0]), dict(current[0])
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        assert str(workspace / ".hol-guard.toml") in changed
        assert not publisher._configuration_input_changed()
        # This is the unchanged _run branch after publication: record the observed
        # metadata, then ask whether those current inputs need another push.
        publisher._input_fingerprint = current
        assert publisher._policy_input_changed(changed)
        assert not publisher.is_ready()
        assert publisher._snapshot == snapshot
        assert len(calls) == 2
    finally:
        publisher.close()


def test_lost_metadata_fault_does_not_expose_that_overlay_hint(tmp_path: Path) -> None:
    publisher, workspace, calls = _publisher(tmp_path)
    try:
        with LostMetadataHints(publisher):
            prior = publisher._current_input_fingerprint()
            atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
            assert publisher._configuration_input_changed()
            publisher.request_publish()
            publisher._publish_once()
            snapshot = publisher.current_snapshot()
            assert snapshot is not None and snapshot["effective_policy"]["sandbox_analysis"] == "strict"
            assert publisher._current_input_fingerprint()[0] == prior[0]
            assert not publisher._configuration_input_changed()
            assert not publisher._policy_input_changed()
            assert publisher.current_snapshot() == snapshot
            assert len(calls) == 2
    finally:
        publisher.close()


def test_original_await_ack_accepts_same_signed_full_strict_snapshot(tmp_path: Path) -> None:
    publisher, workspace, calls = _publisher(tmp_path)
    try:
        atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
        publisher.request_publish()
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        # This is a Python-written signed fixture, explicitly not a native
        # persistence claim. Both original MAC readbacks and predicates run.
        _write_v3_snapshot_file(publisher.guard_home, _RUST_SNAPSHOT_STATE_NAME, snapshot)
        worker = SimpleNamespace(
            policy_snapshot_publisher=publisher,
            prepare_workspace_policy=lambda _workspace, *, deadline: publisher.current_snapshot_binding(),
        )
        session = SimpleNamespace(store=publisher.store, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
        assert await_ack(session, minimum=snapshot["generation"], action="allow", strict=True,
                         workspace=workspace, deadline=time.monotonic() + 2.0) == snapshot
        assert publisher.is_ready() and len(calls) == 2
    finally:
        publisher.close()
