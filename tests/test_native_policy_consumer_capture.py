"""Actual SQLite/source fences with explicit synthetic runtime and push ACK."""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import replace
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_consumer_capture as capture
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeCapabilities, NativeRuntimeIdentity, NativeRuntimeStatus
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_oauth_connection_authority import _store


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    store, credentials = _store(tmp_path)
    credentials.update({
        "workspace_id": "22222222-2222-4222-8222-222222222222",
        "grant_id": "44444444-4444-4444-8444-444444444444",
        "machine_id": "fixture-device",
        "runtime_id": None,
    })
    store.set_oauth_local_credentials(**credentials)
    (store.guard_home / "config.toml").write_text('mode = "enforce"\n')
    baseline = _status().capabilities
    assert baseline is not None
    features = tuple(baseline.features) + (
        "policy-snapshot-v4", "policy-scoped-authority-v1", "hook-envelope-v3",
        "pre-tool-generic-authority-v1", "policy-snapshot-control-v1",
    )
    status = NativeRuntimeStatus(
        "auto", True, True, "synthetic-component-runtime",
        NativeRuntimeIdentity(tmp_path / "synthetic-runtime", 1, 1, "a" * 64),
        NativeRuntimeCapabilities(1, "0.0.0", "b" * 64, "c" * 40, "synthetic", features),
    )
    monkeypatch.setattr(capture, "native_runtime_status", lambda: status)
    calls: list[bytes] = []

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "generation-00000000000000000001.json").write_text("{}")
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)
    publisher._provision_verifier_key()
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    assert len(calls) == 1
    assert publisher._snapshot is not None and "source_input_digest" not in publisher._snapshot
    connection = store.capture_oauth_connection()
    assert connection is not None
    return store, publisher, connection, credentials, status


def test_fresh_default_capture_does_not_create_scoped_authority(tmp_path, monkeypatch):
    store, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    try:
        with capture.capture_native_consumer(
            publisher, connection=connection, deadline_monotonic=time.monotonic() + 2,
        ) as observed:
            assert observed.snapshot_version == 3
            assert observed.source_input_digest == publisher._published_cloud_inputs.input_digest
            assert observed.resident_generation == 1
            assert observed.publisher_epoch == publisher._epoch
        assert store.get_sync_payload("policy_bundle") is None
        assert store.get_sync_payload("policy_bundle_ack") is None
        assert publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize("change", [
    "epoch", "closed", "config", "sql", "credentials", "resident", "mode", "database",
])
def test_change_during_observation_discards_captured_precondition(tmp_path, monkeypatch, change):
    store, publisher, connection, credentials, status = _fixture(tmp_path, monkeypatch)
    entered = False
    try:
        with pytest.raises((NativePolicySnapshotError, RuntimeError)):
            with capture.capture_native_consumer(
                publisher, connection=connection, deadline_monotonic=time.monotonic() + 2,
            ):
                entered = True
                if change == "epoch":
                    publisher.request_publish()
                elif change == "closed":
                    publisher.close()
                elif change == "config":
                    (store.guard_home / "config.toml").write_text('mode = "enforce"\ndefault_action = "block"\n')
                elif change == "sql":
                    store.set_sync_payload("readiness-test-bookkeeping", {"value": 1}, "2026-09-20T00:00:00Z")
                    store.delete_sync_payloads(["readiness-test-bookkeeping"])
                elif change == "credentials":
                    # Simulate an out-of-band writer while the supported
                    # credential mutation API is excluded by the retained lock.
                    store._set_oauth_local_credentials_unlocked(**credentials)
                    replacement = store._capture_oauth_connection_unlocked()
                    assert replacement is not None and replacement.epoch != connection.epoch
                    assert replacement.credentials() == connection.credentials()
                elif change == "resident":
                    directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
                    (directory / "generation-00000000000000000002.json").write_text("{}")
                elif change == "database":
                    replacement = tmp_path / "replacement.db"
                    with store._connect() as original, sqlite3.connect(replacement) as destination:
                        original.backup(destination)
                    replacement.replace(store.path)
                else:
                    monkeypatch.setattr(capture, "native_runtime_status", lambda: replace(status, mode="shadow"))
        assert entered, "The real capture must be entered before mutating authority"
    finally:
        publisher.close()


def test_unchanged_files_cannot_hide_expiry_or_incompatible_runtime(tmp_path, monkeypatch):
    _, publisher, connection, _, status = _fixture(tmp_path, monkeypatch)
    entered = False
    try:
        with pytest.raises(NativePolicySnapshotError):
            with capture.capture_native_consumer(
                publisher, connection=connection, deadline_monotonic=time.monotonic() + 2,
            ) as observed:
                entered = True
                publisher._wall_clock = lambda: observed.expires_at_ms / 1000 + 1
        assert entered
        monkeypatch.setattr(capture, "native_runtime_status", lambda: replace(status, compatible=False))
        with pytest.raises(NativePolicySnapshotError):
            with capture.capture_native_consumer(
                publisher, connection=connection, deadline_monotonic=time.monotonic() + 2,
            ):
                pytest.fail("Incompatible runtime cannot enter a capture")
    finally:
        publisher.close()

def test_contended_condition_does_not_retain_authority_locks_after_deadline(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.native_policy_control_transport import run_native_control_worker

    store, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    held, release, entered, left = (threading.Event() for _ in range(4))
    original_lock = capture.hold_policy_publication_mutation

    @contextmanager
    def measured_lock(*args, **kwargs):
        with original_lock(*args, **kwargs):
            entered.set()
            try:
                yield
            finally:
                left.set()

    def holder():
        with publisher._condition:
            held.set()
            assert release.wait(5)

    thread = threading.Thread(target=holder)
    thread.start()
    assert held.wait(2)
    monkeypatch.setattr(capture, "hold_policy_publication_mutation", measured_lock)
    deadline = time.monotonic() + 0.15
    results = []

    def operation(cancelled):
        with capture.capture_native_consumer(
            publisher, connection=connection, deadline_monotonic=deadline,
        ):
            results.append("must-not-yield")
        return True

    try:
        assert run_native_control_worker(operation, deadline_monotonic=deadline) is None
        assert entered.is_set()
        assert left.wait(1), "The timed-out condition wait must unwind its real publication lease"
        # The holder still excludes the condition. Both real outer locks must
        # nevertheless be available before it releases, without a late body.
        with original_lock(store.guard_home, timeout_seconds=0.15):
            with store.hold_oauth_credential_lock(timeout_seconds=0.15):
                store._require_oauth_connection_unlocked(connection)
        assert not results and not release.is_set()
    finally:
        release.set()
        thread.join(timeout=2)
        publisher.close()
    assert not thread.is_alive() and not results
