"""Real bounded storage and owned-process faults at policy activation boundaries.

These controls use disposable databases and encrypted file vaults. They do not
exercise an OS keyring, fill a filesystem, or establish installed enforcement.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_policy
from codex_plugin_scanner.guard.policy_activation_failure import activation_status_from_store
from codex_plugin_scanner.guard.policy_bundle_activation import activate_with_reason, persist_activation_rejection
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.test_policy_bundle_activation_atomicity import _signed_bundle

_FIRST = "2026-07-18T00:00:00Z"
_SECOND = "2026-07-18T01:00:00Z"
_ROOT = Path(__file__).resolve().parents[1]


def _apply(
    store: GuardStore,
    bundle: dict[str, Any],
    keyring: dict[str, Any],
    now: str,
    *,
    cloud_exceptions: Sequence[dict[str, object]] = (),
    **kwargs: Any,
) -> dict[str, object] | None:
    device = store.get_device_metadata()
    return store.apply_policy_bundle_authority(
        build_policy_bundle_decisions(bundle, device_id=device["installation_id"], device_name=device["device_label"]),
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=keyring,
        cloud_exceptions=cloud_exceptions,
        policy_bundle_ack={
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "status": "synced",
        },
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
        **kwargs,
    )


def _sql_state(store: GuardStore, *, restarted: bool = False, repeated: bool = False) -> tuple[str, ...]:
    with sqlite3.connect(store.path) as connection:
        lines = tuple(connection.iterdump())
    # Constructor health is refreshed on reopen. Policy-row write triggers
    # deliberately advance the approval-cache revision even for an equal retry.
    # Every other SQL byte, including all policy and managed authority, remains.
    excluded = []
    if restarted:
        excluded.append("INSERT INTO \"sync_state\" VALUES('policy_integrity',")
    if repeated:
        excluded.extend(
            [
                'INSERT INTO "guard_approval_authority_revision" VALUES(',
                'INSERT INTO "policy_decisions" VALUES(',
                "INSERT INTO \"sqlite_sequence\" VALUES('policy_decisions',",
            ]
        )
    kept = [line for line in lines if not any(line.startswith(prefix) for prefix in excluded)]
    if repeated:
        # Decision IDs are local autoincrement row identities, not policy IDs.
        decisions = [
            {key: value for key, value in row.items() if key != "decision_id"} for row in store.list_policy_decisions()
        ]
        kept.extend(json.dumps(row, sort_keys=True) for row in decisions)
    return tuple(sorted(kept))


def _initial(tmp_path: Path) -> tuple[GuardStore, dict[str, Any], dict[str, Any]]:
    store = GuardStore(tmp_path / "guard")
    keyring = policy_bundle_test_keyring(workspace_id="workspace-1")
    first = _signed_bundle(rollout_state="enforcing", bundle_version="fault-1")
    second = _signed_bundle(rollout_state="enforcing", bundle_version="fault-2")
    assert _apply(store, first, keyring, _FIRST) is not None
    return store, second, keyring


def _assert_retry(store: GuardStore, bundle: dict[str, Any], keyring: dict[str, Any]) -> None:
    assert _apply(store, bundle, keyring, _SECOND) is not None
    complete = _sql_state(store, repeated=True)
    assert store.get_sync_payload("policy_bundle_last_good") == bundle
    assert _apply(store, bundle, keyring, _SECOND) is not None
    assert _sql_state(store, repeated=True) == complete
    assert activation_status_from_store(store)["applied"] is False


def test_real_write_lock_preserves_authority_and_classifies_storage(tmp_path: Path) -> None:
    store, candidate, keyring = _initial(tmp_path)
    before = _sql_state(store)
    with sqlite3.connect(store.path) as owner:
        owner.execute("begin immediate")
        with sqlite_connect_timeout_override(0.1):
            result, reason = activate_with_reason(_apply, store, candidate, keyring, _SECOND)
        assert result is None
        assert reason == "policy_activation_sqlite_locked"
        assert _sql_state(store) == before
        owner.rollback()
    persist_activation_rejection(store, {"reason": reason}, _SECOND)
    status = activation_status_from_store(store)
    assert status["storage_failure"] is True and status["transport_failure"] is False
    assert status["applied"] is False and status["last_good_present"] is True
    _assert_retry(store, candidate, keyring)


def test_real_sqlite_page_quota_failure_rolls_back_and_retries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, candidate, keyring = _initial(tmp_path)
    before = _sql_state(store)
    replace = store._replace_remote_policy_rows_locked
    observed: list[tuple[int, int]] = []

    def limit_after_rows(connection: sqlite3.Connection, rows: Sequence[tuple[object, ...]], **kwargs: Any) -> None:
        replace(connection, rows, **kwargs)
        pages = int(connection.execute("pragma page_count").fetchone()[0])
        limit = int(connection.execute(f"pragma max_page_count={pages}").fetchone()[0])
        observed.append((pages, limit))

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", limit_after_rows)
    with pytest.raises(sqlite3.OperationalError) as caught:
        _apply(store, candidate, keyring, _SECOND, cloud_exceptions=[{"bounded_padding": "x" * (2 * 1024 * 1024)}])
    if sys.version_info >= (3, 11):
        assert caught.value.sqlite_errorcode == getattr(sqlite3, "SQLITE_FULL", 13)
    else:
        # Python 3.10 does not expose SQLite's numeric exception attribute.
        assert str(caught.value) == "database or disk is full"
    assert len(observed) == 1 and observed[0][0] == observed[0][1]
    assert _sql_state(store) == before
    monkeypatch.undo()
    _assert_retry(store, candidate, keyring)


@pytest.mark.skipif(not Path("/dev/full").exists(), reason="requires the kernel ENOSPC test device")
def test_real_enospc_from_bounded_fault_port_rolls_back_and_classifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, candidate, keyring = _initial(tmp_path)
    before = _sql_state(store)
    replace = store._replace_remote_policy_rows_locked
    observed: list[int | None] = []

    def fail_after_rows(connection: sqlite3.Connection, rows: Sequence[tuple[object, ...]], **kwargs: Any) -> None:
        replace(connection, rows, **kwargs)
        # One byte to the kernel's deterministic failure device: no disk filling.
        try:
            with Path("/dev/full").open("wb", buffering=0) as handle:
                handle.write(b"x")
        except OSError as error:
            observed.append(error.errno)
            raise

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", fail_after_rows)
    result, reason = activate_with_reason(_apply, store, candidate, keyring, _SECOND)
    assert observed == [errno.ENOSPC]
    assert result is None and reason == "policy_activation_disk_full"
    assert _sql_state(store) == before
    monkeypatch.undo()
    persist_activation_rejection(store, {"reason": reason}, _SECOND)
    status = activation_status_from_store(store)
    assert status["storage_failure"] is True and status["transport_failure"] is False
    assert status["applied"] is False
    _assert_retry(store, candidate, keyring)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_real_protected_vault_failure_preserves_managed_last_good(tmp_path: Path, damage: str) -> None:
    store = GuardStore(tmp_path / "guard")
    vault = EncryptedFileSecretStore(store.guard_home)
    store._extension_control_authority_secret_store = vault
    bundle = managed_bundle()
    assert activate_managed_bundle(store, bundle)
    before = _sql_state(store)
    secret = vault._path_for(store._key_ref())
    prior = secret.read_bytes()
    if damage == "missing":
        secret.unlink()
    else:
        secret.write_bytes(b'{"version":"fernet-v1","ciphertext":"corrupt"}')
    try:
        assert activate_managed_bundle(store, bundle) is False
        assert _sql_state(store) == before
        assert (
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
            is not AuthorityHealth.PROTECTED
        )
        assert activation_status_from_store(store)["applied"] is False
    finally:
        secret.write_bytes(prior)
    assert activate_managed_bundle(store, bundle)
    assert _sql_state(store) == before
    assert (
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
        is AuthorityHealth.PROTECTED
    )


def _activation_child(home: str, fixture: str, marker: str, stage: str) -> None:
    store = GuardStore(Path(home))
    data = json.loads(Path(fixture).read_text())
    patch = pytest.MonkeyPatch()

    def hold() -> None:
        Path(marker).write_text(stage)
        if not threading.Event().wait(30):
            raise TimeoutError("owned activation barrier expired")

    if stage == "precommit":
        replace = store._replace_remote_policy_rows_locked

        def before_commit(connection: sqlite3.Connection, rows: Sequence[tuple[object, ...]], **kwargs: Any) -> None:
            replace(connection, rows, **kwargs)
            hold()

        patch.setattr(store, "_replace_remote_policy_rows_locked", before_commit)
    elif stage == "postcommit":
        notify = store_policy.notify_native_policy_mutation

        def after_commit(*args: Any, **kwargs: Any) -> None:
            notify(*args, **kwargs)
            hold()

        patch.setattr(store_policy, "notify_native_policy_mutation", after_commit)
    else:
        raise ValueError("unsupported barrier")
    assert _apply(store, data["bundle"], data["keyring"], _SECOND) is not None
    raise AssertionError("the held child unexpectedly returned")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX owned process-group termination")
@pytest.mark.parametrize("stage", ["precommit", "postcommit"])
def test_real_process_termination_recovers_one_complete_commit(tmp_path: Path, stage: str) -> None:
    store, candidate, keyring = _initial(tmp_path)
    before = _sql_state(store, restarted=True)
    fixture = tmp_path / "public-fixture.json"
    fixture.write_text(json.dumps({"bundle": candidate, "keyring": keyring}))
    marker = tmp_path / "barrier.txt"
    script = (
        "import sys;sys.path[:0]=[sys.argv[1]+'/src',sys.argv[1]];"
        "from tests.test_policy_activation_real_faults import _activation_child;"
        "_activation_child(*sys.argv[2:])"
    )
    committed_state: tuple[str, ...] | None = None
    with (tmp_path / "child-error.log").open("wb") as error_log:
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", script, str(_ROOT), str(store.guard_home), str(fixture), str(marker), stage],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=error_log,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 15
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert marker.exists(), "owned activation child did not reach its barrier"
            assert marker.read_text() == stage and child.poll() is None
            if stage == "precommit":
                assert _sql_state(store, restarted=True) == before
            else:
                assert store.get_sync_payload("policy_bundle") == candidate
                assert store.get_sync_payload("policy_bundle_last_good") == candidate
                assert store.get_sync_payload("policy_bundle_keyring") == keyring
                assert store.get_sync_payload(
                    "policy_bundle_acceptance_checkpoint"
                ) == policy_bundle_acceptance_checkpoint(candidate)
                assert store.get_sync_payload("policy_bundle_last_error") == {}
                assert store.get_sync_payload("cloud_exceptions") == []
                rows = store.list_policy_decisions()
                assert len(rows) == 1 and rows[0]["action"] == "allow"
                assert rows[0]["updated_at"] == "2026-07-18T01:00:00.000000+00:00"
                committed_state = _sql_state(store, restarted=True)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        assert child.returncode == -signal.SIGKILL
        with pytest.raises(ProcessLookupError):
            os.killpg(child.pid, 0)
    recovered = GuardStore(store.guard_home)
    if stage == "precommit":
        assert _sql_state(recovered, restarted=True) == before
    else:
        assert committed_state is not None and _sql_state(recovered, restarted=True) == committed_state
        assert recovered.get_sync_payload("policy_bundle") == candidate
        assert recovered.get_sync_payload("policy_bundle_last_good") == candidate
        ack = recovered.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["bundleHash"] == candidate["bundleHash"]
    assert activation_status_from_store(recovered)["applied"] is False
    _assert_retry(recovered, candidate, keyring)
