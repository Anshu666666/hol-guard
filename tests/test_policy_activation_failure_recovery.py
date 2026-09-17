"""HGP-153: activation failures leave recoverable durable state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_activation_failure import (
    STORAGE_FAILURE,
    classify_policy_activation_failure,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_activation_atomicity import (
    _activate_bundle,
    _signed_bundle,
    _sorted_policy_rows,
)


def test_json_encoding_failure_rejects_before_commit(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    prior = _signed_bundle(rollout_state="enforcing")
    assert _activate_bundle(store, prior, "2026-07-18T00:00:00Z") is not None
    rows_before = _sorted_policy_rows(store)
    last_good = store.get_sync_payload("policy_bundle_last_good")

    class _Unencodable:
        def __str__(self) -> str:
            raise TypeError("unencodable")

    result = store.apply_policy_bundle_authority(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:unencodable",
                reason="must not apply",
                source="policy-bundle",
            )
        ],
        "2026-07-18T01:00:00Z",
        policy_bundle={"bundleVersion": "bad", "unencodable": _Unencodable()},
        policy_bundle_keyring={"keys": []},
        cloud_exceptions=[],
        policy_bundle_ack={"status": "synced", "bundleVersion": "bad"},
        policy_bundle_checkpoint={},
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert result is None
    assert _sorted_policy_rows(store) == rows_before
    assert store.get_sync_payload("policy_bundle_last_good") == last_good


def test_sqlite_locked_and_disk_full_do_not_claim_application(tmp_path: Path) -> None:
    locked = classify_policy_activation_failure(sqlite3.OperationalError("database is locked"))
    disk = classify_policy_activation_failure(sqlite3.OperationalError("database or disk is full"))
    transport = classify_policy_activation_failure(TimeoutError("connect timed out"))
    encode = classify_policy_activation_failure(json.JSONDecodeError("bad", "x", 0))
    assert locked["applied"] is False
    assert locked["failure_kind"] == STORAGE_FAILURE
    assert locked["reason"] == "policy_activation_sqlite_locked"
    assert disk["reason"] == "policy_activation_disk_full"
    assert transport["failure_kind"] == "transport"
    assert encode["applied"] is False
    assert encode["retryable"] is False


def test_mid_transaction_failure_is_idempotent_on_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _signed_bundle(rollout_state="enforcing", bundle_version="policy-2026-07-18.1")
    assert _activate_bundle(store, first, "2026-07-18T00:00:00Z") is not None
    rows_before = _sorted_policy_rows(store)
    original_replace = store._replace_remote_policy_rows_locked  # pyright: ignore[reportPrivateUsage]

    def fail_after_rows(connection: sqlite3.Connection, rows: object, **kwargs: object) -> None:
        original_replace(connection, rows, **kwargs)
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", fail_after_rows)
    second = _signed_bundle(rollout_state="enforcing", bundle_version="policy-2026-07-18.2")
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        _activate_bundle(store, second, "2026-07-18T01:00:00Z")
    assert _sorted_policy_rows(store) == rows_before
    monkeypatch.undo()
    assert _activate_bundle(store, second, "2026-07-18T01:00:00Z") is not None
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-07-18.2"
