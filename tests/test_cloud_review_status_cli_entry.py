"""The public CLI status route must stay passive before opening a store."""

from __future__ import annotations

import json
import sys
import time

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_cloud_review_status_storage import _snapshot


def _status(home, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    result = main(["cloud-review", "status", "--guard-home", str(home), "--json"])
    assert result == 0
    return json.loads(capsys.readouterr().out)


def test_public_status_does_not_initialize_an_absent_guard_home(tmp_path, monkeypatch, capsys):
    home = tmp_path / "absent-guard-home"
    started = time.monotonic()

    status = _status(home, monkeypatch, capsys)

    assert not home.exists()
    assert status["status"] == "unavailable"
    assert status["delivery_ready"] is None
    assert status["enabled"] is False
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("invalid", ["corrupt", "missing_schema", "symlink"])
def test_public_status_does_not_repair_an_unreadable_or_legacy_database(tmp_path, monkeypatch, capsys, invalid):
    home = tmp_path / "guard-home"
    home.mkdir()
    database = home / "guard.db"
    if invalid == "symlink":
        target = tmp_path / "external.db"
        target.write_bytes(b"unchanged unrelated file")
        database.symlink_to(target)
    else:
        database.write_bytes(b"corrupt-database" if invalid == "corrupt" else b"")
    before = {path.name: path.read_bytes() for path in home.iterdir()}

    status = _status(home, monkeypatch, capsys)

    assert {path.name: path.read_bytes() for path in home.iterdir()} == before
    assert status["status"] == "unavailable"
    assert status["delivery_ready"] is None


def test_existing_home_status_keeps_named_oauth_sources_separate(tmp_path):
    from codex_plugin_scanner.guard.runtime.cloud_review_status import cloud_review_status

    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    before = _snapshot(store)

    status = cloud_review_status(store.guard_home, source="another-account")

    assert status["source"] is None
    assert status["workspace_id"] is None
    assert status["connected"] is False
    assert status["enabled"] is False
    assert _snapshot(store) == before


@pytest.mark.parametrize("signer_available", [True, False])
def test_public_status_preserves_os_only_signer_selection(tmp_path, monkeypatch, capsys, signer_available):
    from codex_plugin_scanner.guard import store as store_module
    from codex_plugin_scanner.guard.store_base import SystemKeyringSecretStore

    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    encoded_key = store._policy_integrity_secret_store.get_secret(store._policy_integrity_key_ref)
    selected: list[bool] = []
    reads: list[tuple[str, float]] = []

    def backend(_home, *, allow_system_keyring):
        selected.append(allow_system_keyring)
        return SystemKeyringSecretStore("hol-guard.policy-integrity")

    def read(_self, secret_id, *, timeout_seconds):
        reads.append((secret_id, timeout_seconds))
        return encoded_key if signer_available else None

    monkeypatch.setattr(store_module, "_build_policy_integrity_secret_store", backend)
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", read)
    before = _snapshot(store)

    status = _status(store.guard_home, monkeypatch, capsys)

    assert selected == [True]
    assert reads == [(store._policy_integrity_key_ref, 0.5)]
    assert status["enabled"] is signer_available
    # An existing local signer is not substituted when the selected OS signer is absent.
    assert _snapshot(store) == before


def test_public_status_does_not_recreate_installation_identity(tmp_path, monkeypatch, capsys):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    with store._connect() as connection:
        connection.execute("delete from guard_devices")
    before = _snapshot(store)

    status = _status(store.guard_home, monkeypatch, capsys)

    assert _snapshot(store) == before
    assert status["enabled"] is False


def test_public_status_does_not_restore_missing_oauth_metadata(tmp_path, monkeypatch, capsys):
    store = connected_exact_review_store(tmp_path)
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-09-17T00:00:00Z",
    )
    store.delete_sync_payload("oauth_local_credentials")
    store._clear_oauth_secret_payload_cache()
    before = _snapshot(store)

    status = _status(store.guard_home, monkeypatch, capsys)

    assert _snapshot(store) == before
    assert status["connected"] is False


def test_public_status_reads_valid_consent_without_changing_existing_storage(tmp_path, monkeypatch, capsys):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    before = _snapshot(store)

    status = _status(store.guard_home, monkeypatch, capsys)

    assert _snapshot(store) == before
    assert status["enabled"] is True
    assert status["connected"] is True
    assert status["delivery_ready"] is None
