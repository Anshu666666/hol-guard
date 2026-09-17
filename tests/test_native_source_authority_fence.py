"""Existing signed authority cannot disappear into native availability fallback."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_failure_response import runtime_hook_failure_response
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from tests.native_policy_snapshot_test_fixtures import _status
from tests.native_scoped_resident_fixtures import prepare_store, publish_source, raw_payload


@pytest.mark.parametrize("source", ["canonical", "memory"])
@pytest.mark.parametrize("before_start", [False, True])
def test_default_v3_refuses_unrepresented_signed_source_before_hook_admission(
    tmp_path: Path, source: str, before_start: bool
) -> None:
    store, workspace = prepare_store(tmp_path)
    if before_start:
        publish_source(store, source)
    pushes: list[object] = []
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: pushes.append(kw)
    )
    try:
        if not before_start:
            assert not publisher.requires_policy_authority
            publish_source(store, source)
        assert publisher.requires_policy_authority
        assert not publisher.requires_scoped_authority  # Actual default V3 feature set.
        publisher._publish_once()
        assert not pushes and not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        emitted: list[dict[str, Any]] = []
        host: Any = SimpleNamespace(
            policy_snapshot_publisher=publisher,
            prepare_workspace_policy=lambda *_args, **_kw: None,
            metrics=SimpleNamespace(record_route=lambda _route: None),
        )
        assert not prepare_native_hook_policy(
            SimpleNamespace(_write_json=emitted.append),
            SimpleNamespace(hook_worker=host),
            raw_payload(),
            {},
            "codex",
            str(workspace),
            0.0,
        )
        assert emitted[0]["hookSpecificOutput"]["permissionDecision"] == "deny"
    finally:
        publisher.close()


@pytest.mark.parametrize("failure", ["binding-missing", "binding-error", "transport-missing", "transport-error"])
def test_required_source_failures_never_record_or_allow(tmp_path: Path, failure: str) -> None:
    store, _ = prepare_store(tmp_path)
    publish_source(store, "canonical")
    publisher = NativePolicySnapshotPublisher(store=store)
    receipts: list[object] = []

    def snapshot(*_args: object, **_kwargs: object) -> object:
        if failure == "binding-error":
            raise RuntimeError("synthetic readiness error")
        return None if failure == "binding-missing" else {"generation": 1, "policy_digest": "a" * 64}

    def transport(**_kwargs: object) -> None:
        if failure == "transport-error":
            raise RuntimeError("synthetic transport error")

    host: Any = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        _native_policy_snapshot=snapshot,
        _review_raw_hook_native=transport,
        _record_native_decision_receipt=receipts.append,
        metrics=SimpleNamespace(record_route=lambda _route: None),
        activity_writer=None,
    )
    try:
        response = HookWorker._review_native_edge(
            host,
            payload=raw_payload(),
            harness="codex",
            event_name="PreToolUse",
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=tmp_path,
            deadline=None,
        )
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert receipts == []
    finally:
        publisher.close()


@pytest.mark.parametrize("source", [None, "canonical", "memory"])
@pytest.mark.parametrize("watch", [False, True])
def test_queue_failure_cannot_override_existing_source_with_availability_or_watch(
    tmp_path: Path, source: str | None, watch: bool
) -> None:
    store, workspace = prepare_store(tmp_path)
    if source:
        publish_source(store, source)
    if watch:
        (store.guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    publisher = NativePolicySnapshotPublisher(store=store)
    handler = SimpleNamespace(
        server=SimpleNamespace(store=store, hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher)),
        _optional_string=lambda value: value if isinstance(value, str) else None,
        _validated_fail_safe_hook_paths=lambda _params: (workspace, tmp_path),
    )
    try:
        response = runtime_hook_failure_response(
            handler,
            raw_payload(),
            {},
            default_harness="codex",
            reason="Synthetic queue failure",
            reason_code="native_hook_queue_unavailable",
        )
        if source:
            assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert response.get("continue") is True or response["hookSpecificOutput"]["permissionDecision"] == "allow"
    finally:
        publisher.close()


@pytest.mark.parametrize("source", ["canonical", "memory"])
def test_v3_does_not_admit_orphaned_remote_materialization(tmp_path: Path, source: str) -> None:
    store, _ = prepare_store(tmp_path)
    publish_source(store, source)
    key = "policy_bundle" if source == "canonical" else "guard_review_memory_registry"
    with store._connect() as connection:
        connection.execute("delete from sync_state where state_key = ?", (key,))
    pushes = []
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: pushes.append(kw)
    )
    try:
        assert publisher.requires_policy_authority
        publisher._publish_once()
        assert not publisher.is_ready() and not pushes
    finally:
        publisher.close()


def test_supported_signed_defaults_still_publish_but_mutation_fences_returned_result(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.native_policy_snapshot_test_fixtures import _ack
    from tests.test_native_cloud_policy_activation import _activate_defaults, _signed_defaults_bundle
    from tests.test_native_hook_edge import _edge_result

    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(2, "allow")
    _activate_defaults(store, bundle, keyring)
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: _ack(kw["payload"])
    )
    try:
        publisher._publish_once()
        assert publisher.is_ready() and publisher.requires_policy_authority
        binding = publisher.current_snapshot_binding()
        receipts = []

        def transport(**_kw):
            publisher.request_publish(require_source_authority=True)
            return _edge_result()

        host = SimpleNamespace(
            policy_snapshot_publisher=publisher,
            _native_policy_snapshot=lambda *_a, **_kw: binding,
            _review_raw_hook_native=transport,
            _record_native_decision_receipt=receipts.append,
            metrics=SimpleNamespace(record_route=lambda _route: None),
            activity_writer=None,
        )
        result = HookWorker._review_native_edge(
            host,
            payload=raw_payload(),
            harness="codex",
            event_name="PreToolUse",
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=tmp_path,
            deadline=None,
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny" and not receipts
    finally:
        publisher.close()


@pytest.mark.parametrize("source", ["canonical", "memory"])
@pytest.mark.parametrize("transport_error", [False, True])
def test_source_arriving_during_ipc_invalidates_source_free_allow(tmp_path: Path, source: str, transport_error: bool):
    from tests.native_policy_snapshot_test_fixtures import _ack
    from tests.test_native_hook_edge import _edge_result

    store, workspace = prepare_store(tmp_path)
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: _ack(kw["payload"])
    )
    try:
        publisher._publish_once()
        assert publisher.is_ready() and not publisher.requires_policy_authority
        binding = publisher.current_snapshot_binding()
        receipts = []

        def transport(**_kw):
            publish_source(store, source)
            if transport_error:
                raise RuntimeError("synthetic IPC failure after source mutation")
            return _edge_result()

        host = SimpleNamespace(
            policy_snapshot_publisher=publisher,
            _native_policy_snapshot=lambda *_a, **_kw: binding,
            _review_raw_hook_native=transport,
            _record_native_decision_receipt=receipts.append,
            metrics=SimpleNamespace(record_route=lambda _route: None),
            activity_writer=None,
        )
        result = HookWorker._review_native_edge(
            host,
            payload=raw_payload(),
            harness="codex",
            event_name="PreToolUse",
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=workspace,
            deadline=None,
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny" and not receipts
    finally:
        publisher.close()


def test_retained_memory_version_requires_source_after_registry_and_rows_removed(tmp_path: Path):
    store, _ = prepare_store(tmp_path)
    publish_source(store, "memory")
    with store._connect() as connection:
        connection.execute("delete from sync_state where state_key='guard_review_memory_registry'")
        connection.execute("delete from policy_decisions where source='cloud-signed-memory'")
    pushes = []
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kw: pushes.append(kw)
    )
    try:
        assert publisher.requires_policy_authority
        publisher._publish_once()
        assert not publisher.is_ready() and not pushes
    finally:
        publisher.close()
