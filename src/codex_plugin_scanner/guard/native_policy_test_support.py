"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import FrameType

from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .store import GuardStore

_MAX_OBSERVED_FRAMES = 32
_PUBLISHER_MODULE = "codex_plugin_scanner.guard.native_policy_snapshot_publisher"
_PHASES = {
    (_PUBLISHER_MODULE, "_run"): "publisher_loop",
    (_PUBLISHER_MODULE, "_publish_once"): "publication",
    (_PUBLISHER_MODULE, "_publication_context"): "context",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_context", "publication_context"): "context",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_current_input_fingerprint",
    ): "input_fingerprint",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_compiled_effective_policy",
    ): "configuration",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport", "_publish_snapshot_v3"): "v3_transport",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped", "publish_scoped"): "scoped_publication",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_context",
        "compiled_v3_compatible_policy",
    ): "v3_input_capture",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_resident_directory_fingerprint",
    ): "resident_directory",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_confirm_resident_fingerprint",
    ): "resident_confirmation",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_source_requirement",
        "refresh_source_requirement",
    ): "source_presence",
    (
        "codex_plugin_scanner.guard.store_secret_policy_integrity",
        "_policy_integrity_secret_material",
    ): "integrity_key",
    (
        "codex_plugin_scanner.guard.native_policy_authority_read",
        "read_native_policy_authority_inputs",
    ): "authority_capture",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_context",
        "_v3_inputs_from_capture",
    ): "v3_projection",
}


# Finite categories and source positions are bound to reviewed function entries.
# Positions are inspected only for these pinned function identities; none escape.
_CALL_PHASES = {
    "codex_plugin_scanner.guard.store_connection_schema": {
        "StoreConnectionSchemaMixin._connect": "connection_admission",
        "StoreConnectionSchemaMixin._connect_once": "connection_transaction",
        "StoreConnectionSchemaMixin._hold_storage_gate": "storage_gate",
        "StoreConnectionSchemaMixin._hold_advisory_file_lock": "advisory_gate",
        "StoreConnectionSchemaMixin.hold_oauth_credential_lock": "credential_gate",
    },
    "codex_plugin_scanner.guard.store_storage_lock": {
        "hold_storage_file_lock": "storage_file_gate",
        "_WindowsStorageLock.acquire": "storage_lock_acquire",
        "_WindowsStorageLock.release": "storage_lock_release",
    },
    "codex_plugin_scanner.guard.store_secret_policy_integrity": {
        "StoreSecretPolicyIntegrityMixin._policy_integrity_cache_marker": "integrity_marker",
        "StoreSecretPolicyIntegrityMixin._load_policy_integrity_state_cache_marker": "integrity_marker_sql",
        "StoreSecretPolicyIntegrityMixin._get_policy_integrity_secret_from_store": "integrity_backend_read",
        "StoreSecretPolicyIntegrityMixin._load_policy_integrity_control_state": "integrity_control",
        "StoreSecretPolicyIntegrityMixin._repair_store_permissions": "store_permissions",
    },
    "codex_plugin_scanner.guard.store_base": {
        "_acquire_advisory_file_lock": "advisory_lock_acquire",
        "_release_advisory_file_lock": "advisory_lock_release",
        "EncryptedFileSecretStore._ensure_ready": "vault_initialization",
        "EncryptedFileSecretStore.get_secret": "vault_read",
        "EncryptedFileSecretStore.set_secret": "vault_write",
        "EncryptedFileSecretStore._load_fernet_key": "vault_key_read",
        "EncryptedFileSecretStore._atomic_write_bytes": "vault_atomic_write",
        "EncryptedFileSecretStore._decrypt_fernet": "vault_decrypt",
        "SystemKeyringSecretStore._backend_is_available": "keyring_selection",
        "SystemKeyringSecretStore._load_keyring_module_or_none": "keyring_module",
        "SystemKeyringSecretStore.get_secret": "keyring_read",
        "SystemKeyringSecretStore.get_secret_with_timeout": "keyring_bounded_read",
        "SystemKeyringSecretStore._get_macos_secret_in_isolated_process": "keyring_process_read",
    },
    "codex_plugin_scanner.guard.store_policy_integrity_backend": {
        "build_policy_integrity_secret_store": "integrity_backend_selection",
    },
    "codex_plugin_scanner.guard.native_policy_authority_read": {
        "_capture_native_policy_authority_inputs": "authority_snapshot",
    },
    "codex_plugin_scanner.guard.native_policy_authority_managed": {
        "read_frozen_native_managed_authority": "managed_authority_read",
        "FrozenNativeManagedAuthority.require_current_secrets": "managed_secret_fence",
    },
    "codex_plugin_scanner.guard.store_review_event_outbox_schema": {
        "finalize_review_event_payload_hashes": "transaction_hashes",
        "commit_review_event_transaction": "transaction_commit",
        "notify_review_event_wake": "transaction_notification",
    },
}
_CALL_SITES = {
    (
        "codex_plugin_scanner.guard.store_connection_schema",
        "StoreConnectionSchemaMixin._connect_once",
        364,
    ): (
        (370, 370, "sqlite_open"),
        (382, 390, "sqlite_setup"),
        (410, 410, "sqlite_close"),
    ),
    (
        "codex_plugin_scanner.guard.store_connection_schema",
        "StoreConnectionSchemaMixin._hold_advisory_file_lock",
        475,
    ): ((493, 493, "advisory_gate_wait"),),
    (
        "codex_plugin_scanner.guard.store_base",
        "EncryptedFileSecretStore._ensure_ready",
        900,
    ): (
        (908, 910, "vault_thread_gate"),
        (924, 924, "vault_file_gate_wait"),
    ),
    (
        "codex_plugin_scanner.guard.native_policy_authority_read",
        "_capture_native_policy_authority_inputs",
        130,
    ): (
        (152, 152, "authority_transaction_begin"),
        (154, 157, "authority_state_sql"),
        (166, 169, "authority_controls_sql"),
        (177, 179, "authority_device_sql"),
        (187, 190, "authority_source_sql"),
        (201, 205, "authority_rows_sql"),
    ),
    (
        "codex_plugin_scanner.guard.store_review_event_outbox_schema",
        "commit_review_event_transaction",
        80,
    ): ((88, 88, "sqlite_commit"),),
}


def _nested_worker_phase(frame: FrameType, module: str) -> str | None:
    code = frame.f_code
    qualname = getattr(code, "co_qualname", "")
    phase = _CALL_PHASES.get(module, {}).get(qualname)
    if phase is None:
        return None
    sites = _CALL_SITES.get((module, qualname, code.co_firstlineno), ())
    if sites:
        line = frame.f_lineno
        for start, end, category in sites:
            if start <= line <= end:
                return category
    return phase


def _observed_worker_phase(frame: FrameType | None) -> tuple[str, bool]:
    """Classify one worker's stack without returning stack or frame data."""

    for _ in range(_MAX_OBSERVED_FRAMES):
        if frame is None:
            return "unknown", False
        module = frame.f_globals.get("__name__")
        phase = _nested_worker_phase(frame, module) or _PHASES.get((module, frame.f_code.co_name))
        if phase is not None:
            return phase, False
        frame = frame.f_back
    return "unknown", frame is not None


def _publication_failure_observation(publisher: object) -> dict[str, bool | str]:
    """Take one lock-free, non-atomic observation after a test wait fails."""

    result: dict[str, bool | str] = {
        "phase": "unknown",
        "started": False,
        "closed": False,
        "acked": False,
        "snapshot_present": False,
        "error_present": False,
        "worker_present": False,
        "worker_alive": False,
        "worker_frame_present": False,
        "frame_limit_reached": False,
        "observation_failed": False,
    }
    try:
        state = vars(publisher)
        result["started"] = state.get("_started") is True
        result["closed"] = state.get("_closed") is True
        result["acked"] = state.get("_acked") is True
        result["snapshot_present"] = state.get("_snapshot") is not None
        result["error_present"] = state.get("_last_error") is not None
        worker = state.get("_thread")
        result["worker_present"] = isinstance(worker, threading.Thread)
        if isinstance(worker, threading.Thread):
            result["worker_alive"] = worker.is_alive()
        if isinstance(worker, threading.Thread) and result["worker_alive"] and worker.ident is not None:
            # Only this publisher worker is inspected. Do not retain frame data,
            # locals, paths, thread identifiers or policy/error contents.
            frame = sys._current_frames().get(worker.ident)
            try:
                result["worker_frame_present"] = frame is not None
                result["phase"], result["frame_limit_reached"] = _observed_worker_phase(frame)
            finally:
                del frame
    except Exception:
        result["observation_failed"] = True
    return result


def _emit_publication_failure_observation(publisher: object) -> None:
    try:
        observation = _publication_failure_observation(publisher)
        print(
            "native_policy_readiness_observation=" + json.dumps(observation, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
    except Exception:
        # Diagnostic collection/output must not replace the original failure.
        pass


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    publisher.start()
    try:
        ready_wait_seconds = 25.0 if sys.platform == "win32" else 3.0
        if not publisher.wait_until_ready(time.monotonic() + ready_wait_seconds):
            _emit_publication_failure_observation(publisher)
            raise AssertionError(f"native policy publisher was not ready: {publisher.last_error}")
        snapshot = publisher.current_snapshot()
        if snapshot is None:
            raise AssertionError("native policy publisher returned no ACKed snapshot")
        yield snapshot
    finally:
        publisher.close()
