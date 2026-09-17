"""Classify policy-activation failures without claiming application."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Final

STORAGE_FAILURE: Final = "storage"
TRANSPORT_FAILURE: Final = "transport"
PRECOMMIT_FAILURE: Final = "precommit"
POSTCOMMIT_FAILURE: Final = "postcommit"

_LOCKED_MARKERS: Final = ("database is locked", "database schema is locked")
_DISK_FULL_MARKERS: Final = ("disk is full", "database or disk is full", "no space left")


def classify_policy_activation_failure(
    error: BaseException,
    *,
    boundary: str = PRECOMMIT_FAILURE,
) -> dict[str, object]:
    """Return a bounded status that never reports the candidate as applied."""

    kind = STORAGE_FAILURE
    reason = "policy_activation_storage_failed"
    if isinstance(error, (json.JSONDecodeError, TypeError, ValueError)) and not isinstance(error, sqlite3.Error):
        reason = "policy_activation_payload_unencodable"
    elif isinstance(error, sqlite3.OperationalError):
        message = str(error).lower()
        if any(marker in message for marker in _DISK_FULL_MARKERS):
            reason = "policy_activation_disk_full"
        elif any(marker in message for marker in _LOCKED_MARKERS):
            reason = "policy_activation_sqlite_locked"
        else:
            reason = "policy_activation_sqlite_failed"
    elif isinstance(error, sqlite3.Error):
        reason = "policy_activation_sqlite_failed"
    elif isinstance(error, (TimeoutError, ConnectionError)):
        kind = TRANSPORT_FAILURE
        reason = "policy_activation_transport_failed"
    elif isinstance(error, (OSError, MemoryError)):
        reason = "policy_activation_storage_failed"
    else:
        kind = TRANSPORT_FAILURE
        reason = "policy_activation_transport_failed"
    return {
        "applied": False,
        "boundary": boundary,
        "failure_kind": kind,
        "reason": reason,
        "retryable": kind == STORAGE_FAILURE and reason != "policy_activation_payload_unencodable",
    }


def activation_status_from_store(store: object) -> dict[str, object]:
    """Project last-error versus last-good without inventing application."""

    get_sync = getattr(store, "get_sync_payload", None)
    last_error = get_sync("policy_bundle_last_error") if callable(get_sync) else None
    last_good = get_sync("policy_bundle_last_good") if callable(get_sync) else None
    ack = get_sync("policy_bundle_ack") if callable(get_sync) else None
    error_payload = last_error if isinstance(last_error, Mapping) else {}
    reason = error_payload.get("reason") if isinstance(error_payload.get("reason"), str) else None
    ack_status = ack.get("status") if isinstance(ack, Mapping) else None
    return {
        "applied": False if reason else ack_status in {"synced", "applied"},
        "last_good_present": isinstance(last_good, Mapping) and bool(last_good),
        "storage_failure": reason in {
            "policy_activation_disk_full",
            "policy_activation_sqlite_locked",
            "policy_activation_sqlite_failed",
            "policy_activation_storage_failed",
            "policy_activation_payload_unencodable",
        },
        "transport_failure": reason == "policy_activation_transport_failed",
        "reason": reason,
    }


__all__ = [
    "POSTCOMMIT_FAILURE",
    "PRECOMMIT_FAILURE",
    "STORAGE_FAILURE",
    "TRANSPORT_FAILURE",
    "activation_status_from_store",
    "classify_policy_activation_failure",
]
