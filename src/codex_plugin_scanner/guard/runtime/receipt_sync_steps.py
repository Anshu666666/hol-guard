"""Receipt selection steps behind the existing runtime facade."""

from __future__ import annotations

from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..receipt_sync_authority import ReceiptSyncCapture
from ..store import GuardStore


def _resolve_optional_upload_auth_context(
    store: GuardStore,
    provided_context: dict[str, object] | None,
) -> tuple[dict[str, object], OAuthConnectionSnapshot | None]:
    from . import runner as api

    observed: list[OAuthConnectionSnapshot] = []
    try:
        resolved = api._resolve_guard_sync_auth_context(store, connection_observer=observed.append)
    except api.GuardSyncNotConfiguredError:
        if provided_context is None:
            raise
        return provided_context, None
    return resolved, observed[-1] if observed else None


def _prepare_optional_receipt_selection(
    store: GuardStore,
    connection: OAuthConnectionSnapshot | None,
    *,
    synced_at: str,
) -> tuple[ReceiptSyncCapture | None, bool, str]:
    from . import runner as api

    if connection is None:
        return None, False, "full"
    try:
        with store.hold_oauth_credential_lock():
            captured = api._capture_receipt_sync_state_with_credential_lock(store, required_connection=connection)
            allowed, level = api.optional_upload_settings(store, captured.preference_state)
            if not allowed:
                return captured, False, level
            api._ensure_relaxed_receipt_redaction_resync(store, level=level, synced_at=synced_at)
            api._persist_cloud_receipt_redaction_level(store, level=level, synced_at=synced_at)
            api._ensure_cloud_review_privacy_projection(store, level=level, synced_at=synced_at)
            if level == "full":
                store.delete_sync_payload(api._RELAXED_RECEIPT_REDACTION_RESYNC_MARKER)
                store.delete_sync_payload(api._RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)
            captured = api._capture_receipt_sync_state_with_credential_lock(store, required_connection=connection)
            current_allowed, current_level = api.optional_upload_settings(store, captured.preference_state)
            return captured, current_allowed and current_level == level, level
    except (OSError, RuntimeError, ValueError, TypeError, api.sqlite3.Error):
        return None, False, "full"


def _receipt_sync_rows_with_command_detail_backfill_from_marker(
    store: GuardStore,
    *,
    receipts: list[dict[str, object]],
    redaction_level: str,
    synced_at: str,
    marker: object,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    from . import runner as api

    if api._receipt_redaction_level_rank(redaction_level) <= api._receipt_redaction_level_rank("full"):
        return receipts, None
    before_rowid = api._receipt_command_detail_backfill_before_rowid(marker, redaction_level=redaction_level)
    if isinstance(marker, dict) and marker.get("level") == redaction_level and marker.get("complete") is True:
        return receipts, None
    backfill_rows = store.list_receipts_for_command_detail_backfill(
        limit=api._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        days=api._RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        before_rowid=before_rowid,
    )
    seen_receipt_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    merged = list(receipts)
    added = 0
    for row in backfill_rows:
        receipt_id = row.get("receipt_id")
        if not isinstance(receipt_id, str) or receipt_id in seen_receipt_ids:
            continue
        merged.append({**row, api._RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG: True})
        seen_receipt_ids.add(receipt_id)
        added += 1
    backfill_rowids: list[int] = []
    for row in backfill_rows:
        receipt_rowid = row.get("receipt_rowid")
        if isinstance(receipt_rowid, int):
            backfill_rowids.append(receipt_rowid)
    next_before_rowid = min(backfill_rowids) if backfill_rowids else before_rowid
    complete = len(backfill_rows) < api._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT
    return merged, {
        "level": redaction_level,
        "updated_at": synced_at,
        "days": api._RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        "limit": api._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        "receipts": added,
        "queried": len(backfill_rows),
        "before_rowid": next_before_rowid,
        "complete": complete,
    }


def _receipt_progress_timestamp(payload: dict[str, object]) -> str:
    from . import runner as api

    parsed = api._parse_iso_timestamp(api._sync_timestamp(payload))
    if parsed is not None:
        try:
            return parsed.astimezone(api.timezone.utc).isoformat()
        except (OverflowError, ValueError):
            pass
    return api.datetime.now(api.timezone.utc).isoformat()
