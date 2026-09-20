"""Best-effort AIBOM inventory context persistence during daemon startup."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..store import GuardStore

RecordDiagnostic = Callable[..., object]


def persist_aibom_inventory_context(
    *,
    store: GuardStore,
    cached_source: OAuthConnectionSnapshot | None,
    workspace_dir: Path | None,
    home_dir: Path | None,
    now: Callable[[], str],
    record_diagnostic: RecordDiagnostic,
) -> None:
    try:
        if workspace_dir is None or cached_source is None:
            return
        with store.hold_oauth_credential_lock():
            source = store._capture_oauth_connection_unlocked(allow_primary=True, allow_recoverable=True)
            if source is None or not cached_source.same_authority(source):
                return
            workspace_id = source.credentials().get("workspace_id")
            if not isinstance(workspace_id, str) or not workspace_id.strip():
                return
            payload: dict[str, object] = {
                "workspace_dir": str(workspace_dir),
                "workspace_id": workspace_id,
            }
            if home_dir is not None:
                payload["home_dir"] = str(home_dir)
            store._set_sync_payload_unlocked("aibom_inventory_context", payload, now())
    except sqlite3.DatabaseError as error:
        with suppress(Exception):
            record_diagnostic(
                "aibom_inventory_context_persist_failed",
                detail=type(error).__name__,
            )


__all__ = ["persist_aibom_inventory_context"]
