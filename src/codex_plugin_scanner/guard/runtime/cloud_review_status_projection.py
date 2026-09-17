"""Read-only Cloud Review status shared by CLI and local settings."""

from __future__ import annotations

from datetime import datetime, timezone

from .exact_cloud_review import exact_cloud_review_status
from .cloud_review_readiness import cloud_review_workers_ready

_RECOVERY_KEY = "guard_cloud_review_settings_recovery"
_ENABLE_COMMAND = "hol-guard cloud-review enable"


def project_cloud_review_status(
    store: object,
    *,
    now: str | None = None,
    worker: dict[str, object] | None = None,
) -> dict[str, object]:
    status = exact_cloud_review_status(store, now=now)
    binding = store.get_review_event_oauth_binding()
    profile = store.get_cloud_sync_profile()
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"} if binding else None
    outbox = store.review_event_outbox_status(
        now=now or datetime.now(timezone.utc).isoformat(),
        **(delivery_binding or {}),
    )
    sync_key = "guard_cloud_review_sync_state"
    if store.guard_source != "default":
        sync_key += f":{store.guard_source}"
    sync = store.get_sync_payload(sync_key)
    sync = sync if isinstance(sync, dict) else {}
    recovery = store.get_sync_payload(_RECOVERY_KEY)
    recovery = recovery if isinstance(recovery, dict) and recovery.get("binding") == binding else {}
    reason = status.get("reason")
    consent_expired = reason == "cloud_review_capability_expired"
    consent_enabled = status.get("enabled") is True
    connected = profile is not None and binding is not None
    delivery_ready = cloud_review_workers_ready(worker) if worker is not None else consent_enabled and connected
    recovery_action = _ENABLE_COMMAND if consent_expired or not consent_enabled else None
    if consent_expired:
        recovery_action = _ENABLE_COMMAND
    return {
        **status,
        "connected": connected,
        "consent_enabled": consent_enabled,
        "capability_saved": consent_enabled or consent_expired or bool(store.get_sync_payload("guard_exact_cloud_review_capability")),
        "delivery_ready": delivery_ready and consent_enabled,
        "enabled": consent_enabled,
        "expires_at": status.get("expires_at"),
        "workspace_id": binding["workspace_id"] if binding else status.get("workspace_id"),
        "source": binding["oauth_source"] if binding else None,
        "pending_uploads": outbox.get("depth", 0) if binding else 0,
        "held_events": store.count_recoverable_unbound_review_events(),
        "isolated_events": outbox.get("quarantined_depth", 0),
        "activation_error": recovery.get("error"),
        "last_synced_at": (
            sync.get("last_delivery_at")
            if delivery_binding is not None and sync.get("last_delivery_binding") == delivery_binding
            else None
        ),
        "delivery_state": sync.get("state", "idle"),
        "consent_expired": consent_expired,
        "disconnected": not connected,
        "recovery_action": recovery_action,
        "policy_applied": False,
    }


__all__ = ["project_cloud_review_status"]
