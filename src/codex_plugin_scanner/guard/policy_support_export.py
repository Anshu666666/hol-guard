"""Privacy-safe local export for policy delivery incidents."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .daemon.cloud_review_settings import cloud_review_settings_status
from .policy_runtime_error_catalog import explain_policy_runtime_error, policy_runtime_error_catalog
from .runtime.exact_cloud_review import exact_cloud_review_status
from .store import GuardStore

_SECRET_MARKERS = (
    "refresh-token",
    "refresh_token",
    "dpop_private_key",
    "private_key",
    "access_token",
    "BEGIN PRIVATE KEY",
    "canary-secret",
    "tokensecret",
)


def build_policy_support_export(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    observed_at = now or datetime.now(timezone.utc).isoformat()
    review = exact_cloud_review_status(store, now=observed_at)
    settings = cloud_review_settings_status(store)
    bundle = store.get_sync_payload("policy_bundle_last_good")
    last_error = store.get_sync_payload("policy_bundle_last_error")
    sync_summary = store.get_sync_payload("sync_summary")
    binding = store.get_review_event_oauth_binding() or {}
    error_code = None
    if isinstance(last_error, dict):
        reason = last_error.get("reason")
        if isinstance(reason, str):
            error_code = reason
    if error_code is None and isinstance(review.get("reason"), str):
        error_code = str(review["reason"])
    explained = explain_policy_runtime_error(error_code or "policy_support_export")
    export = {
        "kind": "hol-guard-policy-support-export.v1",
        "observed_at": observed_at,
        "failure_classes": {
            "auth": explained["code"] in {"cloud_review_capability_revoked", "cloud_review_capability_missing"}
            or str(review.get("reason") or "").startswith("cloud_review_"),
            "invalid_policy": isinstance(last_error, dict),
            "wrong_target": explained["code"] == "remote_exact_wrong_target",
            "runtime_publication": isinstance(sync_summary, dict)
            and sync_summary.get("telemetry_degradation") is not None,
            "continuation": settings.get("delivery_state") not in {None, "idle"},
        },
        "policy": _bundle_identity(bundle, last_error),
        "cloud_review": {
            "enabled": review.get("enabled"),
            "reason": review.get("reason"),
            "workspace_id": review.get("workspace_id") or settings.get("workspace_id"),
            "personal_consent_required_for_managed_admin_review": settings.get(
                "personal_consent_required_for_managed_admin_review"
            ),
            "pending_uploads": settings.get("pending_uploads"),
            "held_events": settings.get("held_events"),
            "isolated_events": settings.get("isolated_events"),
            "activation_error": settings.get("activation_error"),
            "delivery_state": settings.get("delivery_state"),
            "diagnostics": _public_diagnostics(review.get("diagnostics")),
        },
        "sync": _public_sync_summary(sync_summary),
        "identity": {
            "workspace_id": binding.get("workspace_id"),
            "machine_id": binding.get("machine_id"),
            "machine_installation_id": binding.get("machine_installation_id"),
            "oauth_subject_hash": binding.get("oauth_subject_hash"),
        },
        "error": explained,
        "error_catalog": [dict(entry) for entry in policy_runtime_error_catalog()],
    }
    dumped = repr(export)
    if any(marker in dumped for marker in _SECRET_MARKERS):
        raise RuntimeError("policy_support_export_secret_leak")
    return export


def _bundle_identity(bundle: object, last_error: object) -> dict[str, object]:
    identity: dict[str, object] = {"applied": False}
    if isinstance(bundle, dict):
        identity.update(
            {
                "applied": True,
                "bundle_hash": bundle.get("bundleHash"),
                "contract_version": bundle.get("contractVersion"),
                "workspace_id": bundle.get("workspaceId"),
                "revision": bundle.get("revision") or bundle.get("policyRevision"),
            }
        )
    if isinstance(last_error, dict):
        identity["last_error"] = {
            "reason": last_error.get("reason"),
            "retained_last_good": True,
        }
    return identity


def _public_sync_summary(summary: object) -> dict[str, object]:
    if not isinstance(summary, dict):
        return {}
    return {
        "synced_at": summary.get("synced_at"),
        "remote_policies_stored": summary.get("remote_policies_stored"),
        "receipts_stored": summary.get("receipts_stored"),
        "pain_signals_uploaded": summary.get("pain_signals_uploaded"),
        "pain_signals_status": summary.get("pain_signals_status"),
        "telemetry_degradation": summary.get("telemetry_degradation"),
        "remote_policy_sync_blocked": summary.get("remote_policy_sync_blocked"),
    }


def _public_diagnostics(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    oauth = value.get("oauth") if isinstance(value.get("oauth"), dict) else {}
    worker = value.get("worker") if isinstance(value.get("worker"), dict) else {}
    outbox = value.get("outbox") if isinstance(value.get("outbox"), dict) else {}
    capability = value.get("capability") if isinstance(value.get("capability"), dict) else {}
    return {
        "capability": {"valid": capability.get("valid"), "reason": capability.get("reason")},
        "oauth": {"configured": oauth.get("configured"), "state": oauth.get("state")},
        "outbox": {"depth": outbox.get("depth"), "state": outbox.get("state")},
        "worker": {
            "state": worker.get("state"),
            "exact_review_route_error": worker.get("exact_review_route_error"),
        },
    }
