"""HGP-188: privacy-safe local policy support export."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.policy_support_export import build_policy_support_export
from tests.guard_exact_cloud_review_support import connected_exact_review_store

_SECRET_MARKERS = ("refresh-token", "dpop_private_key", "access_token", "BEGIN PRIVATE KEY", "canary-secret")


def test_support_export_classifies_failures_without_secrets(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    export = build_policy_support_export(store, now="2026-09-17T12:00:00+00:00")
    dumped = repr(export)
    assert export["kind"] == "hol-guard-policy-support-export.v1"
    assert set(export["failure_classes"]) >= {
        "auth",
        "invalid_policy",
        "wrong_target",
        "runtime_publication",
        "continuation",
    }
    assert export["cloud_review"]["personal_consent_required_for_managed_admin_review"] is False
    assert export["error"]["next_action"]
    assert not any(marker in dumped for marker in _SECRET_MARKERS)
