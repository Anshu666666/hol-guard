"""Diagnostic projections accept typed observations, never stored arbitrary text."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_runtime_error_catalog import explain_policy_runtime_error
from codex_plugin_scanner.guard.policy_support_export import build_policy_support_export
from tests.guard_exact_cloud_review_support import connected_exact_review_store

_CANARY = "opaque-private-observation-7fc9"
_NOW = "2026-09-17T12:00:00+00:00"
_SUMMARY_KEYS = (
    "synced_at",
    "remote_policies_stored",
    "receipts_stored",
    "pain_signals_uploaded",
    "pain_signals_upload_status",
    "remote_policy_sync_blocked",
)


@pytest.mark.parametrize("code", [_CANARY, "untrusted_signing_key", "bundle_signature_invalid"])
def test_error_guidance_never_reflects_unknown_code_or_detail(code: str) -> None:
    explained = explain_policy_runtime_error(code, detail=_CANARY)
    assert _CANARY not in json.dumps(explained)
    assert explained["code"] == ("unclassified_failure" if code == _CANARY else code)
    assert explained["explanation"] and explained["next_action"]
    assert "detail" not in explained or explained["detail"] is None


@pytest.mark.parametrize("field", _SUMMARY_KEYS)
@pytest.mark.parametrize("nested", [False, True])
def test_actual_saved_sync_summary_cannot_export_arbitrary_scalar_or_container(
    tmp_path: Path, field: str, nested: bool
) -> None:
    store = connected_exact_review_store(tmp_path)
    value: object = {"unexpected": [_CANARY]} if nested else _CANARY
    store.set_sync_payload("sync_summary", {field: value}, _NOW)
    before = store.get_sync_payload("sync_summary")
    export = build_policy_support_export(store, now=_NOW)
    assert _CANARY not in json.dumps(export)
    assert store.get_sync_payload("sync_summary") == before
    summary = export["sync"]
    assert isinstance(summary, dict)
    output_key = "pain_signals_status" if field == "pain_signals_upload_status" else field
    assert summary[output_key] is None


@pytest.mark.parametrize("value", [True, False, -1, 1.5, "7", 9_007_199_254_740_992])
def test_export_refuses_invalid_count_atoms(tmp_path: Path, value: object) -> None:
    store = connected_exact_review_store(tmp_path)
    store.set_sync_payload("sync_summary", {"receipts_stored": value}, _NOW)
    summary = build_policy_support_export(store, now=_NOW)["sync"]
    assert isinstance(summary, dict) and summary["receipts_stored"] is None


def test_valid_summary_and_declared_version_remain_available(tmp_path: Path) -> None:
    from codex_plugin_scanner.version import __version__

    store = connected_exact_review_store(tmp_path)
    stored = {
        "synced_at": "2026-09-17T12:00:00Z",
        "remote_policies_stored": 0,
        "receipts_stored": 7,
        "pain_signals_uploaded": 9_007_199_254_740_991,
        "pain_signals_upload_status": "success",
        "remote_policy_sync_blocked": False,
    }
    store.set_sync_payload("sync_summary", stored, _NOW)
    export = build_policy_support_export(store, now=_NOW)
    assert export["guard_version"] == __version__
    assert export["sync"] == {
        "synced_at": _NOW,
        "remote_policies_stored": 0,
        "receipts_stored": 7,
        "pain_signals_uploaded": 9_007_199_254_740_991,
        "pain_signals_status": "success",
        "telemetry_degradation": None,
        "remote_policy_sync_blocked": False,
    }
    assert len(json.dumps(export).encode()) < 65_536
    assert store.get_sync_payload("sync_summary") == stored
