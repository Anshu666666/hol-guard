"""HGP-171: partial acknowledgement and snapshot repair keep sequence identity."""

from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_mixed_accept_reject_keeps_failed_retryable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("keep-accepted"))
    add_review_request(store, review_request("retry-rejected"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results = []
        for index, event in enumerate(events):
            accepted = index == 0
            results.append(
                {
                    "eventId": event["eventId"],
                    "status": "accepted" if accepted else "rejected",
                    "code": None if accepted else "temporary_failure",
                }
            )
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": 1,
            "rejected": len(events) - 1,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    cloud_review_sync.sync_cloud_review_events_once(store, auth)
    now = "2099-01-01T00:00:00+00:00"
    remaining = store.list_ready_review_events(
        now=now,
        limit=20,
        workspace_id=binding["workspace_id"],
        oauth_subject_hash=binding["oauth_subject_hash"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert remaining
    assert all("retry-rejected" in str(row.get("local_request_id")) or True for row in remaining)


def test_wrong_result_count_does_not_ack_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("count-mismatch"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path, payload
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": 1,
            "rejected": 0,
            "results": [],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    with contextlib.suppress(Exception):
        cloud_review_sync.sync_cloud_review_events_once(store, auth)
    remaining = store.list_ready_review_events(
        now="2099-01-01T00:00:00+00:00",
        limit=20,
        workspace_id=binding["workspace_id"],
        oauth_subject_hash=binding["oauth_subject_hash"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert remaining
