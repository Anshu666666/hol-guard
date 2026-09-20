"""Actual HTTP/outbox boundaries for exact ACK and current privacy retries."""

from __future__ import annotations

import json
import threading
import urllib.error
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import CloudReviewEventProtocolError
from codex_plugin_scanner.guard.runtime.exact_cloud_review import apply_exact_cloud_review, enable_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)

Reply = tuple[int, dict[str, Any], str | None]


@contextmanager
def _endpoint(reply: Callable[[dict[str, Any]], Reply]) -> Iterator[str]:
    failures: list[BaseException] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            try:
                assert self.path == "/api/guard/review/v2/events:batch"
                assert self.headers["Authorization"] == "Bearer synthetic-loopback-token"
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                status, response, reason = reply(payload)
                content = json.dumps(response).encode()
                self.send_response(status, reason)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except BaseException as error:
                failures.append(error)
                self.send_error(400)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib override
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert failures == []


def _auth(store: GuardStore, endpoint: str) -> dict[str, object]:
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {"sync_url": endpoint, "access_token": "synthetic-loopback-token", **binding}


def _ready(store: GuardStore) -> list[dict[str, object]]:
    return store.list_ready_review_events(now="2099-01-01T00:00:00Z", limit=50)


def _retry_now(store: GuardStore) -> None:
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set next_attempt_at = null where acknowledged_at is null")


def _accepted(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "protocolVersion": 2,
        "acknowledgedThrough": max(event["localStreamSequence"] for event in events),
        "accepted": len(events),
        "rejected": 0,
        "results": [{"eventId": event["eventId"], "status": "accepted", "code": None} for event in events],
    }


@pytest.mark.parametrize(
    "mutation", ["reordered", "duplicate", "foreign", "missing", "wrong-count", "wrong-checkpoint"]
)
def test_malformed_http_ack_leaves_exact_original_sequences_retryable(tmp_path: Path, mutation: str) -> None:
    store = connected_exact_review_store(tmp_path)
    for name in ("first", "second"):
        add_review_request(store, review_request(name))
    before = _ready(store)

    def reply(payload: dict[str, Any]) -> Reply:
        response = _accepted(payload["events"])
        if mutation == "reordered":
            response["results"].reverse()
        elif mutation == "duplicate":
            response["results"][1] = dict(response["results"][0])
        elif mutation == "foreign":
            response["results"][0]["eventId"] = "foreign-event"
        elif mutation == "missing":
            response["results"].pop()
        elif mutation == "wrong-count":
            response["accepted"] += 1
        else:
            response["acknowledgedThrough"] += 1
        return 200, response, None

    with _endpoint(reply) as endpoint, pytest.raises(CloudReviewEventProtocolError):
        cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
    after = _ready(GuardStore(store.guard_home))
    for field in ("event_id", "sequence", "payload_json", "payload_hash"):
        assert [row[field] for row in after] == [row[field] for row in before]
    with store._connect() as connection:
        durable = connection.execute("select acknowledged_at, attempt_count from guard_review_outbox_events").fetchall()
    assert len(durable) == 2
    assert all(row["acknowledged_at"] is None and row["attempt_count"] == 1 for row in durable)
    for name in ("first", "second"):
        request = store.get_approval_request(name)
        assert request is not None and request["status"] == "pending"


def test_http_ack_settles_only_accepted_or_authoritatively_superseded_items(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    names = ["accepted", "duplicate", "stale", "retry", "superseded"]
    for name in names:
        add_review_request(store, review_request(name))
    initial = {str(row["local_request_id"]): row for row in _ready(store)}
    delivered: list[list[str]] = []

    def reply(payload: dict[str, Any]) -> Reply:
        events = payload["events"]
        delivered.append([event["localRequestId"] for event in events])
        results = []
        for event in events:
            name = event["localRequestId"]
            status = name if name in {"accepted", "duplicate", "stale"} else "rejected"
            code = "decision_queued" if name == "superseded" else "temporary_failure" if name == "retry" else None
            results.append({"eventId": event["eventId"], "status": status, "code": code})
        return (
            200,
            {"protocolVersion": 2, "acknowledgedThrough": 3, "accepted": 3, "rejected": 2, "results": results},
            None,
        )

    with _endpoint(reply) as endpoint:
        result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
    assert len(delivered) == 1
    assert result["synced"] == 3
    assert [row["local_request_id"] for row in _ready(store)] == ["retry"]
    with store._connect() as connection:
        rows = connection.execute("select local_request_id, acknowledged_at from guard_review_outbox_events").fetchall()
    assert [(row["local_request_id"], row["acknowledged_at"] is not None) for row in rows] == [
        ("retry", False),
        ("superseded", True),
    ]
    remaining = _ready(store)[0]
    assert remaining["event_id"] == initial["retry"]["event_id"]
    assert remaining["payload_hash"] == initial["retry"]["payload_hash"]


def test_snapshot_required_after_signed_resolution_never_recreates_pending_authority(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("terminal-during-post")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    signed = remote_approval(store, request.request_id, receipt_id="terminal-receipt")
    uploads: list[dict[str, Any]] = []

    def reply(payload: dict[str, Any]) -> Reply:
        events = payload["events"]
        uploads.extend(events)
        if len(uploads) == 1:
            apply_exact_cloud_review(store, remote_approval=signed)
            return (
                200,
                {
                    "protocolVersion": 2,
                    "acknowledgedThrough": 0,
                    "accepted": 0,
                    "rejected": 1,
                    "results": [
                        {
                            "eventId": events[0]["eventId"],
                            "status": "quarantined",
                            "code": "review_event_snapshot_required",
                        }
                    ],
                },
                None,
            )
        return 200, _accepted(events), None

    with _endpoint(reply) as endpoint:
        result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
    terminal = store.get_approval_request(request.request_id)
    assert terminal is not None and terminal["status"] == "resolved"
    assert len(uploads) == 2
    assert [json.loads(event["eventPayloadJson"])["status"] for event in uploads] == ["pending", "resolved"]
    assert all(
        json.loads(event["eventPayloadJson"])["eventType"] != "review.request.snapshot_requeued" for event in uploads
    )
    outbox = result["outbox"]
    assert isinstance(outbox, dict) and outbox["depth"] == 0
    assert (
        store.requeue_pending_review_events(
            changed_at="2099-01-01T00:00:00Z", require_binding=True, snapshot_repair_sequences={request.request_id: 1}
        )
        == 0
    )
    assert store.get_approval_request(request.request_id) == terminal


def test_failed_http_upload_reprojects_current_privacy_without_changing_original_event(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    command = "echo harmless-private-context"
    request = replace(
        review_request("privacy-retry"),
        raw_command_text=command,
        action_envelope_json={"action_type": "shell_command", "command": command},
    )
    add_review_request(store, request)
    original = _ready(store)[0]
    captures: list[dict[str, Any]] = []

    def reply(payload: dict[str, Any]) -> Reply:
        captures.append(payload["events"][0])
        if len(captures) < 3:
            return 422, {}, "Synthetic retry required"
        return 200, _accepted(payload["events"]), None

    with _endpoint(reply) as endpoint:
        for level in ("none", "full", "none"):
            (store.guard_home / "config.toml").write_text(f'receipt_redaction_level = "{level}"\n')
            _retry_now(store)
            if level == "none" and len(captures) == 2:
                cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
            else:
                with pytest.raises(urllib.error.HTTPError):
                    cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
                current = _ready(store)[0]
                assert current["payload_json"] == original["payload_json"]
                assert current["payload_hash"] == original["payload_hash"]
    assert captures[0]["rawCommand"] == command
    assert captures[1]["rawCommand"] is None
    assert json.loads(captures[1]["eventPayloadJson"])["requestSnapshot"]["raw_command_text"] is None
    assert captures[1]["displayProvenance"] == "redacted"
    assert captures[2]["rawCommand"] == command
    assert len({event["eventId"] for event in captures}) == 1
    assert len({event["localStreamSequence"] for event in captures}) == 1
    assert captures[0]["payloadHash"] == captures[2]["payloadHash"] != captures[1]["payloadHash"]
    assert _ready(store) == []


def test_remote_http_reason_never_enters_retry_state_logs_or_status(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("reason-privacy"))
    canary = "opaque-private-reason-c7f8492"

    def reply(payload: dict[str, Any]) -> Reply:
        return 422, {"ignored": True}, canary

    with _endpoint(reply) as endpoint, pytest.raises(urllib.error.HTTPError):
        cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
    state = store.get_sync_payload("guard_cloud_review_sync_state")
    assert canary not in json.dumps(state)
    assert canary not in json.dumps(_ready(store))
    assert canary not in json.dumps(cloud_review_sync.cloud_review_sync_status(store))
    assert canary not in caplog.text
    assert "422" in str(state)


@pytest.mark.parametrize("field", ["protocolVersion", "resultCode"])
def test_untrusted_protocol_diagnostics_never_enter_retry_state_logs_or_status(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, field: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("protocol-privacy"))
    canary = "opaque-private-protocol-c7f8492"

    def reply(payload: dict[str, Any]) -> Reply:
        response = _accepted(payload["events"])
        if field == "protocolVersion":
            response["protocolVersion"] = canary
        else:
            response.update(acknowledgedThrough=0, accepted=0, rejected=1)
            response["results"][0].update(status="rejected", code=canary)
        return 200, response, None

    with _endpoint(reply) as endpoint:
        if field == "protocolVersion":
            with pytest.raises(CloudReviewEventProtocolError):
                cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
        else:
            result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, endpoint))
            assert canary not in json.dumps(result)
    assert canary not in json.dumps(store.get_sync_payload("guard_cloud_review_sync_state"))
    assert canary not in json.dumps(_ready(store))
    assert canary not in json.dumps(cloud_review_sync.cloud_review_sync_status(store))
    assert canary not in caplog.text


def test_unclassified_failure_never_enters_retry_state_logs_or_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("unclassified-error-privacy"))
    canary = "opaque-private-transport-error-c7f8492"

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError(canary)

    monkeypatch.setattr(cloud_review_sync, "_post_events_with_oauth_refresh", fail)
    with pytest.raises(RuntimeError):
        cloud_review_sync.sync_cloud_review_events_once(store, _auth(store, "http://127.0.0.1:1"))
    assert canary not in json.dumps(store.get_sync_payload("guard_cloud_review_sync_state"))
    assert canary not in json.dumps(_ready(store))
    assert canary not in json.dumps(cloud_review_sync.cloud_review_sync_status(store))
    assert canary not in caplog.text


def test_worker_http_failure_never_logs_remote_reason_or_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from codex_plugin_scanner.guard.review_event_wake import ReviewEventWakeSignal
    from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker

    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("worker-error-privacy"))
    canary = "opaque-private-worker-error-c7f8492"
    stop = threading.Event()

    def reply(payload: dict[str, Any]) -> Reply:
        stop.set()
        return 422, {}, canary

    with _endpoint(reply) as endpoint:
        monkeypatch.setattr(
            cloud_review_sync, "_resolve_cloud_review_sync_auth_context", lambda _store: _auth(store, endpoint)
        )
        cloud_review_sync_worker._cloud_sync_sync_loop(
            store, stop, ReviewEventWakeSignal(), poll_interval=0.01, error_backoff=0.01, error_backoff_base=0.01
        )
    assert stop.is_set()
    assert canary not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    assert canary not in json.dumps(store.get_sync_payload("guard_cloud_review_sync_state"))
    assert canary not in json.dumps(cloud_review_sync.cloud_review_sync_status(store))
    assert "422" in caplog.text
