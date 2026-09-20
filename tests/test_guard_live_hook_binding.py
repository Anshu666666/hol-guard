"""Atomic live-hook registration with actual SQLite and current process identity.

These are local Store mechanism controls, not native/transport qualification.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store, review_request


def setup(tmp_path: Path) -> tuple[GuardStore, GuardApprovalRequest, dict[str, Any]]:
    store = connected_exact_review_store(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    request = replace(review_request("atomic-live-request"), workspace=str(workspace))
    identity = current_process_identity()
    assert identity is not None
    payload: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        CODEX_BROWSER_WAIT_PROCESS_KEY: identity,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 30,
        "tool_name": "Bash",
        "tool_input": {"command": request.launch_target},
        "cwd": str(workspace),
    }
    return store, request, payload


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def counts(store: GuardStore) -> tuple[int, int, int]:
    return (len(store.list_approval_requests()), len(store.list_guard_sessions()), len(store.list_guard_operations()))


def test_same_waiter_dedup_preserves_deadline_correlation_and_one_operation(tmp_path: Path) -> None:
    store, request, payload = setup(tmp_path)
    first = store.add_approval_request(request, now(), live_hook_payload=payload)
    before = store.get_guard_operation_for_approval_request(first)
    row = store.get_approval_request(first)
    assert row is not None
    snapshot = row["continuation_snapshot"]
    assert isinstance(snapshot, dict)
    second = store.add_approval_request(
        replace(request, request_id="another-generated-id"), now(), live_hook_payload=payload
    )
    assert first == second and counts(store) == (1, 1, 1)
    after = store.get_guard_operation_for_approval_request(first)
    assert before == after
    repeated = store.get_approval_request(first)
    assert repeated is not None and repeated["continuation_snapshot"] == snapshot
    assert snapshot["capability"] == "suspended-response" and snapshot["hookAttached"] is True


def test_changed_wait_payload_cannot_steal_deduplicated_owner(tmp_path: Path) -> None:
    store, request, payload = setup(tmp_path)
    key = store.add_approval_request(request, now(), live_hook_payload=payload)
    before = store.get_approval_request(key)
    operation = store.get_guard_operation_for_approval_request(key)
    changed = {**payload, "tool_input": {"command": "printf changed"}}
    with pytest.raises(ValueError, match="codex_live_hook_owner_conflict"):
        store.add_approval_request(replace(request, request_id="conflicting-id"), now(), live_hook_payload=changed)
    assert counts(store) == (1, 1, 1)
    assert store.get_approval_request(key) == before
    assert store.get_guard_operation_for_approval_request(key) == operation


@pytest.mark.parametrize("change", ["process-token", "process-shape", "timeout-bool", "event"])
def test_invalid_live_binding_leaves_no_request_or_operation(tmp_path: Path, change: str) -> None:
    store, request, payload = setup(tmp_path)
    if change == "process-token":
        payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = {**payload[CODEX_BROWSER_WAIT_PROCESS_KEY], "startToken": "stale"}
    elif change == "process-shape":
        payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = {**payload[CODEX_BROWSER_WAIT_PROCESS_KEY], "extra": True}
    elif change == "timeout-bool":
        payload[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = True
    else:
        payload["hook_event_name"] = "PostToolUse"
    with pytest.raises(ValueError, match="codex_live_hook_binding_invalid"):
        store.add_approval_request(request, now(), live_hook_payload=payload)
    assert counts(store) == (0, 0, 0)


def test_expired_binding_rolls_back_inserted_approval(tmp_path: Path) -> None:
    store, request, payload = setup(tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    with pytest.raises(ValueError, match="codex_live_hook_deadline_expired"):
        store.add_approval_request(request, old, live_hook_payload=payload)
    assert counts(store) == (0, 0, 0)


def test_operation_storage_failure_rolls_back_request_and_session(tmp_path: Path) -> None:
    store, request, payload = setup(tmp_path)
    with store._connect() as db:
        db.execute(
            "create trigger refuse_operation before insert on guard_operations "
            "begin select raise(abort, 'controlled-operation-failure'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="controlled-operation-failure"):
        store.add_approval_request(request, now(), live_hook_payload=payload)
    assert counts(store) == (0, 0, 0)
    with store._connect() as db:
        db.execute("drop trigger refuse_operation")
    key = store.add_approval_request(request, now(), live_hook_payload=payload)
    assert counts(store) == (1, 1, 1)
    operation = store.get_guard_operation_for_approval_request(key)
    assert operation is not None and operation["approval_request_ids"] == [key]


def test_other_adapter_retains_no_automatic_live_binding(tmp_path: Path) -> None:
    store, request, payload = setup(tmp_path)
    key = store.add_approval_request(replace(request, harness="cursor"), now(), live_hook_payload=payload)
    assert counts(store) == (1, 0, 0)
    assert store.get_guard_operation_for_approval_request(key) is None
    row = store.get_approval_request(key)
    assert row is not None
    snapshot = row["continuation_snapshot"]
    assert isinstance(snapshot, dict) and snapshot["capability"] != "suspended-response"


def test_other_live_process_cannot_take_existing_waiter(tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sys
    import time

    from tests.test_guard_codex_live_action_boundary import _close_owned

    store, request, payload = setup(tmp_path)
    key = store.add_approval_request(request, now(), live_hook_payload=payload)
    before = store.get_approval_request(key)
    operation = store.get_guard_operation_for_approval_request(key)
    identity_file = tmp_path / "other-process.json"
    script = (
        "import json,sys;from pathlib import Path;"
        "from codex_plugin_scanner.guard.live_process_identity import current_process_identity;"
        "Path(sys.argv[1]).write_text(json.dumps(current_process_identity()));sys.stdin.read()"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(identity_file)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    try:
        end = time.monotonic() + 5
        while not identity_file.exists() and time.monotonic() < end:
            time.sleep(0.01)
        other = json.loads(identity_file.read_text())
        assert other["pid"] == child.pid and other["pid"] != os.getpid()
        changed = {**payload, CODEX_BROWSER_WAIT_PROCESS_KEY: other}
        with pytest.raises(ValueError, match="codex_live_hook_owner_conflict"):
            store.add_approval_request(
                replace(request, request_id="different-live-owner"), now(), live_hook_payload=changed
            )
        assert counts(store) == (1, 1, 1)
        assert store.get_approval_request(key) == before
        assert store.get_guard_operation_for_approval_request(key) == operation
    finally:
        _close_owned(child)
        if child.stdin is not None:
            child.stdin.close()


def test_verified_native_queue_records_actual_waiter_without_changing_deny(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import time

    from codex_plugin_scanner.guard import native_approval_bridge
    from codex_plugin_scanner.guard.native_approval_bridge import NativeApprovalBridge
    from tests.test_native_approval_v4_transport import _challenge, _status
    from tests.test_native_review_approval_coordination import _edge, _worker

    # The existing test edge supplies a synthetic receipt. Actual HookWorker
    # receipt validation and native-review queue run; this is not a Rust run.
    worker, store = _worker(tmp_path, monkeypatch, _edge("codex"))
    snapshot = {"generation": 7, "policy_digest": "c" * 64, "runtime_identity": "a" * 64}
    monkeypatch.setattr(worker, "prepare_workspace_policy", lambda *_args, **_kwargs: snapshot)
    challenge = _challenge()
    calls: list[str] = []

    def client(**kwargs: Any) -> bytes:
        wire = json.loads(kwargs["payload"])
        calls.append(wire["operation"])
        assert wire["operation"] == "approval_challenge_v4"
        observed = datetime.now(timezone.utc)
        challenge.update(
            request_id=wire["request"]["envelope"]["request_id"],
            harness="codex",
            issued_at_ms=int(observed.timestamp() * 1000),
            expires_at_ms=int((observed + timedelta(seconds=30)).timestamp() * 1000),
        )
        return json.dumps(challenge).encode()

    monkeypatch.setattr(
        native_approval_bridge,
        "_DEFAULT_BRIDGE",
        NativeApprovalBridge(
            client_request=client,
            status_provider=lambda: _status(tmp_path),
            environment_provider=lambda: {},
            clock=time.monotonic,
        ),
    )
    identity = current_process_identity()
    assert identity is not None
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        response = worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://example.test"},
                CODEX_BROWSER_WAIT_PROCESS_KEY: identity,
                CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 30,
            },
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=store.guard_home,
            workspace=workspace,
        )
        pending = store.list_approval_requests(status="pending")
        assert len(pending) == 1 and response["prompted"] is True
        output = response["hookSpecificOutput"]
        assert isinstance(output, dict)
        assert output["permissionDecision"] == "deny"
        operation = store.get_guard_operation_for_approval_request(str(pending[0]["request_id"]))
        assert operation is not None and operation["status"] == "waiting_on_approval"
        metadata = operation["metadata"]
        assert isinstance(metadata, dict)
        assert metadata["codex_browser_wait_process"] == identity
        assert pending[0]["policy_action"] == "review"
        assert calls == ["approval_challenge_v4"]
        envelope = pending[0]["action_envelope_json"]
        assert isinstance(envelope, dict) and envelope["nativeApprovalChallenge"] == challenge
    finally:
        worker.close()


@pytest.mark.parametrize("changed_binding", ["operation", "session"])
def test_stored_owner_binding_change_cannot_create_replacement(tmp_path: Path, changed_binding: str) -> None:
    store, request, payload = setup(tmp_path)
    key = store.add_approval_request(request, now(), live_hook_payload=payload)
    before = store.get_approval_request(key)
    with store._connect() as db:
        if changed_binding == "operation":
            db.execute("update guard_operations set operation_id = 'moved-existing-operation'")
        else:
            db.execute("update guard_sessions set workspace = 'different-workspace'")
    with pytest.raises(ValueError, match="codex_live_hook_owner_conflict"):
        store.add_approval_request(request, now(), live_hook_payload=payload)
    assert counts(store) == (1, 1, 1)
    assert store.get_approval_request(key) == before


@pytest.mark.parametrize("reuse_request_id", [False, True])
def test_waiter_cannot_adopt_existing_non_waiting_request(tmp_path: Path, reuse_request_id: bool) -> None:
    store, request, payload = setup(tmp_path)
    key = store.add_approval_request(request, now())
    existing = store.get_approval_request(key)
    assert existing is not None
    snapshot = existing["continuation_snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["capability"] == "retry-only" and snapshot["hookAttached"] is False
    assert counts(store) == (1, 0, 0)
    with store._connect() as db:
        before = list(db.iterdump())
    incoming = request if reuse_request_id else replace(request, request_id="new-waiting-request")
    with pytest.raises(ValueError, match="codex_live_hook_owner_conflict"):
        store.add_approval_request(incoming, now(), live_hook_payload=payload)
    with store._connect() as db:
        assert list(db.iterdump()) == before
    assert store.get_approval_request(key) == existing
    assert counts(store) == (1, 0, 0)
