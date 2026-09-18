"""Transport continuity tests, using synthetic decoder-valid challenges.

These tests exercise actual SQLite transactions and local integrity protection.
They do not establish native enrollment, challenge issuance, or permission.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_approval_models import NativeApprovalSession, _new_session
from codex_plugin_scanner.guard.native_approval_queue import (
    load_native_approval_state,
    queue_native_approval_request,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_approval_v4_transport import _challenge

_NOW = "2026-09-18T00:00:00+00:00"
_MARKER = "SYNTHETIC_PRIVATE_COMMAND_TAIL"


def _store(path: Path) -> GuardStore:
    store = GuardStore(path)
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "synthetic-grant", "workspace_id": "synthetic-workspace", "machine_id": "synthetic-machine"},
        _NOW,
    )
    assert store.get_review_event_oauth_binding() is not None
    return store


def _inputs(
    request_id: str = "synthetic-native-request",
) -> tuple[GuardApprovalRequest, NativeApprovalSession, dict[str, object]]:
    challenge = _challenge()
    challenge["request_id"] = request_id
    issued_at = int(datetime.fromisoformat(_NOW).timestamp() * 1000)
    challenge["issued_at_ms"] = issued_at
    challenge["expires_at_ms"] = issued_at + 60_000
    request = GuardApprovalRequest(
        request_id=request_id,
        harness="claude-code",
        artifact_id="synthetic",
        artifact_name="Bash",
        artifact_hash="synthetic",
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project",
        config_path="/synthetic/workspace",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:4781/requests/{request_id}",
        workspace="/synthetic/workspace",
        launch_target="synthetic",
        action_envelope_json={"action_type": "shell_command", "command": "echo " + _MARKER},
    )
    session = _new_session(challenge, json.dumps({"raw_payload": _MARKER}).encode())
    snapshot: dict[str, object] = {
        "generation": challenge["policy_generation"],
        "policy_digest": challenge["policy_digest"],
        "runtime_identity": challenge["runtime_identity"],
        "source_input_digest": "f" * 64,
        "resident_generation": 9,
        "mode": "enforce",
    }
    return request, session, snapshot


def _queue(store: GuardStore) -> tuple[dict[str, object], NativeApprovalSession, dict[str, object]]:
    request, session, snapshot = _inputs()
    row = queue_native_approval_request(store, request=request, session=session, snapshot=snapshot, now=_NOW)
    return row, session, snapshot


def test_queue_and_companion_commit_together_without_original_payload(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    row, session, snapshot = _queue(store)
    state = load_native_approval_state(store, row)
    assert state is not None
    assert state.challenge == session.challenge and state.snapshot == snapshot
    with store._connect() as connection:
        companion = connection.execute("select * from guard_native_approval_requests").fetchone()
        assert companion is not None
        assert _MARKER not in companion["state_json"]
        assert "raw_payload" not in companion["state_json"]
        assert "/synthetic/workspace" not in companion["state_json"]
        assert companion["proof_json"] is None and companion["consumed_at"] is None
        assert connection.execute("select count(*) from approval_requests").fetchone()[0] == 1
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == 1
    assert row["status"] == "pending"
    # Every property access is detached from the frozen commitment.
    state.challenge["request_id"] = "changed"
    assert state.challenge == session.challenge


def test_companion_failure_rolls_back_queue_and_event(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    request, session, snapshot = _inputs()
    snapshot["policy_digest"] = "0" * 64
    with pytest.raises(ValueError, match="snapshot_mismatch"):
        queue_native_approval_request(store, request=request, session=session, snapshot=snapshot, now=_NOW)
    with store._connect() as connection:
        assert connection.execute("select count(*) from approval_requests").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == 0


def test_distinct_challenges_never_deduplicate_onto_an_older_request(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    first, _, _ = _queue(store)
    request, session, snapshot = _inputs("synthetic-second")
    second = queue_native_approval_request(store, request=request, session=session, snapshot=snapshot, now=_NOW)
    assert second["request_id"] != first["request_id"]
    assert load_native_approval_state(store, first) is not None
    assert load_native_approval_state(store, second) is not None
    with pytest.raises(ValueError, match="already_exists"):
        queue_native_approval_request(store, request=request, session=session, snapshot=snapshot, now=_NOW)
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == 2


@pytest.mark.parametrize(
    "field", ["request_id", "artifact_hash", "workspace", "harness", "queue_group_id", "action_envelope_json"]
)
def test_mutated_request_cannot_reuse_sealed_companion(tmp_path: Path, field: str) -> None:
    store = _store(tmp_path / "guard")
    row, _, _ = _queue(store)
    row[field] = "{}" if field == "action_envelope_json" else "different"
    assert load_native_approval_state(store, row) is None


def test_changed_oauth_subject_cannot_reuse_sealed_companion(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    row, _, _ = _queue(store)
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "changed", "workspace_id": "synthetic-workspace", "machine_id": "synthetic-machine"},
        _NOW,
    )
    assert load_native_approval_state(store, row) is None


@pytest.mark.parametrize("mutation", ["missing", "snapshot", "signature"])
def test_missing_or_forged_companion_is_not_authority(tmp_path: Path, mutation: str) -> None:
    store = _store(tmp_path / "guard")
    row, _, _ = _queue(store)
    with store._connect() as connection:
        if mutation == "missing":
            connection.execute("delete from guard_native_approval_requests")
        else:
            record = connection.execute("select state_json from guard_native_approval_requests").fetchone()
            state = json.loads(record[0])
            if mutation == "snapshot":
                state["snapshot"]["generation"] += 1
            else:
                state["signature"] = "\u2603"
            connection.execute("update guard_native_approval_requests set state_json = ?", (json.dumps(state),))
    assert load_native_approval_state(store, row) is None


def test_missing_oauth_identity_has_no_queue_side_effect(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    request, session, snapshot = _inputs()
    with pytest.raises(ValueError, match="identity_missing"):
        queue_native_approval_request(store, request=request, session=session, snapshot=snapshot, now=_NOW)
    assert store.get_approval_request(request.request_id) is None


def test_conflicting_request_id_is_refused_before_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    request, session, snapshot = _inputs()
    with pytest.raises(ValueError, match="request_mismatch"):
        queue_native_approval_request(
            store, request=replace(request, request_id="different"), session=session, snapshot=snapshot, now=_NOW
        )
    assert store.get_approval_request(request.request_id) is None


def test_expired_challenge_never_enters_the_queue(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    request, session, snapshot = _inputs()
    with pytest.raises(ValueError, match="challenge_expired"):
        queue_native_approval_request(
            store, request=request, session=session, snapshot=snapshot, now="2026-09-18T00:01:00+00:00"
        )
    assert store.get_approval_request(request.request_id) is None


def test_stale_caller_copy_cannot_hide_changed_stored_request(tmp_path: Path) -> None:
    store = _store(tmp_path / "guard")
    row, _, _ = _queue(store)
    with store._connect() as connection:
        connection.execute("update approval_requests set artifact_hash = 'changed'")
    assert load_native_approval_state(store, row) is None
