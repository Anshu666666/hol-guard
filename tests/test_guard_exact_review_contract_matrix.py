"""Actual signed receiver/SQLite boundaries; test trust is not browser MFA."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    cloud_review_settings_status,
)
from codex_plugin_scanner.guard.review_contracts import (
    payload_hash_for_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    authorize_exact_cloud_review_job,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    exact_review_job,
    remote_approval,
    review_request,
)
from tests.guard_review_signing_helpers import sign_review_payload


def _permission_rows(
    store: GuardStore,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with store._connect() as connection:
        once = [
            dict(row) for row in connection.execute("select * from guard_local_once_approvals order by approval_id")
        ]
    return store.list_policy_decisions(), once


def _resign(envelope: dict[str, object]) -> None:
    envelope["payloadHash"] = payload_hash_for_remote_approval_envelope(envelope)
    envelope["signature"] = sign_review_payload(envelope)


@pytest.mark.parametrize("phase", ["after_queue_admission", "before_commit"])
@pytest.mark.parametrize(
    "change",
    ["policy_revision", "command_arguments", "artifact_hash", "harness", "status"],
)
def test_each_stale_binding_refuses_without_consuming_other_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, change: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    unrelated = review_request("unrelated-permission")
    add_review_request(store, unrelated)
    apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, unrelated.request_id, receipt_id="unrelated-receipt"),
    )
    before = _permission_rows(store)
    request = review_request("stale-after-admission")
    add_review_request(store, request)
    proof = remote_approval(store, request.request_id, receipt_id="stale-receipt")
    authorize_exact_cloud_review_job(store, exact_review_job(store, proof))
    columns = {
        "policy_revision": (
            "decision_v2_json",
            json.dumps({"policyVersion": "changed-policy-revision"}),
        ),
        "command_arguments": (
            "action_envelope_json",
            json.dumps(
                {
                    "action_type": "shell_command",
                    "command": "printf changed",
                    "tool_name": "Bash",
                }
            ),
        ),
        "artifact_hash": ("artifact_hash", "changed-artifact-hash"),
        "harness": ("harness", "claude-code"),
        "status": ("status", "resolved"),
    }

    def mutate() -> None:
        column, value = columns[change]
        with GuardStore(store.guard_home)._connect() as connection:
            connection.execute(
                f"update approval_requests set {column} = ? where request_id = ?",
                (value, request.request_id),
            )

    def apply() -> str:
        try:
            apply_exact_cloud_review(store, remote_approval=proof, expected_harness="codex")
        except ExactCloudReviewError as error:
            return error.code
        return "unexpected-success"

    if phase == "after_queue_admission":
        mutate()
        code = apply()
    else:
        entered = threading.Event()
        release = threading.Event()
        original = store.resolve_one_request_with_signed_remote_exact_result

        def barrier(*args: Any, **kwargs: Any) -> dict[str, object]:
            entered.set()
            assert release.wait(10), "owned application barrier was not released"
            return original(*args, **kwargs)

        monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", barrier)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(apply)
            try:
                assert entered.wait(10), "application did not reach the commit boundary"
                mutate()
            finally:
                release.set()
            code = future.result(timeout=10)
        monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", original)
    expected = (
        "remote_exact_request_not_pending"
        if change == "status"
        else (
            "remote_exact_harness_mismatch"
            if change == "harness" and phase == "after_queue_admission"
            else "remote_exact_request_stale"
        )
    )
    assert code == expected
    assert not store.has_exact_cloud_review_receipt("stale-receipt")
    assert _permission_rows(store) == before
    assert store.get_sync_payload("guard_review_memory_registry") is None
    rejected = store.list_events(limit=1, event_name="cloud_review.exact_rejected")
    assert rejected and expected in json.dumps(rejected)
    fresh = review_request("fresh-after-stale")
    add_review_request(store, fresh)
    result = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, fresh.request_id, receipt_id="fresh-receipt", decision="block"),
    )
    assert result.action == "block"
    assert _permission_rows(store) == before


@pytest.mark.parametrize("duplicate", [False, True])
def test_actual_simultaneous_signed_receipts_commit_only_one_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, duplicate: bool
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    request = review_request("concurrent-review-target")
    add_review_request(store, request)
    first = remote_approval(store, request.request_id, receipt_id="first-review", decision="allow_once")
    second = (
        first if duplicate else remote_approval(store, request.request_id, receipt_id="second-review", decision="block")
    )
    other = GuardStore(store.guard_home)
    gate = threading.Barrier(2, timeout=10)
    for current in (store, other):
        original = current.resolve_one_request_with_signed_remote_exact_result

        def barrier(*args: Any, _original: Any = original, **kwargs: Any) -> dict[str, object]:
            gate.wait()
            return _original(*args, **kwargs)

        monkeypatch.setattr(current, "resolve_one_request_with_signed_remote_exact_result", barrier)

    def apply(current: GuardStore, proof: dict[str, object]) -> tuple[str, str]:
        try:
            result = apply_exact_cloud_review(current, remote_approval=proof)
            return "resolved", result.action
        except ExactCloudReviewError as error:
            return "refused", error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(apply, current, proof) for current, proof in ((store, first), (other, second))]
        outcomes = [future.result(timeout=15) for future in futures]
    assert sum(result[0] == "resolved" for result in outcomes) == 1
    assert sum(result == ("refused", "remote_exact_request_not_pending") for result in outcomes) == 1
    row = store.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "resolved"
    assert row["resolution_action"] == next(result[1] for result in outcomes if result[0] == "resolved")
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_exact_cloud_review_receipts").fetchone()[0] == 1
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == (
            1 if row["resolution_action"] == "allow" else 0
        )
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("guard_review_memory_registry") is None
    assert store.get_request_resume(request.request_id) is None


def test_abrupt_process_exit_after_commit_does_not_replay_resolution(
    tmp_path: Path,
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    request = review_request("crash-after-commit")
    add_review_request(store, request)
    proof = remote_approval(store, request.request_id, receipt_id="crash-commit-receipt")
    proof_file = tmp_path / "synthetic-proof.json"
    proof_file.write_text(json.dumps(proof))
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json,os,sys; from pathlib import Path; from codex_plugin_scanner.guard.store import GuardStore; "
            "from codex_plugin_scanner.guard.runtime.exact_cloud_review import apply_exact_cloud_review; "
            "apply_exact_cloud_review(GuardStore(Path(sys.argv[1])),"
            "remote_approval=json.loads(Path(sys.argv[2]).read_text())); os._exit(71)",
            str(store.guard_home),
            str(proof_file),
        ],
        capture_output=True,
        timeout=20,
        check=False,
        env=dict(os.environ),
    )
    assert child.returncode == 71 and child.stdout == b"" and child.stderr == b""
    restarted = GuardStore(store.guard_home)
    before = _permission_rows(restarted)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_replayed"):
        apply_exact_cloud_review(restarted, remote_approval=proof)
    assert _permission_rows(restarted) == before
    assert restarted.get_sync_payload("guard_review_memory_registry") is None
    assert restarted.get_request_resume(request.request_id) is None
    assert len(restarted.list_events(limit=10, event_name="cloud_review.exact_applied")) == 1


@pytest.mark.parametrize("role", ["owner", "workspace-owner", "admin"])
def test_each_signed_admin_role_resolves_only_one_request_without_personal_consent(tmp_path: Path, role: str) -> None:
    store = connected_exact_review_store(tmp_path)
    for request_id in ("admin-target", "admin-other"):
        add_review_request(store, review_request(request_id))
    status = cloud_review_settings_status(store)
    assert status["enabled"] is False
    assert status["personal_consent_required_for_managed_admin_review"] is False
    proof = remote_approval(
        store,
        "admin-target",
        receipt_id="admin-valid",
        authority="workspace_admin_mfa",
        reviewer_role=role,
        step_up_challenge_id="synthetic-step-up",
    )
    assert apply_exact_cloud_review(store, remote_approval=proof).action == "allow"
    other = store.get_approval_request("admin-other")
    assert other is not None and other["status"] == "pending"
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("guard_review_memory_registry") is None


def test_properly_resigned_foreign_workspace_cannot_inherit_admin_authority(
    tmp_path: Path,
) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("foreign-admin")
    add_review_request(store, request)
    proof = remote_approval(
        store,
        request.request_id,
        receipt_id="foreign-admin-receipt",
        authority="workspace_admin_mfa",
        step_up_challenge_id="synthetic-step-up",
    )
    proof["workspaceId"] = "workspace-other"
    _resign(proof)
    before = _permission_rows(store)
    with pytest.raises(ExactCloudReviewError) as error:
        apply_exact_cloud_review(store, remote_approval=proof)
    assert error.value.code == "signing_key_workspace_mismatch"
    assert not store.has_exact_cloud_review_receipt("foreign-admin-receipt")
    pending = store.get_approval_request(request.request_id)
    assert pending is not None and pending["status"] == "pending"
    assert _permission_rows(store) == before
    assert store.get_sync_payload("guard_review_memory_registry") is None
