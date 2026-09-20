"""Actual daemon/bridge/waiting action with a controlled native transport.

Only native edge/snapshot and resident responses are synthetic. The shipped
challenge producer, Store/outbox, command authorization, authenticated loopback
completion, owned child and action execution run normally. This does not verify
WebAuthn cryptography or qualify installed native authority.
"""

from __future__ import annotations

import copy
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_approval_bridge
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_approval_bridge import NativeApprovalBridge
from codex_plugin_scanner.guard.runtime.exact_cloud_review import authorize_exact_cloud_review_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review_executor import execute_exact_cloud_review_operation
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_result
from tests.test_guard_codex_live_action_boundary import LiveAction, _close_owned
from tests.test_native_approval_v4_transport import _artifact, _challenge, _result, _status
from tests.test_native_review_approval_coordination import _edge, _worker


class LiveNativeAction:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str = "replay") -> None:
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        edge_worker, _ = _worker(tmp_path, monkeypatch, _edge("codex"))
        edge_worker.close()
        self.challenge = _challenge()
        self.snapshot = {"generation": 7, "policy_digest": "c" * 64, "runtime_identity": "a" * 64}
        monkeypatch.setattr(HookWorker, "prepare_workspace_policy", lambda _self, *_args, **_kwargs: self.snapshot)
        self.calls: list[dict[str, Any]] = []
        self.original_envelope: dict[str, Any] | None = None
        self.consumed = False

        def client(**kwargs: object) -> bytes:
            encoded = kwargs["payload"]
            assert isinstance(encoded, bytes)
            wire = json.loads(encoded)
            self.calls.append(wire)
            operation = wire["operation"]
            envelope = wire["request"]["envelope"]
            if operation == "approval_challenge_v4":
                assert self.original_envelope is None
                self.original_envelope = copy.deepcopy(envelope)
                now = datetime.now(timezone.utc)
                self.challenge.update(
                    request_id=envelope["request_id"],
                    harness="codex",
                    issued_at_ms=int(now.timestamp() * 1000),
                    expires_at_ms=int((now + timedelta(seconds=30)).timestamp() * 1000),
                )
                return json.dumps(self.challenge).encode()
            assert self.original_envelope is not None
            assert {k: v for k, v in envelope.items() if k != "deadline_budget_ms"} == {
                k: v for k, v in self.original_envelope.items() if k != "deadline_budget_ms"
            }
            if self.consumed:
                return b"{}"
            phase = "validated" if operation == "approval_validate_v4" else "consumed"
            result = _result(phase=phase)
            receipt = result["receipt"]
            assert isinstance(receipt, dict)
            for key in (set(receipt) & set(self.challenge)) - {"schema"}:
                receipt[key] = self.challenge[key]
            self.consumed = phase == "consumed"
            return json.dumps(result).encode()

        bridge = NativeApprovalBridge(
            client_request=client,
            status_provider=lambda: _status(tmp_path),
            environment_provider=lambda: {},
            clock=time.monotonic,
        )
        monkeypatch.setattr(native_approval_bridge, "_DEFAULT_BRIDGE", bridge)
        self.action = LiveAction(tmp_path, mode)
        self.store = self.action.store
        self.home = self.action.home
        self.payload = self.action.payload
        self.request_id = ""
        self.proof: dict[str, Any] = {}

    def start(self) -> None:
        self.action.start()
        self.request_id = self.action.request_id
        row = self.store.get_approval_request(self.request_id)
        assert isinstance(row, dict)
        envelope = row["action_envelope_json"]
        assert isinstance(envelope, dict) and envelope["nativeApprovalChallenge"] == self.challenge
        self.proof = {
            "schema": "guard-native-approval-proof.v4",
            "challenge": copy.deepcopy(self.challenge),
            "assertion": _artifact()["webauthn"],
        }
        assert [call["operation"] for call in self.calls] == ["approval_challenge_v4"]
        assert self.original_envelope is not None
        assert self.original_envelope["raw_payload"] == json.loads(self.action.bound_payload.read_text())
        assert self.original_envelope["raw_payload"]["tool_input"] == self.payload["tool_input"]

    def close(self) -> None:
        self.action.close()

    def job(self) -> dict[str, Any]:
        from tests.test_native_live_approval_completion import NativeWait

        # Shared synthetic command builder; no authority factory is injected.
        return NativeWait.job(cast(NativeWait, cast(object, self)))


def test_real_waiting_action_completes_once_after_actual_command_and_consumed_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait = LiveNativeAction(tmp_path, monkeypatch)
    try:
        wait.start()
        original_request = wait.store.get_approval_request(wait.request_id)
        original_operation = wait.store.get_guard_operation_for_approval_request(wait.request_id)
        repeated = wait.action.daemon._server.hook_worker.review_http_payload(
            payload=json.loads(wait.action.bound_payload.read_text()),
            params={},
            default_harness="codex",
            home_dir=wait.home,
            guard_home=wait.store.guard_home,
            workspace=wait.action.workspace,
        )
        assert repeated["approval_request_id"] == wait.request_id
        assert wait.store.get_approval_request(wait.request_id) == original_request
        assert wait.store.get_guard_operation_for_approval_request(wait.request_id) == original_operation
        assert len(wait.calls) == 1
        job = wait.job()
        authorized = authorize_exact_cloud_review_job(wait.store, job)
        assert authorized.operation == "guard.review.resolveExact"
        execution = execute_exact_cloud_review_operation(
            payload=job["payload"],
            store=wait.store,
            generated_at=datetime.now(timezone.utc).isoformat(),
            job=job,
            resume_after_approval=lambda **_kwargs: pytest.fail("native flow used legacy resume"),
        )
        output = wait.action.finish()
        assert output["allowed"] is True
        assert wait.action.marker.read_bytes() == b"executed\n"
        assert [row["completed"] for row in output["completion"]] == [True, True]
        assert output["completion"][1]["replayed"] is True
        assert [call["operation"] for call in wait.calls] == [
            "approval_challenge_v4",
            "approval_validate_v4",
            "approval_consume_v4",
        ]
        wire = exact_result(job, execution)
        assert wire["applicationStatus"] == "applied" and wire["continuationStatus"] == "resumed"
    finally:
        wait.close()


def test_killed_actual_waiter_cannot_receive_native_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wait = LiveNativeAction(tmp_path, monkeypatch)
    try:
        wait.start()
        job = wait.job()
        assert wait.action.child is not None
        _close_owned(wait.action.child)
        from codex_plugin_scanner.guard.native_live_approval_state import stage_native_job

        with pytest.raises(ValueError, match="native_live_owner_unavailable"):
            stage_native_job(wait.store, job, now=datetime.now(timezone.utc).isoformat())
        assert not wait.action.marker.exists() and not wait.consumed
        assert [call["operation"] for call in wait.calls] == ["approval_challenge_v4"]
    finally:
        wait.close()
