"""Shipped bridge, real loopback daemon and one waiting process/action boundary.

OAuth/signing enrollment uses the explicit test trust fixture and policy uses
its Python oracle. These controls do not qualify ordinary login or installed
native enforcement. No operation/session rows or completion results are seeded.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import _daemon_json_post
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.live_process_identity import process_identity_matches
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store, remote_approval

_CHILD = r"""
import contextlib, io, json, subprocess, sys
from pathlib import Path
from urllib.parse import urlencode
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
params=json.loads(sys.stdin.read())
# Only browser UI is stubbed. The identity producer, HTTP authentication,
# polling, policy revalidation and completion are actual shipped functions.
resume.open_browser_url=lambda _url: False
bind=bridge._with_browser_wait_process
def observe_binding(*args, **kwargs):
    data=bind(*args, **kwargs)
    Path(params['bound_payload']).write_text(data)
    return data
bridge._with_browser_wait_process=observe_binding
observed=[]
original_post=resume._daemon_json_post
def observe_post(**kwargs):
    if params['mode']=='wrong-command':
        hook=json.loads(kwargs['payload']['hook_input'])
        hook['tool_input']['command']='printf different'
        kwargs['payload']={'hook_input':json.dumps(hook)}
    def call():
        try:
            result=original_post(**kwargs)
            observed.append({'completed':result.get('completed') is True,
                'replayed':result.get('replayed') is True,'httpStatus':200})
            return result
        except Exception as error:
            status=getattr(error,'status',None)
            observed.append({'completed':False,'replayed':False,
                'httpStatus':status if type(status) is int else None})
            raise
    result=call()
    if params['mode']=='replay':
        repeated=call()
        assert repeated.get('completed') is True and repeated.get('replayed') is True
    return result
resume._daemon_json_post=observe_post
sys.stdin=io.StringIO(json.dumps(params['payload']))
output=io.StringIO()
with contextlib.redirect_stdout(output):
    exit_code=bridge.main(state_path=Path(params['guard_home'])/'daemon-state.json',
        fallback_command=[sys.executable,'-c','raise SystemExit(1)'],start_command=[],
        query=urlencode({'guard-home':params['guard_home'],'home':params['home']}),
        hook_timeouts={'PreToolUse':30})
allowed=exit_code==0 and json.loads(output.getvalue())==resume.allow_pretool_response()
if allowed:
    with Path(params['marker']).open('ab') as observed_output:
        subprocess.run(params['argv'],check=True,timeout=5,stdout=observed_output)
print(json.dumps({'allowed':allowed,'bridgeExit':exit_code,'completion':observed}),flush=True)
"""


def _exited_without_reaping(child: subprocess.Popen[bytes]) -> bool:
    if os.name == "posix":
        return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    return child.poll() is not None


def _close_owned(child: subprocess.Popen[bytes], *, require_exit: bool = False) -> int:
    """Pin the leader until the sole group signal; never signal after reaping."""
    if child.returncode is not None:
        return child.returncode
    if require_exit:
        end = time.monotonic() + 30
        while not _exited_without_reaping(child) and time.monotonic() < end:
            time.sleep(0.01)
        assert _exited_without_reaping(child), "owned bridge did not finish"
    if os.name == "posix":
        # Popen has not polled/waited: the live or waitable leader pins the PGID.
        with suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        code = child.wait(timeout=5)
        end = time.monotonic() + 5
        while True:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                return code
            assert time.monotonic() < end, "owned process group remains"
            time.sleep(0.01)
    if not _exited_without_reaping(child):
        child.kill()
    return child.wait(timeout=5)


class LiveAction:
    def __init__(self, tmp: Path, mode: str, *, wait_seconds: int = 120):
        self.tmp = tmp
        self.request_id = ""
        self.operation: dict[str, Any] = {}
        self.store = connected_exact_review_store(tmp)
        self.workspace = tmp / "workspace"
        self.workspace.mkdir()
        self.home = tmp / "home"
        self.home.mkdir()
        self.marker = self.workspace / "effect.txt"
        self.bound_payload = tmp / "bound-payload.json"
        self.argv = ["/usr/bin/printf", "executed\n"]
        self.payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": shlex.join(self.argv)},
            "cwd": str(self.workspace),
        }
        (self.store.guard_home / "config.toml").write_text(
            'mode="enforce"\ndefault_action="review"\nsubprocess_action="review"\n'
            f"approval_wait_timeout_seconds={wait_seconds}\n"
        )
        enable_exact_cloud_review(self.store)
        self.daemon = GuardDaemonServer(
            self.store,
            host="127.0.0.1",
            port=0,
            home_dir=self.home,
            workspace_dir=self.workspace,
            idle_timeout_seconds=60,
        )
        self.child: subprocess.Popen[bytes] | None = None
        self.output = (tmp / "child.stdout").open("wb")
        self.errors = (tmp / "child.stderr").open("wb")
        self.mode = mode

    def start(self) -> None:
        self.daemon.start()
        self.start_child()

    def start_child(self, *, expected_marker: bytes | None = None) -> None:
        self.child = subprocess.Popen(
            [sys.executable, "-c", _CHILD],
            stdin=subprocess.PIPE,
            stdout=self.output,
            stderr=self.errors,
            env=dict(os.environ),
            start_new_session=os.name == "posix",
        )
        assert self.child.stdin is not None
        self.child.stdin.write(
            json.dumps(
                {
                    "guard_home": str(self.store.guard_home),
                    "home": str(self.home),
                    "payload": self.payload,
                    "argv": self.argv,
                    "marker": str(self.marker),
                    "bound_payload": str(self.bound_payload),
                    "mode": self.mode,
                }
            ).encode()
        )
        self.child.stdin.close()
        end = time.monotonic() + 10
        while time.monotonic() < end:
            pending = self.store.list_approval_requests(status="pending", harness="codex")
            if pending:
                assert len(pending) == 1
                self.request_id = str(pending[0]["request_id"])
                assert not _exited_without_reaping(self.child)
                assert (self.marker.read_bytes() if self.marker.exists() else None) == expected_marker
                operation = self.store.get_guard_operation_for_approval_request(self.request_id)
                assert operation is not None
                self.operation = cast(dict[str, Any], operation)
                metadata = self.operation["metadata"]
                assert isinstance(metadata, dict)
                assert metadata["codex_browser_wait_process"]["pid"] == self.child.pid
                assert process_identity_matches(metadata["codex_browser_wait_process"])
                assert operation["approval_request_ids"] == [self.request_id]
                assert pending[0]["workspace"] == str(self.workspace)
                return
            assert not _exited_without_reaping(self.child), "bridge exited before pending request"
            time.sleep(0.02)
        raise AssertionError("real hook did not queue an approval")

    def approve(self, *, decision: str = "allow_once") -> None:
        approval = remote_approval(self.store, self.request_id, receipt_id="signed-action-boundary", decision=decision)
        result = apply_exact_cloud_review(self.store, remote_approval=approval, expected_harness="codex")
        assert result.action == ("allow" if decision == "allow_once" else "block")

    def finish(self) -> dict[str, Any]:
        assert self.child is not None
        assert _close_owned(self.child, require_exit=True) == 0
        self.output.close()
        self.errors.close()
        return json.loads((self.tmp / "child.stdout").read_text())

    def close(self) -> None:
        try:
            if self.child is not None:
                _close_owned(self.child)
        finally:
            self.output.close()
            self.errors.close()
            self.daemon.stop()


@contextmanager
def live_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str = "normal", *, wait_seconds: int = 120
) -> Iterator[LiveAction]:
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
    action = LiveAction(tmp_path, mode, wait_seconds=wait_seconds)
    try:
        action.start()
        yield action
    finally:
        action.close()


def test_signed_approval_reaches_one_waiting_action(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with live_action(tmp_path, monkeypatch, "replay") as action:
        action.approve()
        result = action.finish()
        assert result == {
            "allowed": True,
            "bridgeExit": 0,
            "completion": [
                {"completed": True, "replayed": False, "httpStatus": 200},
                {"completed": True, "replayed": True, "httpStatus": 200},
            ],
        }
        assert action.marker.read_text() == "executed\n"
        completion = action.store.get_request_resume(action.request_id)
        assert completion is not None
        assert completion["status"] == "sent" and completion["continuation_status"] == "resumed"
        assert completion["continuation_reason"] == "live_hook_completed"
        assert completion["attempt_count"] == 1
        evidence = completion["continuation_evidence"]
        assert isinstance(evidence, list) and len(evidence) == 1


def test_signed_block_never_executes_waiting_action(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with live_action(tmp_path, monkeypatch) as action:
        action.approve(decision="block")
        result = action.finish()
        assert result["allowed"] is False and not action.marker.exists()
        completion = action.store.get_request_resume(action.request_id)
        assert completion is not None and completion["continuation_status"] == "blocked_not_resumed"


def test_changed_action_cannot_consume_signed_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with live_action(tmp_path, monkeypatch, "wrong-command") as action:
        action.approve()
        result = action.finish()
        assert result["allowed"] is False and not action.marker.exists()
        assert result["completion"] == [{"completed": False, "replayed": False, "httpStatus": 409}]
        assert action.store.get_request_resume(action.request_id) is None


def test_invalid_signature_cannot_resolve_or_release_action(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with live_action(tmp_path, monkeypatch) as action:
        approval = remote_approval(action.store, action.request_id, receipt_id="invalid-signature")
        approval["signature"] = "invalid"
        with pytest.raises(ExactCloudReviewError):
            apply_exact_cloud_review(action.store, remote_approval=approval, expected_harness="codex")
        pending = action.store.get_approval_request(action.request_id)
        assert pending is not None and pending["status"] == "pending"
        assert action.store.get_request_resume(action.request_id) is None and not action.marker.exists()
        action.approve(decision="block")
        assert action.finish()["allowed"] is False and not action.marker.exists()


def test_elapsed_original_wait_deadline_refuses_late_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with live_action(tmp_path, monkeypatch, wait_seconds=2) as action:
        deadline = datetime.fromisoformat(action.operation["metadata"]["codex_browser_wait_deadline_at"])
        while datetime.now(timezone.utc) <= deadline:
            time.sleep(0.01)
        action.approve()
        result = action.finish()
        assert result["allowed"] is False and not action.marker.exists()
        assert result["completion"] == [{"completed": False, "replayed": False, "httpStatus": 409}]
        completion = action.store.get_request_resume(action.request_id)
        assert completion is None or completion.get("continuation_status") != "resumed"


def test_cancelled_waiter_cannot_complete_after_signed_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with live_action(tmp_path, monkeypatch) as action:
        assert action.child is not None
        assert _close_owned(action.child) != 0
        assert not process_identity_matches(action.operation["metadata"]["codex_browser_wait_process"])
        action.approve()
        with pytest.raises(_DaemonResponseError) as refused:
            _daemon_json_post(
                state_path=action.store.guard_home / "daemon-state.json",
                path=f"/v1/requests/{action.request_id}/live-decision",
                payload={"hook_input": action.bound_payload.read_text()},
                timeout_seconds=5,
            )
        assert refused.value.status == 409
        assert not action.marker.exists()
        completion = action.store.get_request_resume(action.request_id)
        assert completion is None or completion.get("continuation_status") != "resumed"


def test_identical_next_harness_action_requires_a_new_exact_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with live_action(tmp_path, monkeypatch) as action:
        before = action.store.list_policy_decisions()
        first_id = action.request_id
        first = action.store.get_approval_request(first_id)
        assert first is not None
        action.approve()
        assert action.finish()["allowed"] is True
        assert action.marker.read_text() == "executed\n"
        assert action.store.list_policy_decisions() == before
        assert action.store.get_sync_payload("guard_review_memory_registry") is None
        # Keep the same daemon, store, workspace, exact command and artifact.
        # A second real bridge process must wait for its own fresh decision.
        action.output = (tmp_path / "child.stdout").open("wb")
        action.errors = (tmp_path / "child.stderr").open("wb")
        action.start_child(expected_marker=b"executed\n")
        second = action.store.get_approval_request(action.request_id)
        assert second is not None and second["status"] == "pending"
        assert action.request_id != first_id
        assert second["artifact_id"] == first["artifact_id"]
        assert second["artifact_hash"] != first["artifact_hash"]
        first_envelope = deepcopy(first["action_envelope_json"])
        assert isinstance(first_envelope, dict)
        second_envelope = deepcopy(second["action_envelope_json"])
        assert isinstance(second_envelope, dict)
        first_process = first_envelope["raw_payload_redacted"].pop("guard_codex_browser_wait_process")
        second_process = second_envelope["raw_payload_redacted"].pop("guard_codex_browser_wait_process")
        assert first_process != second_process
        assert second_envelope == first_envelope
        assert action.marker.read_text() == "executed\n"
        blocked = remote_approval(
            action.store,
            action.request_id,
            receipt_id="second-action-block",
            decision="block",
        )
        apply_exact_cloud_review(action.store, remote_approval=blocked, expected_harness="codex")
        assert action.finish()["allowed"] is False
        assert action.marker.read_text() == "executed\n"
        assert action.store.list_policy_decisions() == before
        assert action.store.get_sync_payload("guard_review_memory_registry") is None
