"""HGP-179: result-upload failure retries delivery without a second apply."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_queue import _retry_pending_result
from codex_plugin_scanner.guard.runtime.exact_cloud_review import apply_exact_cloud_review, enable_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_pending_result_retry_keeps_original_application(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("result-upload")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    approval = remote_approval(store, request.request_id, receipt_id="result-upload-receipt")
    resolution = apply_exact_cloud_review(store, remote_approval=approval)
    applied_request = store.get_approval_request(request.request_id)
    assert applied_request is not None
    applied_at = applied_request["resolved_at"]
    payload = {
        "applicationStatus": "applied",
        "applicationUpdatedAt": applied_at,
        "continuationStatus": "manual_retry_required",
        "localRequestId": resolution.request_id,
        "receiptId": resolution.receipt_id,
    }
    posted: list[dict[str, object]] = []

    def _post(_auth: object, job: dict[str, object], result: dict[str, object]) -> None:
        posted.append(result)

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.command_queue._post_result", _post)
    state: dict[str, object] = {
        "pending_result": {
            "job": {"id": "job-1", "createdAt": "2026-09-17T12:00:00+00:00"},
            "payload": payload,
        },
        "state": "result_pending",
    }
    assert _retry_pending_result(store, {"sync_url": "https://hol.org"}, state) is True
    restarted = GuardStore(store.guard_home)
    row = restarted.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "resolved"
    assert row["resolved_at"] == applied_at
    assert posted == [payload]
    with pytest.raises(Exception, match="remote_exact_replayed"):
        apply_exact_cloud_review(restarted, remote_approval=approval)


def _poll_in_new_process() -> None:
    import json
    import os
    import sys

    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.runtime import command_queue

    home = Path(sys.argv[1])
    store = GuardStore(home)
    command_queue._resolve_command_queue_auth_context = lambda _store, force_refresh=False: {
        "sync_url": sys.argv[2],
        "access_token": "synthetic-result-token",
    }
    error_type = None
    try:
        command_queue.poll_command_queue_once(
            store, HarnessContext(home_dir=home.parent, workspace_dir=home.parent, guard_home=home)
        )
    except Exception as error:
        error_type = type(error).__name__
    state = command_queue.command_queue_status(store)
    print(
        json.dumps(
            {"pid": os.getpid(), "errorType": error_type, "state": state["state"], "module": command_queue.__file__}
        )
    )


@pytest.mark.parametrize(
    ("lease_expires", "mutation"),
    [
        (False, "none"),
        (True, "none"),
        (True, "job"),
        (True, "body"),
        (True, "binding"),
        (True, "no-lease"),
        (True, "expired-lease"),
        (True, "subject-during-lease"),
        (True, "subject-on-refresh"),
        (True, "same-subject-refresh"),
        (True, "second-drop"),
        (True, "lease-drop"),
    ],
)
def test_actual_lost_result_response_restarts_and_delivers_original_result(
    tmp_path: Path, lease_expires: bool, mutation: str
) -> None:
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import time
    from datetime import datetime, timedelta, timezone
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from typing import Any

    from codex_plugin_scanner.guard.runtime import command_queue
    from tests.guard_exact_cloud_review_support import exact_review_job

    store = connected_exact_review_store(tmp_path)
    request = review_request("lost-result-response")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    job = exact_review_job(store, remote_approval(store, request.request_id, receipt_id="lost-response-receipt"))
    job.update(
        resultContractVersion="guard-cloud-review-command-result-v2",
        serverResolvedBinding={"localRequestId": request.request_id},
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    errors: list[BaseException] = []
    lease_count = 0
    lease_deadline: datetime | None = None

    def rotate_subject() -> None:
        credentials = store.get_oauth_local_credentials(allow_primary=False)
        assert isinstance(credentials, dict)
        fields = (
            "issuer",
            "client_id",
            "refresh_token",
            "dpop_private_key_pem",
            "dpop_public_jwk",
            "dpop_public_jwk_thumbprint",
            "machine_id",
            "device_id",
            "workspace_id",
            "runtime_id",
            "access_token",
            "access_token_expires_at",
        )
        options: dict[str, Any] = {key: credentials[key] for key in fields if key in credentials}
        store.set_oauth_local_credentials(
            **options, grant_id="reconnected-grant", now=datetime.now(timezone.utc).isoformat()
        )

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            nonlocal lease_count, lease_deadline
            try:
                assert self.headers["Authorization"] == "Bearer synthetic-result-token"
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert self.path.startswith("/api/guard/review/v2/commands/")
                posts.append((self.path.rsplit("/", 1)[-1], payload))
                response: dict[str, Any] = {"ok": True}
                if self.path.endswith("/lease"):
                    lease_count += 1
                    lease_deadline = datetime.now(timezone.utc) + timedelta(
                        seconds=0.1 if lease_expires and lease_count == 1 else 60
                    )
                    response = {
                        "protocolVersion": 2,
                        "item": {
                            **job,
                            "leaseId": f"lease-{lease_count}",
                            "leaseExpiresAt": lease_deadline.isoformat(),
                        },
                    }
                    if lease_count == 2 and mutation == "lease-drop":
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    if lease_count > 1:
                        item = response["item"]
                        if mutation == "job":
                            item["id"] = "foreign-job"
                        elif mutation == "body":
                            item["payload"] = {**item["payload"], "harness": "foreign-harness"}
                        elif mutation == "binding":
                            item["serverResolvedBinding"] = {"localRequestId": "foreign-request"}
                        elif mutation == "no-lease":
                            response["item"] = None
                        elif mutation == "expired-lease":
                            item["leaseExpiresAt"] = "2000-01-01T00:00:00Z"
                        elif mutation == "subject-during-lease":
                            rotate_subject()
                elif self.path.endswith("/result") and sum(path == "result" for path, _ in posts) <= (
                    2 if mutation == "second-drop" else 1
                ):
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                status = 200
                if (
                    self.path.endswith("/result")
                    and sum(path == "result" for path, _ in posts) == 2
                    and mutation in {"subject-on-refresh", "same-subject-refresh"}
                ):
                    status = 401
                    if mutation == "subject-on-refresh":
                        rotate_subject()
                content = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except BaseException as error:
                errors.append(error)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib override
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    checkout = Path(__file__).resolve().parents[1]

    def poll() -> dict[str, Any]:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from tests.test_guard_exact_cloud_review_result_upload_retry import _poll_in_new_process; "
                "_poll_in_new_process()",
                str(store.guard_home),
                f"http://127.0.0.1:{server.server_port}",
            ],
            cwd=checkout,
            env={**os.environ, "PYTHONPATH": os.pathsep.join((str(checkout / "src"), str(checkout)))},
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        decoded = json.loads(result.stdout)
        assert decoded["pid"] != os.getpid()
        assert Path(decoded["module"]).resolve() == Path(command_queue.__file__).resolve()
        return decoded

    try:
        first = poll()
        assert first["errorType"] == "RemoteDisconnected"
        assert first["state"] == "result_pending"
        before = GuardStore(store.guard_home).get_approval_request(request.request_id)
        assert before is not None and before["status"] == "resolved"
        originals = [payload for path, payload in posts if path == "result"]
        assert len(originals) == 1
        original = originals[0]["result"]
        assert original["applicationStatus"] == "applied"
        assert original["continuationStatus"] == "manual_retry_required"
        if lease_expires:
            assert lease_deadline is not None
            remaining = (lease_deadline - datetime.now(timezone.utc)).total_seconds()
            if remaining > 0:
                time.sleep(min(remaining + 0.02, 1))
        second = poll()
        assert second["pid"] != first["pid"]
        if mutation in {"second-drop", "lease-drop"}:
            assert second["errorType"] == "RemoteDisconnected" and second["state"] == "result_pending"
            third = poll()
            assert third["pid"] not in {first["pid"], second["pid"]}
            second = third
        assert second["errorType"] is None
        received = [payload for path, payload in posts if path == "result"]
        if mutation in {"none", "same-subject-refresh", "second-drop", "lease-drop"}:
            assert second["state"] == "idle"
            assert len(received) == (3 if mutation in {"same-subject-refresh", "second-drop"} else 2)
            assert all(payload["result"] == original for payload in received[1:])
        else:
            assert second["state"] == "result_pending"
            assert len(received) == (2 if mutation == "subject-on-refresh" else 1)
            state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
            assert isinstance(state, dict)
            pending = state["pending_result"]
            assert isinstance(pending, dict)
            retained = pending["payload"]
            assert isinstance(retained, dict) and retained["result"] == original
        assert lease_count == (3 if mutation == "lease-drop" else 2 if lease_expires else 1)
        assert GuardStore(store.guard_home).get_approval_request(request.request_id) == before
        assert len(store.list_events(event_name="cloud_command.accepted")) == 1
        with store._connect() as connection:
            assert (
                connection.execute(
                    "select count(*) from guard_exact_cloud_review_receipts where receipt_id = ?",
                    ("lost-response-receipt",),
                ).fetchone()[0]
                == 1
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []


@pytest.mark.parametrize("missing_evidence", [False, True])
def test_native_result_retry_uses_recorded_completion_without_consuming_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_evidence: bool
) -> None:
    import json
    import threading
    import time
    from datetime import datetime, timedelta, timezone

    from codex_plugin_scanner.guard.native_live_approval_state import native_proof_ready
    from codex_plugin_scanner.guard.runtime.command_capability import mark_command_job_consumed
    from codex_plugin_scanner.guard.runtime.command_queue_protocol import result_payload
    from codex_plugin_scanner.guard.runtime.command_queue_result_retry import (
        exact_result_delivery_binding,
        rebind_exact_result,
    )
    from codex_plugin_scanner.guard.runtime.exact_cloud_review import authorize_exact_cloud_review_job
    from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_transport_job
    from codex_plugin_scanner.guard.runtime.native_cloud_review_executor import execute_native_cloud_review
    from tests.test_native_live_approval_completion import NativeWait

    wait = NativeWait(tmp_path, monkeypatch)
    job = exact_transport_job({**wait.job(), "leaseId": "initial-lease", "leaseExpiresAt": "2000-01-01T00:00:00Z"})
    authorized = authorize_exact_cloud_review_job(wait.store, job)
    mark_command_job_consumed(wait.store, authorized)
    executions: list[dict[str, object]] = []

    def execute() -> None:
        executions.append(execute_native_cloud_review(wait.store, job, now=datetime.now(timezone.utc).isoformat()))

    thread = threading.Thread(target=execute)
    thread.start()
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            row = wait.store.get_approval_request(wait.request_id)
            if row is not None and native_proof_ready(wait.store, row):
                break
            time.sleep(0.01)
        else:
            pytest.fail("The production executor did not stage the original proof")
        assert wait.complete()["completed"] is True
    finally:
        thread.join(timeout=6)
    assert not thread.is_alive() and len(executions) == 1
    payload = result_payload(job, executions[0])
    result = payload["result"]
    assert (
        isinstance(result, dict)
        and result["applicationStatus"] == "applied"
        and result["continuationStatus"] == "resumed"
    )
    pending = {"job": job, "payload": payload, "delivery_binding": exact_result_delivery_binding(wait.store)}
    before = wait.store.get_approval_request(wait.request_id)
    calls = list(wait.calls)
    if missing_evidence:
        with wait.store._connect() as connection:
            connection.execute(
                "update guard_operations set metadata_json = "
                "json_remove(metadata_json, '$.native_approval_consumed_receipt') where operation_id = ?",
                ("codex-live-" + wait.request_id,),
            )
    renewed = {
        **job,
        "leaseId": "fresh-lease",
        "leaseExpiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
    }
    rebound = rebind_exact_result(wait.store, pending, renewed)
    if missing_evidence:
        assert rebound is None
    else:
        assert rebound is not None and rebound["result"] == result and rebound["leaseId"] == "fresh-lease"
        assert json.dumps(rebound["result"], sort_keys=True) == json.dumps(payload["result"], sort_keys=True)
    assert wait.store.get_approval_request(wait.request_id) == before
    assert wait.calls == calls and len(calls) == 2
