"""Actual runtime POST/signing/retry and Store joins; HTTP/native peers controlled."""

from __future__ import annotations

import json
import urllib.error
import uuid
from typing import Any

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff
from tests import test_native_policy_runtime_reports as native_report_controls
from tests.support.network import stub_authenticated_urlopen

responder = native_report_controls.responder
signed_source = native_report_controls.signed_source


def context_for(connection) -> dict[str, object]:
    c = connection.credentials()
    return {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": c["access_token"],
        "dpop_key_material": GuardDpopKeyMaterial(
            "ES256", c["dpop_private_key_pem"], c["dpop_public_jwk"], c["dpop_public_jwk_thumbprint"]
        ),
    }


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return json.dumps(self.payload).encode()


def session_response(session, connection, *, application, delivery):
    c = connection.credentials()
    return {
        "syncedAt": "2026-09-20T00:00:00Z",
        "items": [
            {
                "sessionId": session["sessionId"],
                "deviceId": session["deviceId"],
                "workspace": c["workspace_id"],
                "harness": session["harness"],
                "oauthGrant": {"grantId": c["grant_id"], "clientId": c["client_id"], "runtimeId": c.get("runtime_id")},
                "policyApplicationObservationReceipt": {
                    "contractVersion": "guard.policy-application-receipt.v1",
                    "reportRevision": application,
                },
                "policyDeliverySupportReceipt": {
                    "contractVersion": "guard.policy-delivery-support-receipt.v1",
                    "reportRevision": delivery,
                },
            }
        ],
    }


def test_actual_post_negotiates_then_reports_and_withdraws_without_cached_positive(signed_source, monkeypatch):
    store, publisher, connection, _ = signed_source
    calls = responder(store, publisher, monkeypatch)
    monkeypatch.setattr(runner, "find_native_policy_snapshot_publisher", lambda _: publisher)
    bodies = []
    returned = []
    context = context_for(connection)

    def http(request, timeout=None):
        assert request.full_url == "https://hol.org/api/guard/runtime/sessions/sync"
        assert request.get_method() == "POST" and request.has_header("Dpop")
        assert timeout == 10
        session = json.loads(request.data)["session"]
        bodies.append(session)
        revisions = str(uuid.uuid4()), str(uuid.uuid4())
        returned.append(revisions)
        return Response(session_response(session, connection, application=revisions[0], delivery=revisions[1]))

    stub_authenticated_urlopen(monkeypatch, http)
    session: dict[str, object] = {
        "sessionId": "synthetic-current-session",
        "harness": "hol-guard",
        "workspace": "local-machine",
    }
    with hold_sync_auth_handoff(store, context, connection):
        first = runner.sync_runtime_session(store, session=session, auth_context=context)
        second = runner.sync_runtime_session(store, session=session, auth_context=context)
        publisher.request_publish()
        third = runner.sync_runtime_session(store, session=session, auth_context=context)
    assert first["runtime_session_id"] == second["runtime_session_id"] == third["runtime_session_id"]
    assert len(calls) == 2
    for field, index in (("policyApplicationObservation", 0), ("policyDeliverySupport", 1)):
        assert bodies[0][field]["previousReportRevision"] is None
        assert bodies[0][field]["observation"] is None
        assert bodies[1][field]["previousReportRevision"] == returned[0][index]
        assert bodies[1][field]["observation"] is not None
        assert bodies[2][field]["previousReportRevision"] == returned[1][index]
        assert bodies[2][field]["observation"] is None
    assert bodies[1]["policyApplicationObservation"]["observation"]["snapshotVersion"] == 4
    assert all(body["workspace"] == "local-machine" for body in bodies)


def test_lost_response_retries_exact_report_and_uses_new_write_revision(signed_source, monkeypatch):
    store, publisher, connection, _ = signed_source
    responder(store, publisher, monkeypatch)
    monkeypatch.setattr(runner, "find_native_policy_snapshot_publisher", lambda _: publisher)
    context = context_for(connection)
    bodies: list[dict[str, Any]] = []
    revisions = []
    timeouts = []
    original_ack = store.get_sync_payload("policy_bundle_ack")

    def http(request, timeout=None):
        session = json.loads(request.data)["session"]
        bodies.append(session)
        timeouts.append(timeout)
        revision = str(uuid.uuid4()), str(uuid.uuid4())
        revisions.append(revision)
        if len(bodies) == 2:
            # Explicit simulated server write followed by transport loss. The
            # retry is the same request; its new receipt is not an acceptance.
            raise urllib.error.URLError(TimeoutError("controlled lost response"))
        return Response(session_response(session, connection, application=revision[0], delivery=revision[1]))

    stub_authenticated_urlopen(monkeypatch, http)
    session: dict[str, object] = {
        "sessionId": "synthetic-retry-session",
        "harness": "codex",
        "workspace": "local-machine",
    }
    with hold_sync_auth_handoff(store, context, connection):
        for _ in range(3):
            runner.sync_runtime_session(store, session=session, auth_context=context)
    assert len(bodies) == 4 and timeouts == [10, 10, 90, 10]
    assert bodies[1] == bodies[2]
    assert bodies[3]["policyApplicationObservation"]["previousReportRevision"] == revisions[2][0]
    assert bodies[3]["policyDeliverySupport"]["previousReportRevision"] == revisions[2][1]
    assert store.get_sync_payload("policy_bundle_ack") == original_ack
