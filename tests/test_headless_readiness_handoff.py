"""Real Store/resolver/background flow; controlled HTTP and absent native publisher.

The signed unavailable observation is intentional: this suite verifies delivery
of exact current authentication to the handshake, not native readiness itself.
"""

from __future__ import annotations

import io
import json
import time
from urllib.parse import urlsplit

import pytest

from codex_plugin_scanner.guard import policy_consumer_readiness_sync as readiness
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import selected_sync_auth_handoff
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_oauth_connection_authority import _inputs
from tests.test_policy_consumer_readiness_observation import challenge_for, verify_signed


@pytest.fixture
def flow(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    inputs = _inputs()
    inputs.update(
        workspace_id="22222222-2222-4222-8222-222222222222",
        grant_id="44444444-4444-4444-8444-444444444444",
        runtime_id="hol-guard",
    )
    store.set_oauth_local_credentials(**inputs)
    expected = store.capture_oauth_connection()
    assert expected is not None
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    events, resolutions, contexts, boundary, sent = [], [], [], [], []
    resolve = runner._resolve_guard_sync_auth_context
    actual_readiness = readiness.sync_consumer_readiness
    state: dict[str, object] = {"after_resolve": lambda context: None, "before_readiness": lambda: None}

    def resolved(selected_store, **kwargs):
        context = resolve(selected_store, **kwargs)
        resolutions.append(selected_store)
        contexts.append(context)
        after_resolve = state["after_resolve"]
        assert callable(after_resolve)
        after_resolve(context)
        return context

    monkeypatch.setattr(server, "_resolve_guard_sync_auth_context", resolved)
    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolved)
    monkeypatch.setattr(readiness, "find_native_policy_snapshot_publisher", lambda selected_store: None)

    def runtime_http(*, request, validate_request, **kwargs):
        validate_request()
        assert request.get_method() == "POST" and request.get_header("Dpop")
        assert urlsplit(request.full_url).path == "/api/guard/runtime/sessions/sync"
        body = json.loads(request.data)
        state["session"] = body["session"]
        events.append("runtime")
        return {"syncedAt": runner._now(), "items": [body["session"]]}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", runtime_http)

    def consumer_http(request, timeout):
        assert timeout == runner._RUNTIME_SYNC_TIMEOUT_SECONDS
        assert request.get_method() == "POST" and request.get_header("Dpop")
        body = json.loads(request.data)
        path = urlsplit(request.full_url).path
        sent.append(path)
        if path == readiness._CHALLENGE_PATH:
            events.append("challenge")
            challenge = challenge_for(expected, body["localContext"])
            subject = challenge["subject"]
            assert isinstance(subject, dict)
            subject["runtimeSessionId"] = body["runtimeSessionId"]
            state["challenge"] = challenge
            return io.BytesIO(json.dumps(challenge).encode())
        assert path == readiness._OBSERVATION_PATH
        events.append("observation")
        verified = verify_signed(body, expected)
        assert verified["readiness"] == "unavailable"
        assert verified["reason"] == "snapshot_unavailable"
        challenge = state["challenge"]
        assert isinstance(challenge, dict)
        response = {
            "contractVersion": "guard.consumer-readiness-ack.v2",
            **{key: challenge[key] for key in ("challengeId", "subjectVersion", "challengeSequence")},
            "readiness": "unavailable",
            "receivedAtMs": int(time.time() * 1000),
            "validUntilMs": None,
        }
        return io.BytesIO(json.dumps(response).encode())

    monkeypatch.setattr(runner, "managed_urlopen", consumer_http)

    def observe_readiness(selected_store, *, connection, auth_context, runtime_summary):
        before_readiness = state["before_readiness"]
        assert callable(before_readiness)
        before_readiness()
        events.append("readiness")
        boundary.append((selected_store, connection, auth_context, runtime_summary))
        return actual_readiness(
            selected_store, connection=connection, auth_context=auth_context, runtime_summary=runtime_summary
        )

    monkeypatch.setattr(runner, "sync_consumer_readiness", observe_readiness)

    def receipts(selected_store, *, auth_context, **kwargs):
        events.append("receipts")
        state["receipt_connection"] = selected_sync_auth_handoff(selected_store, auth_context)
        return {"synced_at": runner._now(), "receipts_stored": 0}

    monkeypatch.setattr(runner, "sync_receipts", receipts)

    def supply(selected_store, context):
        events.append("supply")
        state["supply_connection"] = selected_sync_auth_handoff(selected_store, context)
        state["supply_context"] = context
        if state.get("supply_error"):
            raise RuntimeError("controlled supply failure")
        return {"status": "synced"}

    monkeypatch.setattr(server, "_sync_supply_chain_cloud_state_with_optional_auth_context", supply)
    state.update(
        store=store,
        inputs=inputs,
        expected=expected,
        events=events,
        resolutions=resolutions,
        contexts=contexts,
        boundary=boundary,
        sent=sent,
    )
    return state


def test_background_pass_hands_exact_resolved_connection_to_actual_readiness(flow):
    result = server._run_headless_cloud_sync(store=flow["store"])
    assert result["status"] == "synced"
    assert result["runtime_sessions_visible"] == 1
    assert len(flow["boundary"]) == 1
    store, connection, context, runtime = flow["boundary"][0]
    assert connection == flow["expected"], "background readiness must receive the exact resolved connection"
    assert store is flow["store"] and context is flow["contexts"][0]
    assert len(flow["resolutions"]) == 1
    assert connection.credentials() == flow["expected"].credentials()
    assert context["access_token"] == connection.credentials()["access_token"]
    assert context["dpop_key_material"].public_jwk_thumbprint == connection.credentials()["dpop_public_jwk_thumbprint"]
    assert runtime["consumer_readiness"]["readiness"] == "unavailable"
    assert runtime["consumer_readiness"]["applied_policy"] is False
    assert flow["events"] == ["runtime", "readiness", "challenge", "observation", "receipts", "supply"]
    assert flow["receipt_connection"] == connection and flow["supply_connection"] == connection
    assert flow["supply_context"] is context
    assert selected_sync_auth_handoff(store, context) is None
    assert store.get_sync_payload("policy_bundle") is None and store.get_sync_payload("policy_bundle_ack") is None


@pytest.mark.parametrize("change", ["same-values", "workspace", "runtime", "key", "disconnect"])
def test_replacement_after_resolution_is_not_substituted_into_background_pass(flow, change):
    def replace_connection(context):
        inputs = dict(flow["inputs"])
        if change == "disconnect":
            flow["store"].clear_oauth_local_credentials()
        else:
            if change == "workspace":
                inputs["workspace_id"] = "77777777-7777-4777-8777-777777777777"
            elif change == "runtime":
                inputs["runtime_id"] = "replacement-runtime"
            elif change == "key":
                new = _inputs()
                for key in ("dpop_private_key_pem", "dpop_public_jwk", "dpop_public_jwk_thumbprint"):
                    inputs[key] = new[key]
            flow["store"].set_oauth_local_credentials(**inputs)

    flow["after_resolve"] = replace_connection
    result = server._run_headless_cloud_sync(store=flow["store"])
    assert result["status"] == "pending"
    assert len(flow["resolutions"]) == 1
    assert flow["events"] == [] and flow["boundary"] == [] and flow["sent"] == []
    assert selected_sync_auth_handoff(flow["store"], flow["contexts"][0]) is None


def test_mutated_context_after_handoff_cannot_supply_readiness_authority(flow, monkeypatch):
    proof = runner.sync_local_guard_cloud_proof

    def mutate_before_proof(store, *, auth_context, **kwargs):
        assert selected_sync_auth_handoff(store, auth_context) == flow["expected"]
        auth_context["access_token"] = "changed-after-handoff"
        assert selected_sync_auth_handoff(store, auth_context) is None
        return proof(store, auth_context=auth_context, **kwargs)

    monkeypatch.setattr(server, "sync_local_guard_cloud_proof", mutate_before_proof)
    result = server._run_headless_cloud_sync(store=flow["store"])
    assert result["status"] == "synced"
    assert flow["boundary"][0][1] is None and flow["sent"] == []
    assert flow["boundary"][0][3]["consumer_readiness"] == {"readiness": "unavailable", "applied_policy": False}
    # Runtime registration retains its existing fresh-resolution fallback, but
    # it cannot substitute that connection into the caller's readiness scope.
    assert len(flow["resolutions"]) == 2
    assert flow["supply_connection"] is None
    assert selected_sync_auth_handoff(flow["store"], flow["contexts"][0]) is None


def test_other_store_object_cannot_consume_headless_handoff(flow, monkeypatch):
    other = GuardStore(flow["store"].guard_home, allow_system_keyring=False)
    proof = runner.sync_local_guard_cloud_proof

    def use_other_store(store, *, auth_context, **kwargs):
        assert selected_sync_auth_handoff(store, auth_context) == flow["expected"]
        assert selected_sync_auth_handoff(other, auth_context) is None
        return proof(other, auth_context=auth_context, **kwargs)

    monkeypatch.setattr(server, "sync_local_guard_cloud_proof", use_other_store)
    result = server._run_headless_cloud_sync(store=flow["store"])
    assert result["status"] == "synced"
    assert flow["boundary"][0][0] is other and flow["boundary"][0][1] is None
    assert flow["sent"] == []
    assert selected_sync_auth_handoff(flow["store"], flow["contexts"][0]) is None


def test_exception_and_next_pass_do_not_reuse_expired_scope(flow):
    flow["supply_error"] = True
    failed = server._run_headless_cloud_sync(store=flow["store"])
    first = flow["contexts"][0]
    assert failed["status"] == "pending"
    assert flow["supply_connection"] == flow["expected"]
    assert selected_sync_auth_handoff(flow["store"], first) is None
    flow["supply_error"] = False
    result = server._run_headless_cloud_sync(store=flow["store"])
    second = flow["contexts"][1]
    assert result["status"] == "synced"
    assert len(flow["resolutions"]) == 2 and first is not second
    assert len(flow["sent"]) == 4 and len(flow["boundary"]) == 2
    assert flow["supply_context"] is second
    assert selected_sync_auth_handoff(flow["store"], second) is None


def test_explicit_none_readiness_refusal_remains_before_capture_or_http(flow):
    context = runner._resolve_guard_sync_auth_context(flow["store"])
    result = readiness.sync_consumer_readiness(
        flow["store"],
        connection=None,
        auth_context=context,
        runtime_summary={"runtime_session_id": "existing-session", "runtime_session_synced_at": runner._now()},
    )
    assert result == {"readiness": "unavailable", "applied_policy": False}
    assert flow["events"] == [] and flow["sent"] == []


def test_non_oauth_resolver_override_cannot_mint_a_handoff(flow, monkeypatch):
    monkeypatch.setattr(
        runner,
        "_test_sync_auth_context_override",
        {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "override",
            "dpop_key_material": None,
        },
    )
    seen = []

    def proof(store, *, auth_context, **kwargs):
        seen.append(selected_sync_auth_handoff(store, auth_context))
        return {"synced_at": runner._now(), "receipts_stored": 0}

    monkeypatch.setattr(server, "sync_local_guard_cloud_proof", proof)
    result = server._run_headless_cloud_sync(store=flow["store"])
    assert result["status"] == "synced" and seen == [None]
    assert flow["supply_connection"] is None and flow["sent"] == []
    assert selected_sync_auth_handoff(flow["store"], flow["contexts"][0]) is None
