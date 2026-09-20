"""Actual durable report negotiation, response joins, and concurrent-write recovery."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.native_policy_runtime_reports import NativeRuntimeReports
from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.runtime.policy_report_revisions import (
    RuntimeReportWrite,
    finish_runtime_reports,
    prepare_runtime_reports,
)
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-09-20T00:00:00+00:00"
WORKSPACE = "00000000-0000-4000-8000-000000000001"
APPLICATION = "policyApplicationObservation"
DELIVERY = "policyDeliverySupport"
SESSION: dict[str, object] = {
    "sessionId": "synthetic-session",
    "deviceId": "synthetic-machine",
    "workspace": WORKSPACE,
    "harness": "synthetic-harness",
}


def _revision(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012d}"


def _store(tmp_path: Path, runtime: str | None = "synthetic-runtime") -> tuple[GuardStore, dict[str, Any]]:
    key = generate_dpop_key_pair()
    inputs: dict[str, Any] = {
        "issuer": "https://hol.org",
        "client_id": "synthetic-client",
        "grant_id": "synthetic-grant",
        "device_id": "synthetic-device",
        "machine_id": SESSION["deviceId"],
        "workspace_id": WORKSPACE,
        "runtime_id": runtime,
        "refresh_token": "synthetic-secret-refresh-canary",
        "access_token": "synthetic-secret-access-canary",
        "access_token_expires_at": "2099-01-01T00:00:00+00:00",
        "dpop_private_key_pem": key.private_key_pem,
        "dpop_public_jwk": key.public_jwk,
        "dpop_public_jwk_thumbprint": key.public_jwk_thumbprint,
        "now": NOW,
    }
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    store.set_oauth_local_credentials(**inputs)
    return store, inputs


def _connection(store: GuardStore) -> OAuthConnectionSnapshot:
    result = store.capture_oauth_connection()
    assert result is not None
    return result


def _observations() -> NativeRuntimeReports:
    common: dict[str, object] = {
        "workspaceId": WORKSPACE,
        "deviceId": SESSION["deviceId"],
        "runtimeIdentity": "a" * 64,
        "residentGeneration": "7",
        "servingInstanceDigest": "b" * 64,
        "sourceObservedAt": "2026-09-20T00:00:00.000Z",
        "expiresAt": "2026-09-20T00:01:00.000Z",
    }
    return NativeRuntimeReports(
        {
            **common,
            "state": "current",
            "mode": "enforce",
            "bundleHash": "sha256:" + "c" * 64,
            "bundleVersion": 3,
            "snapshotVersion": 4,
            "policyGeneration": "5",
            "policyDigest": "d" * 64,
            "sourceInputDigest": "e" * 64,
        },
        {**common, "state": "available", "profileId": "guard.native-artifact-restrictive.v1"},
    )


def _prepare(
    store: GuardStore,
    connection: OAuthConnectionSnapshot,
    observations: NativeRuntimeReports | None = None,
) -> tuple[dict[str, Any], RuntimeReportWrite]:
    fields, write = prepare_runtime_reports(store, connection, SESSION, observations or _observations(), now=NOW)
    assert write is not None
    return fields, write


def _response(write: RuntimeReportWrite, application: int = 1, delivery: int = 2) -> dict[str, Any]:
    subject = write.subject
    return {
        "items": [
            {
                **{key: subject[key] for key in ("sessionId", "deviceId", "workspace", "harness")},
                "oauthGrant": {key: subject[key] for key in ("grantId", "clientId", "runtimeId")},
                APPLICATION: None,
                DELIVERY: None,
                APPLICATION + "Receipt": {
                    "contractVersion": "guard.policy-application-receipt.v1",
                    "reportRevision": _revision(application),
                },
                DELIVERY + "Receipt": {
                    "contractVersion": "guard.policy-delivery-support-receipt.v1",
                    "reportRevision": _revision(delivery),
                },
            }
        ]
    }


def _negotiate(store: GuardStore, connection: OAuthConnectionSnapshot) -> RuntimeReportWrite:
    fields, write = _prepare(store, connection)
    assert all(value["observation"] is None for value in fields.values())
    finish_runtime_reports(store, connection, write, _response(write), now=NOW)
    return write


def _assert_withdrawals(fields: dict[str, Any]) -> None:
    assert set(fields) == {APPLICATION, DELIVERY}
    for value in fields.values():
        assert set(value) == {"contractVersion", "previousReportRevision", "observation"}
        assert value["observation"] is None


def test_initial_withdrawal_negotiates_each_revision_without_claiming_acceptance(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    fields, write = _prepare(store, connection)
    _assert_withdrawals(fields)
    assert all(value["previousReportRevision"] is None for value in fields.values())
    # Receipts arrive even though both returned observations are literal null.
    finish_runtime_reports(store, connection, write, _response(write), now=NOW)
    reopened = GuardStore(store.guard_home, allow_system_keyring=False)
    fields, _ = _prepare(reopened, _connection(reopened))
    assert fields[APPLICATION]["previousReportRevision"] == _revision(1)
    assert fields[DELIVERY]["previousReportRevision"] == _revision(2)
    assert fields[APPLICATION]["observation"] == _observations().application
    assert fields[DELIVERY]["observation"] == _observations().delivery
    state = store.get_sync_payload(write.state_key)
    assert state is not None
    assert set(state) == {"schema", "subject", "revisions", "pending"}


@pytest.mark.parametrize("kind", [APPLICATION, DELIVERY])
@pytest.mark.parametrize(
    "invalid", ["missing", "wrong-contract", "bad-revision", "extra-field", "null", "bad-version", "bad-variant", "nil"]
)
def test_receipts_negotiate_independently(tmp_path: Path, kind: str, invalid: str) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _, write = _prepare(store, connection)
    response = _response(write)
    item = response["items"][0]
    receipt = item[kind + "Receipt"]
    if invalid == "missing":
        del item[kind + "Receipt"]
    elif invalid == "null":
        item[kind + "Receipt"] = None
    elif invalid == "wrong-contract":
        receipt["contractVersion"] = "foreign-contract"
    elif invalid == "bad-revision":
        receipt["reportRevision"] = "not-a-revision"
    elif invalid == "bad-version":
        receipt["reportRevision"] = "00000000-0000-0000-8000-000000000001"
    elif invalid == "bad-variant":
        receipt["reportRevision"] = "00000000-0000-4000-4000-000000000001"
    elif invalid == "nil":
        receipt["reportRevision"] = "00000000-0000-0000-0000-000000000000"
    else:
        receipt["accepted"] = True
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = _prepare(store, connection)
    assert fields[kind]["previousReportRevision"] is None
    assert fields[kind]["observation"] is None
    other = DELIVERY if kind == APPLICATION else APPLICATION
    assert fields[other]["previousReportRevision"] == _revision(2 if other == DELIVERY else 1)
    assert fields[other]["observation"] is not None


@pytest.mark.parametrize("shape", ["missing", "wrong-type", "empty", "foreign", "duplicate", "non-object"])
def test_missing_wrong_duplicate_or_foreign_response_withdraws(tmp_path: Path, shape: str) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    _, write = _prepare(store, connection)
    response: Any = _response(write, 3, 4)
    if shape == "missing":
        response = {}
    elif shape == "wrong-type":
        response["items"] = {}
    elif shape == "empty":
        response["items"] = []
    elif shape == "foreign":
        response["items"][0]["sessionId"] = "foreign-session"
    elif shape == "duplicate":
        response["items"].append(deepcopy(response["items"][0]))
    else:
        response = None
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = _prepare(store, connection)
    _assert_withdrawals(fields)
    assert all(value["previousReportRevision"] is None for value in fields.values())


@pytest.mark.parametrize("field", ["sessionId", "deviceId", "workspace", "harness", "grantId", "clientId", "runtimeId"])
def test_response_requires_every_exact_subject_field(tmp_path: Path, field: str) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _, write = _prepare(store, connection)
    response = _response(write)
    item = response["items"][0]
    target = item["oauthGrant"] if field in {"grantId", "clientId", "runtimeId"} else item
    target[field] = "foreign-subject"
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = _prepare(store, connection)
    _assert_withdrawals(fields)


@pytest.mark.parametrize("returned_runtime", ["literal-null", "omitted", "harness"])
def test_optional_local_runtime_requires_literal_null_in_returned_grant(tmp_path: Path, returned_runtime: str) -> None:
    store, _ = _store(tmp_path, runtime=None)
    connection = _connection(store)
    assert "runtime_id" not in connection.credentials()  # Actual Store representation.
    _, write = _prepare(store, connection)
    assert write.subject["runtimeId"] is None
    response = _response(write)
    grant = response["items"][0]["oauthGrant"]
    if returned_runtime == "omitted":
        del grant["runtimeId"]
    elif returned_runtime == "harness":
        grant["runtimeId"] = SESSION["harness"]
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = _prepare(store, connection)
    if returned_runtime == "literal-null":
        assert all(value["observation"] is not None for value in fields.values())
    else:
        _assert_withdrawals(fields)


def test_unique_matching_item_in_batch_does_not_adopt_foreign_receipts(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _, write = _prepare(store, connection)
    response = _response(write)
    foreign = _response(write, 8, 9)["items"][0]
    foreign["sessionId"] = "another-session"
    response["items"].insert(0, foreign)
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = _prepare(store, connection)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(1)
    assert fields[DELIVERY]["previousReportRevision"] == _revision(2)


@pytest.mark.parametrize("finish_lost_response", [False, True])
def test_lost_response_and_retry_withdraw_until_new_receipts(tmp_path: Path, finish_lost_response: bool) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    fields, lost = _prepare(store, connection)
    assert fields[APPLICATION]["observation"] is not None
    if finish_lost_response:
        finish_runtime_reports(store, connection, lost, None, now=NOW)
    fields, retry = _prepare(store, connection)
    _assert_withdrawals(fields)
    # A retry receipt acknowledges the new withdrawal even if prior delivery was lost.
    finish_runtime_reports(store, connection, retry, _response(retry, 3, 4), now=NOW)
    finish_runtime_reports(store, connection, lost, _response(lost, 8, 9), now=NOW)
    fields, _ = _prepare(store, connection)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(3)
    assert fields[DELIVERY]["previousReportRevision"] == _revision(4)
    assert fields[APPLICATION]["observation"] is not None


@pytest.mark.parametrize("older_response_first", [False, True])
def test_two_out_of_order_writes_cannot_overwrite_latest_local_attempt(
    tmp_path: Path, older_response_first: bool
) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    _, old = _prepare(store, connection)
    fields, new = _prepare(store, connection)
    _assert_withdrawals(fields)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    writes = [(old, 3, 4), (new, 5, 6)]
    if not older_response_first:
        writes.reverse()
    for write, application, delivery in writes:
        finish_runtime_reports(peer, _connection(peer), write, _response(write, application, delivery), now=NOW)
    fields, latest = _prepare(store, connection)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(5)
    assert fields[DELIVERY]["previousReportRevision"] == _revision(6)
    # The server may have processed the older write last. Its next refusal still rotates
    # the receipt; adopting that receipt does not claim this positive was accepted.
    finish_runtime_reports(store, connection, latest, _response(latest, 7, 8), now=NOW)
    fields, _ = _prepare(store, connection)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(7)


@pytest.mark.parametrize("mutation", ["reconnect", "named-source", "different-store"])
def test_connection_replacement_cannot_adopt_an_old_write(tmp_path: Path, mutation: str) -> None:
    store, inputs = _store(tmp_path)
    old_connection = _connection(store)
    _negotiate(store, old_connection)
    _, old = _prepare(store, old_connection)
    if mutation == "reconnect":
        store.clear_oauth_local_credentials()
        store.set_oauth_local_credentials(**inputs)
        current_store = store
    else:
        home = store.guard_home if mutation == "named-source" else tmp_path / "other"
        current_store = GuardStore(home, allow_system_keyring=False, source="secondary")
        current_store.set_oauth_local_credentials(**inputs)
    current_connection = _connection(current_store)
    fields, current = _prepare(current_store, current_connection)
    _assert_withdrawals(fields)
    assert current.state_key != old.state_key
    old_state = store.get_sync_payload(old.state_key)
    finish_runtime_reports(current_store, current_connection, old, _response(old, 8, 9), now=NOW)
    assert store.get_sync_payload(old.state_key) == old_state
    state = current_store.get_sync_payload(current.state_key)
    assert isinstance(state, dict) and state["pending"] == current.attempt
    finish_runtime_reports(current_store, current_connection, current, _response(current, 3, 4), now=NOW)
    fields, _ = _prepare(current_store, current_connection)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(3)


def test_stale_captured_connection_fails_before_durable_mutation(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    stale = _connection(store)
    _, write = _prepare(store, stale)
    before = store.get_sync_payload(write.state_key)
    store.set_oauth_local_credentials(**inputs)
    with pytest.raises(RuntimeError, match="connection changed"):
        finish_runtime_reports(store, stale, write, _response(write), now=NOW)
    with pytest.raises(RuntimeError, match="connection changed"):
        _prepare(store, stale)
    assert store.get_sync_payload(write.state_key) == before


@pytest.mark.parametrize("kind", ["application", "delivery"])
@pytest.mark.parametrize("field", ["workspaceId", "deviceId"])
def test_foreign_observation_withdraws_only_its_report(tmp_path: Path, kind: str, field: str) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    reports = _observations()
    target = reports.application if kind == "application" else reports.delivery
    assert target is not None
    target[field] = "foreign-observation"
    fields, _ = _prepare(store, connection, reports)
    own, other = (APPLICATION, DELIVERY) if kind == "application" else (DELIVERY, APPLICATION)
    assert fields[own]["observation"] is None
    assert fields[other]["observation"] is not None


def test_report_state_and_write_representation_never_persist_credentials_or_observations(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    _, write = _prepare(store, connection)
    with store._connect() as database:
        rows = database.execute(
            "select state_key,payload_json from sync_state where state_key like 'runtime_policy_report_revisions:%'"
        ).fetchall()
    assert len(rows) == 1
    persisted = json.dumps([list(row) for row in rows])
    for secret in (inputs["refresh_token"], inputs["access_token"], inputs["dpop_private_key_pem"]):
        assert secret not in persisted
        assert secret not in repr(write)
    assert "PRIVATE KEY" not in persisted
    assert "policyDigest" not in persisted
    assert "sourceObservedAt" not in persisted
    assert str(store.path) not in persisted
    assert str(SESSION["sessionId"]) not in repr(write)


@pytest.mark.parametrize("field", ["deviceId", "sessionId", "harness"])
def test_invalid_local_session_withdraws_without_recording_an_attempt(tmp_path: Path, field: str) -> None:
    store, _ = _store(tmp_path)
    session = {**SESSION, field: ""}
    fields, write = prepare_runtime_reports(store, _connection(store), session, _observations(), now=NOW)
    _assert_withdrawals(fields)
    assert write is None
    with store._connect() as database:
        assert (
            database.execute(
                "select count(*) from sync_state where state_key like 'runtime_policy_report_revisions:%'"
            ).fetchone()[0]
            == 0
        )


def test_headless_local_workspace_label_does_not_replace_authenticated_subject(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    session = {**SESSION, "workspace": "local-machine"}
    fields, write = prepare_runtime_reports(store, connection, session, _observations(), now=NOW)
    assert write is not None
    _assert_withdrawals(fields)
    assert write.subject["workspace"] == WORKSPACE
    response = _response(write)
    finish_runtime_reports(store, connection, write, response, now=NOW)
    fields, _ = prepare_runtime_reports(store, connection, session, _observations(), now=NOW)
    assert all(isinstance(value, dict) and value["observation"] is not None for value in fields.values())
    assert session["workspace"] == "local-machine"


@pytest.mark.parametrize("missing", ["application", "delivery", "both"])
def test_current_source_withdrawal_never_reuses_a_previous_positive(tmp_path: Path, missing: str) -> None:
    store, _ = _store(tmp_path)
    connection = _connection(store)
    _negotiate(store, connection)
    native = _observations()
    observations = NativeRuntimeReports(
        None if missing in {"application", "both"} else native.application,
        None if missing in {"delivery", "both"} else native.delivery,
    )
    fields, _ = _prepare(store, connection, observations)
    assert fields[APPLICATION]["previousReportRevision"] == _revision(1)
    assert fields[DELIVERY]["previousReportRevision"] == _revision(2)
    assert fields[APPLICATION]["observation"] == observations.application
    assert fields[DELIVERY]["observation"] == observations.delivery


@pytest.mark.parametrize(
    "workspace",
    [
        "00000000-0000-0000-8000-000000000001",
        "00000000-0000-4000-4000-000000000001",
        "00000000-0000-0000-0000-000000000000",
    ],
    ids=["invalid-version", "invalid-variant", "nil"],
)
def test_invalid_stored_workspace_uuid_withdraws_before_recording_attempt(tmp_path: Path, workspace: str) -> None:
    store, inputs = _store(tmp_path)
    updated_inputs: dict[str, Any] = {**inputs, "workspace_id": workspace}
    store.set_oauth_local_credentials(**updated_inputs)
    fields, write = prepare_runtime_reports(store, _connection(store), SESSION, _observations(), now=NOW)
    _assert_withdrawals(fields)
    assert write is None
    with store._connect() as database:
        assert (
            database.execute(
                "select count(*) from sync_state where state_key like 'runtime_policy_report_revisions:%'"
            ).fetchone()[0]
            == 0
        )
