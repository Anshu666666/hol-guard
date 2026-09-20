"""Per-write report revisions, bound to the actual authenticated session POST.

A revision receipt acknowledges a write, including withdrawal. It never proves
that the server accepted a positive observation or that a policy is current.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from typing import cast

from ..native_policy_runtime_reports import NativeRuntimeReports
from ..oauth_connection_authority import OAuthConnectionSnapshot, connection_identity
from ..store import GuardStore

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_KINDS = {
    "application": (
        "policyApplicationObservation",
        "guard.policy-application-observation.v1",
        "guard.policy-application-receipt.v1",
    ),
    "delivery": (
        "policyDeliverySupport",
        "guard.policy-delivery-support.v1",
        "guard.policy-delivery-support-receipt.v1",
    ),
}


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeReportWrite:
    state_key: str
    attempt: str
    subject: dict[str, object] = field(repr=False)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _revision(value: object) -> str | None:
    return value if isinstance(value, str) and _UUID.fullmatch(value) is not None else None


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= maximum and all(0x21 <= ord(c) <= 0x7E for c in value)


def _subject(connection: OAuthConnectionSnapshot, session: dict[str, object]) -> dict[str, object] | None:
    credentials = connection.credentials()
    # The local credential store omits the optional runtime when it is null.
    # Only the returned authenticated grant must carry an explicit runtimeId.
    runtime = credentials.get("runtime_id")
    # A requested session workspace is a local display label, not authority.
    workspace = credentials.get("workspace_id")
    if (
        (runtime is not None and not _text(runtime, 1024))
        or not isinstance(workspace, str)
        or _UUID.fullmatch(workspace) is None
        or not _text(credentials.get("grant_id"), 1024)
        or not _text(credentials.get("client_id"), 1024)
        or not _text(session.get("sessionId"), 4096)
        or not _text(session.get("harness"), 1024)
        or not _text(session.get("deviceId"), 1024)
        or session.get("deviceId") != credentials.get("machine_id")
    ):
        return None
    return {
        "sessionId": session["sessionId"],
        "harness": session["harness"],
        "deviceId": session["deviceId"],
        "workspace": workspace,
        "grantId": credentials["grant_id"],
        "clientId": credentials["client_id"],
        "runtimeId": runtime,
    }


def _read(connection: sqlite3.Connection, key: str) -> dict[str, object]:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
    if row is None:
        return {}
    try:
        value = json.loads(str(row[0]))
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write(connection: sqlite3.Connection, key: str, value: dict[str, object], now: str) -> None:
    connection.execute(
        "insert into sync_state (state_key,payload_json,updated_at) values (?,?,?) "
        "on conflict(state_key) do update set payload_json=excluded.payload_json,updated_at=excluded.updated_at",
        (key, _canonical(value), now),
    )


def _state_key(connection: OAuthConnectionSnapshot, subject: dict[str, object]) -> str:
    # Persist only a domain-separated digest, never keys/tokens or the identity
    # string that includes the local private DPoP material.
    identity = _canonical(
        {
            "credentialKey": connection.credential_key,
            "epoch": connection.epoch,
            "storeScope": connection.store_scope,
            "connection": connection_identity(connection.credentials()),
            "subject": subject,
        }
    )
    return (
        "runtime_policy_report_revisions:"
        + hashlib.sha256(b"guard.runtime-report-subject.v1\0" + identity.encode()).hexdigest()
    )


def _bound_observation(value: object, subject: dict[str, object]) -> dict[str, object] | None:
    if (
        not isinstance(value, dict)
        or value.get("workspaceId") != subject["workspace"]
        or value.get("deviceId") != subject["deviceId"]
    ):
        return None
    return cast(dict[str, object], value.copy())


def prepare_runtime_reports(
    store: GuardStore,
    connection: OAuthConnectionSnapshot | None,
    session: dict[str, object],
    observations: NativeRuntimeReports,
    *,
    now: str,
) -> tuple[dict[str, object], RuntimeReportWrite | None]:
    reports: dict[str, object] = {
        name: {"contractVersion": version, "previousReportRevision": None, "observation": None}
        for name, version, _ in _KINDS.values()
    }
    if connection is None:
        return reports, None
    subject = _subject(connection, session)
    if subject is None:
        return reports, None
    key = _state_key(connection, subject)
    attempt = secrets.token_hex(32)
    with store.hold_oauth_credential_lock(), store._connect() as database:
        store._require_oauth_connection_unlocked(connection)
        database.execute("begin immediate")
        state = _read(database, key)
        known = state.get("subject") == subject and state.get("schema") == "guard.runtime-report-revisions.v1"
        uncertain = not known or state.get("pending") is not None
        revisions = state.get("revisions") if known else None
        revisions = revisions if isinstance(revisions, dict) else {}
        retained: dict[str, object] = {}
        for kind, (name, version, _) in _KINDS.items():
            previous = _revision(revisions.get(kind))
            retained[kind] = previous
            observation = observations.application if kind == "application" else observations.delivery
            reports[name] = {
                "contractVersion": version,
                "previousReportRevision": previous,
                "observation": _bound_observation(observation, subject)
                if previous is not None and not uncertain
                else None,
            }
        _write(
            database,
            key,
            {
                "schema": "guard.runtime-report-revisions.v1",
                "subject": subject,
                "revisions": retained,
                "pending": attempt,
            },
            now,
        )
        store._require_oauth_connection_unlocked(connection)
    return reports, RuntimeReportWrite(key, attempt, subject)


def _returned_item(response: object, subject: dict[str, object]) -> dict[str, object] | None:
    if not isinstance(response, dict) or not isinstance(response.get("items"), list):
        return None
    items = [
        item for item in response["items"] if isinstance(item, dict) and item.get("sessionId") == subject["sessionId"]
    ]
    if len(items) != 1:
        return None
    item = items[0]
    if any(item.get(key) != subject[key] for key in ("sessionId", "workspace", "deviceId", "harness")):
        return None
    grant = item.get("oauthGrant")
    if not isinstance(grant, dict) or any(
        key not in grant or grant[key] != subject[key] for key in ("grantId", "clientId", "runtimeId")
    ):
        return None
    return cast(dict[str, object], item)


def finish_runtime_reports(
    store: GuardStore,
    connection: OAuthConnectionSnapshot | None,
    write: RuntimeReportWrite | None,
    response: object,
    *,
    now: str,
) -> None:
    """Consume only the response to this POST; lost/foreign responses withdraw.

    An older concurrent POST can never overwrite a newer local attempt. The
    next server write handles uncertain remote ordering by rotating/withdrawing.
    """
    if connection is None or write is None:
        return
    if _state_key(connection, write.subject) != write.state_key:
        return
    item = _returned_item(response, write.subject)
    revisions: dict[str, object] = {}
    for kind, (name, _, contract) in _KINDS.items():
        receipt = item.get(name + "Receipt") if item is not None else None
        revisions[kind] = (
            _revision(receipt.get("reportRevision"))
            if isinstance(receipt, dict)
            and set(receipt) == {"contractVersion", "reportRevision"}
            and receipt.get("contractVersion") == contract
            else None
        )
    with store.hold_oauth_credential_lock(), store._connect() as database:
        store._require_oauth_connection_unlocked(connection)
        database.execute("begin immediate")
        current = _read(database, write.state_key)
        if current.get("pending") != write.attempt or current.get("subject") != write.subject:
            return
        _write(
            database,
            write.state_key,
            {
                "schema": "guard.runtime-report-revisions.v1",
                "subject": write.subject,
                "revisions": revisions,
                "pending": None,
            },
            now,
        )
        store._require_oauth_connection_unlocked(connection)
