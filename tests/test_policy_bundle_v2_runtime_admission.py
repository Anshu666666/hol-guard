"""Runtime admission regressions for signed generic policy bundle v2 documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_parser import (
    policy_bundle_is_enforceable,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_v2 import (
    _signed_bundle,
    _verification_key,
)


def _generic_v2_payload(*, rollout_state: str, rule_id: str, artifact_id: str) -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "policy.runtime-admission", "name": "Admission", "revision": 1},
        "spec": {
            "defaults": {"mode": "prompt", "defaultAction": "warn"},
            "rolloutState": rollout_state,
            "rules": [
                {
                    "id": rule_id,
                    "enabled": True,
                    "effect": "block",
                    "match": {
                        "artifacts": [artifact_id],
                        "harnesses": ["codex"],
                    },
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {
                        "source": "suggested-memory",
                        "receiptIds": ["receipt-1"],
                        "suggestionId": "suggestion-1",
                        "createdAt": "2026-07-15T12:00:00Z",
                        "createdBy": "owner-1",
                    },
                }
            ],
        },
    }


class _SyncResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _SyncResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        del exc_type, exc, tb
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _sync_signed_v2_bundle(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    bundle: dict[str, object],
    *,
    synced_at: str,
) -> dict[str, object]:
    stub_authenticated_urlopen(
        monkeypatch,
        lambda request, timeout: _SyncResponse(
            {"syncedAt": synced_at, "receiptsStored": 0, "policyBundle": bundle}
        ),
    )
    monkeypatch.setattr(guard_runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner, "sync_guard_events", lambda _store, auth_context=None: 0)
    return guard_runner.sync_receipts(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "test-token",
            "dpop_key_material": None,
        },
    )


def test_v2_publication_contract_matches_live_rollout_states() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    draft = _signed_bundle(private_key, verification_key)
    pending = _signed_bundle(private_key, verification_key, rollout_state="pending_approval")
    published = _signed_bundle(private_key, verification_key, rollout_state="enforcing")

    assert policy_bundle_is_enforceable(draft) is False
    assert policy_bundle_is_enforceable(pending) is False
    assert policy_bundle_is_enforceable(published) is True
    omitted_payload = _generic_v2_payload(
        rollout_state="enforcing",
        rule_id="rule.live",
        artifact_id="command:live",
    )
    spec = cast(dict[str, object], omitted_payload["spec"])
    spec.pop("rolloutState", None)
    omitted = _signed_bundle(private_key, verification_key, payload_base=omitted_payload)
    assert policy_bundle_is_enforceable(omitted) is True


@pytest.mark.parametrize("rollout_state", ["draft", "pending_approval"])
def test_signed_unpublished_generic_v2_bundle_is_not_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollout_state: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    live = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=8,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.live-block",
            artifact_id="command:live-block",
        ),
    )
    unpublished = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        payload_base=_generic_v2_payload(
            rollout_state=rollout_state,
            rule_id="rule.draft-block",
            artifact_id="command:draft-block",
        ),
    )
    validated, reason, _keys = validate_synced_policy_bundle(
        unpublished,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
    )
    assert reason is None
    assert validated is not None
    assert policy_bundle_is_enforceable(unpublished) is False

    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-07-15T12:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-07-15T12:00:00Z")

    _sync_signed_v2_bundle(store, monkeypatch, live, synced_at="2026-07-15T12:01:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    live_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:live-block" in live_rows
    assert store.get_sync_payload("policy_bundle_ack") == {}

    _sync_signed_v2_bundle(store, monkeypatch, unpublished, synced_at="2026-07-15T12:02:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    assert store.get_sync_payload("policy_bundle_last_good") == live
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error.get("reason") == "inactive_rollout_state"
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert acknowledgement == {} or (
        isinstance(acknowledgement, dict) and acknowledgement.get("status") != "applied"
    )
    remaining_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:draft-block" not in remaining_rows
    assert "command:live-block" in remaining_rows

    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")

    store.set_sync_payload("policy_bundle", unpublished, "2026-07-15T12:03:00Z")
    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")
    assert cached_policy_bundle_validation(store, live)[0] == live


def test_signed_enforcing_generic_v2_bundle_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    published = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=10,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.published-block",
            artifact_id="command:published-block",
        ),
    )
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-07-15T12:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-07-15T12:00:00Z")

    _sync_signed_v2_bundle(store, monkeypatch, published, synced_at="2026-07-15T12:04:00Z")
    assert store.get_sync_payload("policy_bundle") == published
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert last_error in (None, {})
    assert "command:published-block" in [row["artifact_id"] for row in store.list_policy_decisions()]
    assert cached_policy_bundle_validation(store, published)[0] == published
