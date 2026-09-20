"""Actual signature/parser checks; these are not installed runtime acceptance."""

from __future__ import annotations

import json
import ssl
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from ci.native_runtime.installed_managed_policy_fixture import ManagedPolicyFixture
from ci.native_runtime.installed_scoped_policy_fixture import WORKSPACE
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    validated_managed_controls_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    is_mapping,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

# Parser input only; these are never advertised or written to runtime state.
PARSER_CAPABILITIES = frozenset(
    {EXTENSION_CONTROL_LAYER_CAPABILITY, MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY, POLICY_EXTENSION_TARGETS_CAPABILITY}
)
PERMISSION = "command.git.permission.force-push"


@pytest.fixture
def fixture(tmp_path: Path) -> Iterator[ManagedPolicyFixture]:
    value = ManagedPolicyFixture(tmp_path)
    try:
        yield value
    finally:
        value.close()


def _parse(fixture: ManagedPolicyFixture, bundle: dict[str, object]):
    return validated_managed_controls_policy_bundle_v2_payload(
        bundle,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=PARSER_CAPABILITIES,
        trusted_verification_keys=(fixture.verification,),
        anchored_verification_keys=(fixture.verification,),
    )


@pytest.mark.parametrize(
    ("target_kind", "target_id", "lockdown"),
    [("permission", PERMISSION, False), ("extension", "command.ollama", False), (None, None, True)],
)
def test_signed_managed_fixture_delivers_without_preinstalling_authority(
    fixture: ManagedPolicyFixture, target_kind: str | None, target_id: str | None, lockdown: bool
) -> None:
    controls = []
    if target_kind is not None and target_id is not None:
        controls.append({"targetKind": target_kind, "targetId": target_id, "state": "disabled"})
    defaults = {"mode": "observe", "defaultAction": "warn"}
    fixture.bundle = fixture.signed_managed_bundle(7, controls=controls, lockdown=lockdown, defaults=defaults)
    # Changes to caller inputs must not invalidate a previously signed payload.
    defaults["mode"] = "enforce"
    if controls:
        controls[0]["state"] = "enabled"
    request = urllib.request.Request(
        fixture.sync_url, data=b"{}", headers={"Authorization": f"Bearer {fixture.token}"}, method="POST"
    )
    with urllib.request.urlopen(
        request, context=ssl.create_default_context(cafile=str(fixture.ca_file)), timeout=2
    ) as response:
        delivered = json.load(response)["policyBundle"]
    assert delivered == fixture.bundle
    assert delivered["payloadHash"] == payload_hash_for_policy_bundle_v2(delivered)
    assert delivered["bundleHash"] == computed_policy_bundle_v2_hash(delivered)
    accepted, reason, _keys = validate_synced_policy_bundle(
        delivered,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is not None and reason is None
    validated, parsed, reason = _parse(fixture, delivered)
    assert validated is not None and parsed is not None and reason is None, reason
    assert parsed.authority_mode == "managed-restrictive"
    assert parsed.managed_global_lockdown is lockdown
    assert [
        (control.target.kind.value, control.target.target_id, control.state.value)
        for control in parsed.managed_controls
    ] == ([(target_kind, target_id, "disabled")] if controls else [])
    payload = delivered["payload"]
    assert payload["spec"]["rules"] == []
    assert payload["spec"]["defaults"] == {"mode": "observe", "defaultAction": "warn"}
    assert payload["metadata"]["revision"] == delivered["bundleVersion"] == 7
    assert ("globalLockdown" in payload[HOL_EXTENSION_CONTROLS_FIELD]) is lockdown
    assert fixture.requests == 1
    for key in ("policy_bundle", "policy_bundle_ack", "native_policy_bundle_ack_acceptance", "managed_controls_active"):
        assert fixture.store.get_sync_payload(key) is None
    assert not fixture.store.list_policy_decisions()


@pytest.mark.parametrize(
    ("authority_mode", "permission", "expected_reason"),
    [
        ("managed-restrictive", PERMISSION, "managed_restrictive_broadening"),
        ("workspace-shared", "command.guard-self-protection.permission.self-authorization", "immutable_floor"),
    ],
)
def test_signed_enable_attempt_passes_signature_and_fails_actual_parser(
    fixture: ManagedPolicyFixture, authority_mode: str, permission: str, expected_reason: str
) -> None:
    bundle = fixture.signed_managed_bundle(
        8,
        controls=[{"targetKind": "permission", "targetId": permission, "state": "enabled"}],
        authority_mode=authority_mode,
    )
    accepted, reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is not None and reason is None
    validated, parsed, reason = _parse(fixture, bundle)
    assert validated is None and parsed is None and reason == expected_reason
    assert fixture.store.get_sync_payload("managed_controls_active") is None


def test_changes_after_signing_fail_actual_signature_validation(fixture: ManagedPolicyFixture) -> None:
    bundle = fixture.signed_managed_bundle(9, lockdown=True)
    payload = bundle["payload"]
    assert is_mapping(payload)
    controls = payload[HOL_EXTENSION_CONTROLS_FIELD]
    assert is_mapping(controls)
    controls.pop("globalLockdown")
    accepted, reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=fixture.store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=WORKSPACE,
    )
    assert accepted is None and reason is not None


def test_managed_negotiation_requires_actual_runtime_session_delivery(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ci.native_runtime.probe_installed_native_extensions import provision
    from codex_plugin_scanner.guard.runtime import runner

    for key in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    provision(fixture.store)
    assert fixture.negotiated_capabilities == ()
    assert fixture.response_for_request("/api/guard/receipts/sync", {})["managedControlsCapabilities"] == []
    summary = runner.sync_runtime_session(
        fixture.store, session={"harness": "claude-code", "workspace": str(fixture.workspace)}
    )
    assert isinstance(summary["runtime_session_synced_at"], str)
    assert frozenset(fixture.negotiated_capabilities) == PARSER_CAPABILITIES
    assert fixture.store.get_sync_payload("policy_bundle") is None
    assert fixture.store.get_sync_payload("native_policy_bundle_ack_acceptance") is None


def test_unprotected_runtime_cannot_negotiate_managed_authority(
    fixture: ManagedPolicyFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    for key in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("SSL_CERT_FILE", str(fixture.ca_file))
    runner.sync_runtime_session(fixture.store, session={"harness": "claude-code"})
    assert fixture.negotiated_capabilities == ()
