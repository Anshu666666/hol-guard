"""Catalog status is produced by the real service and real Store migration."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle


def _service(store: GuardStore, registry: CommandSafetyExtensionRegistry, view: ExtensionControlAuthorityView):
    return ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))


@pytest.mark.parametrize("kind", [ControlTargetKind.PERMISSION, ControlTargetKind.EXTENSION])
def test_effective_service_names_missing_catalog_target(tmp_path: Path, kind: ControlTargetKind) -> None:
    store = GuardStore(tmp_path / "guard")
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    target = "command.missing.permission.operation" if kind is ControlTargetKind.PERMISSION else "command.missing"
    layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        registry.catalog_digest,
        False,
        (ExtensionControl(ControlTarget(kind, target), ControlState.DISABLED),),
    )
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, registry.catalog_digest, (layer,))
    payload = _service(store, registry, view).effective()
    status = payload["catalog_status"]
    assert isinstance(status, dict)
    assert status["applied"] is False and status["catalog_compatible"] is False
    assert status["runtime_version"] == __version__
    assert status["catalog_digest"] == registry.catalog_digest
    assert target in str(status["next_action"])
    key = "missing_permission_ids" if kind is ControlTargetKind.PERMISSION else "missing_extension_ids"
    assert status[key] == (target,)


def test_effective_service_does_not_claim_application_for_compatible_catalog(tmp_path: Path) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, registry.catalog_digest, ())
    payload = _service(GuardStore(tmp_path / "guard"), registry, view).effective()
    status = payload["catalog_status"]
    assert isinstance(status, dict)
    assert status["catalog_compatible"] is True
    assert status["applied"] is False


def test_effective_service_reports_exact_observed_catalog_mismatch(tmp_path: Path) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    other = "ab" * 32
    layer = ExtensionControlLayer(CONTROL_SCHEMA_VERSION, ControlLayerKind.SIGNED_CLOUD, other, False, ())
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, other, (layer,))
    status = _service(GuardStore(tmp_path / "guard"), registry, view).effective()["catalog_status"]
    assert isinstance(status, dict)
    assert status["applied"] is False and status["catalog_compatible"] is False
    assert status["policy_catalog_digests"] == (other,)
    assert status["catalog_digest"] == registry.catalog_digest
    assert "Update this device" in str(status["next_action"])


def test_effective_service_refuses_mismatched_empty_snapshot_catalog(tmp_path: Path) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    other = "ab" * 32
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, other, ())
    status = _service(GuardStore(tmp_path / "guard"), registry, view).effective()["catalog_status"]
    assert isinstance(status, dict)
    assert status["applied"] is False and status["catalog_compatible"] is False
    assert status["observed_catalog_digest"] == other
    assert "catalog-digest-mismatch" in status["failure_codes"]


def test_effective_service_refuses_compatibility_when_authority_is_unavailable(tmp_path: Path) -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    view = ExtensionControlAuthorityView(AuthorityHealth.UNENROLLED, 0, registry.catalog_digest, ())
    status = _service(GuardStore(tmp_path / "guard"), registry, view).effective()["catalog_status"]
    assert isinstance(status, dict)
    assert status["applied"] is False and status["catalog_compatible"] is False
    assert "authority-unavailable" in status["failure_codes"]
    assert "Restore valid local" in str(status["next_action"])


def test_actual_catalog_upgrade_downgrade_and_removal_preserve_restrictions(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(store.guard_home)
    assert activate_managed_bundle(store, managed_bundle())
    original = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    ack = store.get_sync_payload("policy_bundle_ack")
    changed = CommandSafetyExtensionRegistry(
        (replace(original.extensions[0], description="Catalog compatibility fixture"), *original.extensions[1:])
    )
    removed = CommandSafetyExtensionRegistry(
        tuple(item for item in original.extensions if item.extension_id != "command.git")
    )
    for registry in (changed, original, removed, original):
        view = store.read_extension_control_authority_for_registry(registry)
        assert view.health is AuthorityHealth.PROTECTED
        assert view.catalog_digest == registry.catalog_digest
        restrictions = [
            control
            for layer in view.layers
            if layer.kind is ControlLayerKind.SIGNED_CLOUD
            for control in layer.controls
        ]
        assert restrictions and all(control.state is ControlState.DISABLED for control in restrictions)
        assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active
        assert store.get_sync_payload("policy_bundle_ack") == ack
        status = _service(store, registry, view).effective()["catalog_status"]
        assert isinstance(status, dict) and status["applied"] is False
        if registry is removed:
            assert status["catalog_compatible"] is False
            assert status["missing_permission_ids"] or status["missing_extension_ids"]
        else:
            assert status["catalog_compatible"] is True
    # Reopen the real vault/database and re-read migration state before retry.
    recovered = GuardStore(store.guard_home)
    recovered._extension_control_authority_secret_store = EncryptedFileSecretStore(store.guard_home)
    view = recovered.read_extension_control_authority_for_registry(original)
    assert view.health is AuthorityHealth.PROTECTED
    assert recovered.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active
    assert recovered.get_sync_payload("policy_bundle_ack") == ack
    assert all(control.state is ControlState.DISABLED for layer in view.layers for control in layer.controls)
