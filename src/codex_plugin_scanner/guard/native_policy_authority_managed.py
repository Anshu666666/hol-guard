"""Freeze authenticated built-in controls without inventing native semantics."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    managed_controls_layers_from_activation_state,
    managed_controls_revision_from_state,
    parsed_managed_controls_from_validated_policy_bundle,
)
from .native_policy_authority_compile import compile_native_managed_authority
from .native_policy_authority_contract import NativeManagedPolicyAuthority
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    layers_to_json,
)
from .runtime.extension_control_contract import ControlLayerKind, ControlTargetKind
from .runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from .store import GuardStore

_REGISTRY = BUILT_IN_COMMAND_EXTENSION_REGISTRY


def _unavailable() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_policy_authority_managed_unavailable")


def require_unenrolled_secrets(store: GuardStore) -> None:
    """Absence is a captured state too; a newly present key/anchor revokes it."""
    try:
        if (
            store._authority_key(required=False) is not None
            or store._secret_store().get_secret(store._anchor_ref()) is not None
        ):
            raise _unavailable()
    except ExtensionControlAuthorityError as error:
        raise _unavailable() from error


@dataclass(frozen=True, slots=True, repr=False)
class FrozenNativeManagedAuthority:
    """Verified authority from the existing reader, fenced by the caller's database observation."""

    authority: NativeManagedPolicyAuthority
    snapshot: ExtensionControlRuntimeSnapshot
    _key: bytes
    _anchor: AuthorityAnchor

    def require_current_secrets(self, store: GuardStore) -> None:
        try:
            key = store._authority_key(required=False)
            if key != self._key or key is None or store._read_anchor(key=key) != self._anchor:
                raise _unavailable()
        except ExtensionControlAuthorityError as error:
            raise _unavailable() from error

    def validate_capture(
        self,
        payloads: Mapping[str, object],
        local_row: Mapping[str, object] | None,
    ) -> None:
        if local_row is None or (
            local_row.get("revision") != self.authority.revision
            or local_row.get("catalog_digest") != self.authority.catalog_digest
            or local_row.get("snapshot_digest") != self._anchor.snapshot_digest
        ):
            raise _unavailable()
        active = payloads.get(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
        revision = payloads.get(MANAGED_CONTROLS_REVISION_STATE_KEY)
        try:
            current_revision = (
                managed_controls_revision_from_state(revision, authority_key=self._key) if revision is not None else 0
            )
            if current_revision != self.authority.managed_revision:
                raise _unavailable()
            if active is not None:
                layers, active_revision = managed_controls_layers_from_activation_state(
                    active,
                    catalog_digest=self.authority.catalog_digest,
                    authority_key=self._key,
                )
                if active_revision != current_revision or layers != tuple(
                    layer for layer in self.snapshot.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD
                ):
                    raise _unavailable()
            elif self.authority.managed_revision and any(
                layer.kind is ControlLayerKind.SIGNED_CLOUD for layer in self.snapshot.layers
            ):
                raise _unavailable()
        except ExtensionControlAuthorityError as error:
            raise _unavailable() from error

    def require_signed_bundle(self, bundle: Mapping[str, object], payloads: Mapping[str, object]) -> None:
        """Bind the retained managed projection to the complete currently signed input."""
        active = payloads.get(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
        if not isinstance(active, dict) or bundle.get("contractVersion") != "guard-policy-bundle.v2":
            raise _unavailable()
        value = cast(dict[str, object], active)
        if (
            any(
                value.get(field) != bundle.get(field)
                for field in (
                    "bundleHash",
                    "bundleVersion",
                    "workspaceId",
                    "issuedAt",
                    "expiresAt",
                )
            )
            or value.get("catalogDigest") != self.authority.catalog_digest
        ):
            raise _unavailable()
        capabilities = value.get("negotiatedCapabilities")
        if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
            raise _unavailable()
        try:
            parsed = parsed_managed_controls_from_validated_policy_bundle(
                dict(bundle),
                registry=_REGISTRY,
                negotiated_capabilities=frozenset(cast(list[str], capabilities)),
            )
        except (ValueError, ExtensionControlAuthorityError) as error:
            raise _unavailable() from error
        # The native managed contract has no targeted rule selector/effect or
        # delegated enforcement field. A control-only projection cannot stand in for it.
        if (
            parsed.rule_targets
            or parsed.delegated_targets
            or value.get("ruleTargets") != []
            or value.get("delegatedTargets") != []
        ):
            raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
        expected_layers = () if parsed.signed_cloud_layer is None else (parsed.signed_cloud_layer,)
        if (
            value.get("signedCloudLayersJson") != layers_to_json(expected_layers)
            or value.get("authorityMode") != parsed.authority_mode
        ):
            raise _unavailable()

    def provenance(self) -> dict[str, object]:
        return {
            "kind": "managed-controls",
            "revision": self.authority.revision,
            "managed_revision": self.authority.managed_revision,
            "catalog_digest": self.authority.catalog_digest,
            "effective_digest": self.snapshot.effective_digest,
            "local_snapshot_digest": self._anchor.snapshot_digest,
        }


def read_frozen_native_managed_authority(
    store: GuardStore, *, connection: sqlite3.Connection | None = None
) -> FrozenNativeManagedAuthority | None:
    """Use existing MAC, anchor, transition, catalog and composition checks off-hook."""
    try:
        key = store._authority_key(required=False)
        anchor = store._read_anchor(key=key) if key is not None else None
        view = (
            store.read_extension_control_authority_for_registry(_REGISTRY)
            if connection is None
            else store._read_captured_extension_control_authority(connection, _REGISTRY)
        )
        if view.health is AuthorityHealth.UNENROLLED and anchor is None:
            require_unenrolled_secrets(store)
            return None
        if (
            view.health is not AuthorityHealth.PROTECTED
            or key is None
            or anchor is None
            or anchor.phase is not AuthorityPhase.COMMITTED
            or anchor.revision != view.revision
            or view.catalog_digest != _REGISTRY.catalog_digest
        ):
            raise _unavailable()
        authority = compile_native_managed_authority(view, _REGISTRY)
        for control in authority.controls:
            permission = (
                _REGISTRY.permission(control.target_id)
                if control.target_kind == ControlTargetKind.PERMISSION.value
                else None
            )
            extension = _REGISTRY.get(permission.extension_id if permission is not None else control.target_id)
            if extension is None or extension.source != "built-in" or extension.delegated_protection is not None:
                raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
        result = FrozenNativeManagedAuthority(
            authority,
            ExtensionControlRuntimeSnapshot.from_authority_view(view),
            key,
            anchor,
        )
        result.require_current_secrets(store)
        return result
    except ExtensionControlAuthorityError as error:
        raise _unavailable() from error


__all__ = ["FrozenNativeManagedAuthority", "read_frozen_native_managed_authority"]
