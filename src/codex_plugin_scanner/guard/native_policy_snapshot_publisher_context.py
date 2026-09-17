"""Runtime negotiation and ephemeral signing context, outside synchronous hooks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .native_cloud_policy_inputs import NativeCloudPolicyInputs
from .native_policy_authority_read import NativeVerifiedPolicyInputs
from .native_policy_snapshot_constants import _REQUIRED_PUBLISH_FEATURES, NativePolicySnapshotError
from .native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES, compiled_scoped_policy
from .native_policy_snapshot_source_requirement import refresh_source_requirement

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

PublicationContext = tuple[
    Any,
    Any,
    bytes,
    Mapping[str, object],
    Callable[..., bytes | None],
    NativeCloudPolicyInputs | NativeVerifiedPolicyInputs,
]


def publication_context(self: NativePolicySnapshotPublisher) -> PublicationContext | None:
    refresh_source_requirement(self)
    status_provider = self._status_provider
    if status_provider is None:
        from .native_runtime import native_runtime_status

        status_provider = native_runtime_status
    status = status_provider()
    if getattr(status, "mode", None) not in {"auto", "force", "shadow"}:
        _context_error(self, "native_policy_snapshot_native_disabled")
        return None
    identity = getattr(status, "identity", None)
    capabilities = getattr(status, "capabilities", None)
    if (
        not getattr(status, "available", False)
        or not getattr(status, "compatible", False)
        or identity is None
        or capabilities is None
    ):
        _context_error(self, "native_policy_snapshot_runtime_unavailable")
        return None
    features = frozenset(getattr(capabilities, "features", ()))
    scoped = bool(features & SCOPED_PUBLISH_FEATURES)
    if self._scoped_publication_enabled and not scoped:
        with self._condition:
            self._acked = False
        raise NativePolicySnapshotError("native_policy_snapshot_protocol_unsupported")
    with self._condition:
        self._scoped_publication_enabled = scoped
    required = (
        (_REQUIRED_PUBLISH_FEATURES - {"policy-snapshot-v3", "policy-snapshot-push-v1"}) | SCOPED_PUBLISH_FEATURES
        if scoped
        else _REQUIRED_PUBLISH_FEATURES
    )
    if not required.issubset(features):
        with self._condition:
            self._acked = False
        raise NativePolicySnapshotError("native_policy_snapshot_protocol_unsupported")
    material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        _context_error(self, "native_policy_snapshot_integrity_key_unavailable")
        return None
    material: object = None
    try:
        material = material_getter(create=True)
        if (
            not isinstance(material, tuple)
            or len(material) != 2
            or not isinstance(material[0], bytes)
            or not isinstance(material[1], str)
        ):
            _context_error(self, "native_policy_snapshot_integrity_key_unavailable")
            return None
        if not scoped and self._source_memory_required:
            raise NativePolicySnapshotError("native_cloud_policy_memory_unsupported")
        config, cloud_inputs = compiled_scoped_policy(self) if scoped else self._compiled_native_policy()
        if (
            isinstance(cloud_inputs, NativeCloudPolicyInputs)
            and self._source_authority_required
            and cloud_inputs.source_identity is None
        ):
            raise NativePolicySnapshotError("native_cloud_policy_authority_unavailable")
        client = self._client_request
        if client is None:
            from .native_resident_client import native_resident_client_request

            client = native_resident_client_request
        return identity, capabilities, material[0], config, client, cloud_inputs
    finally:
        material = None


def _context_error(publisher: NativePolicySnapshotPublisher, reason: str) -> None:
    if publisher._scoped_publication_enabled:
        with publisher._condition:
            publisher._acked = False
    publisher._record_error(reason)
