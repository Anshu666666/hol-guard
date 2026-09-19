"""Runtime negotiation and ephemeral signing context, outside synchronous hooks."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .mdm.policy import managed_policy_cache_read_only
from .native_cloud_policy_inputs import NativeCloudPolicyInputs, read_native_cloud_policy_inputs
from .native_managed_capture import bind_configuration_origin
from .native_policy_authority_read import NativeVerifiedPolicyInputs, read_native_policy_authority_inputs
from .native_policy_publication_lock import hold_policy_publication_mutation
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


@dataclass(frozen=True)
class CapturedV3PublicationInputs(NativeCloudPolicyInputs):
    """Complete V3-compatible authority, rechecked before resident acceptance."""

    input_digest: str = ""


def requires_scoped_publication(publisher: NativePolicySnapshotPublisher, inputs: NativeVerifiedPolicyInputs) -> bool:
    authority = inputs.authority
    return bool(
        publisher._scoped_publication_enabled
        or publisher._source_authority_required
        or publisher._source_memory_required
        or inputs.sources
        or inputs.defaults is not None
        or authority.rows
        or authority.command_expressions
        or authority.managed is not None
        or authority.managed_config is not None
    )


def _v3_inputs_from_capture(
    publisher: NativePolicySnapshotPublisher,
    inputs: NativeVerifiedPolicyInputs,
    *,
    allow_signed_defaults: bool,
) -> CapturedV3PublicationInputs:
    authority = inputs.authority
    if (
        publisher._scoped_publication_enabled
        or publisher._source_memory_required
        or authority.rows
        or authority.command_expressions
        or authority.managed is not None
        or authority.managed_config is not None
    ):
        raise NativePolicySnapshotError("native_policy_authority_scoped_consumer_required")
    sources = inputs.sources
    cloud = read_native_cloud_policy_inputs(publisher.store, now=publisher._wall_clock())
    if sources:
        if not allow_signed_defaults or len(sources) != 1 or sources[0].get("kind") != "signed-bundle":
            raise NativePolicySnapshotError("native_policy_authority_scoped_consumer_required")
        source = sources[0]
        if cloud.defaults != inputs.defaults or cloud.source_identity != (
            source.get("revision"),
            source.get("digest"),
            source.get("workspace_id"),
            inputs.expires_at_ms,
        ):
            raise NativePolicySnapshotError("native_policy_authority_source_changed")
    elif publisher._source_authority_required or inputs.defaults is not None or cloud.source_identity is not None:
        raise NativePolicySnapshotError("native_policy_authority_source_changed")
    return CapturedV3PublicationInputs(
        defaults=cloud.defaults,
        source_identity=cloud.source_identity,
        expires_at_ms=cloud.expires_at_ms,
        input_digest=inputs.input_digest,
    )


def compiled_v3_compatible_policy(
    publisher: NativePolicySnapshotPublisher,
    *,
    allow_signed_defaults: bool = True,
) -> tuple[dict[str, object], CapturedV3PublicationInputs]:
    refresh_source_requirement(publisher)
    # The observer can run before the first publication. Bootstrap only the
    # existing local integrity key; this never creates policy authority.
    publisher.store._policy_integrity_secret_material(create=True)
    inputs = read_native_policy_authority_inputs(publisher.store, now=publisher._wall_clock())
    config = (
        publisher._compiled_effective_policy()
        if inputs.defaults is None
        else publisher._compiled_effective_policy(cloud_defaults=inputs.defaults)
    )
    inputs = bind_configuration_origin(config, inputs)
    return config, _v3_inputs_from_capture(publisher, inputs, allow_signed_defaults=allow_signed_defaults)


def publication_context(
    self: NativePolicySnapshotPublisher, *, publish_epoch: int | None = None
) -> PublicationContext | None:
    with self._condition:
        if publish_epoch is None:
            publish_epoch = self._epoch
        if self._closed or self._epoch != publish_epoch:
            return None
    refresh_source_requirement(self)
    status_provider = self._status_provider
    if status_provider is None:
        from .native_runtime import native_runtime_status

        status_provider = native_runtime_status
    status = status_provider()
    if getattr(status, "mode", None) not in {"auto", "force", "shadow"}:
        _context_error(
            self,
            "native_policy_snapshot_native_disabled",
            publish_epoch=publish_epoch,
        )
        return None
    identity = getattr(status, "identity", None)
    capabilities = getattr(status, "capabilities", None)
    if (
        not getattr(status, "available", False)
        or not getattr(status, "compatible", False)
        or identity is None
        or capabilities is None
    ):
        _context_error(
            self,
            "native_policy_snapshot_runtime_unavailable",
            publish_epoch=publish_epoch,
        )
        return None
    features = frozenset(getattr(capabilities, "features", ()))
    material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        _context_error(
            self,
            "native_policy_snapshot_integrity_key_unavailable",
            publish_epoch=publish_epoch,
        )
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
            _context_error(
                self,
                "native_policy_snapshot_integrity_key_unavailable",
                publish_epoch=publish_epoch,
            )
            return None
        if not self._scoped_publication_enabled and not features.intersection(SCOPED_PUBLISH_FEATURES):
            if not _REQUIRED_PUBLISH_FEATURES.issubset(features):
                raise NativePolicySnapshotError("native_policy_snapshot_protocol_unsupported")
            # Retain the established authenticated V3 refusal diagnostics.
            # Passing this preflight never bypasses the complete capture below.
            _ = read_native_cloud_policy_inputs(self.store, now=self._wall_clock())
        # Capabilities describe what a runtime can consume, not the authority
        # selected for this publication. Authenticate the complete input first.
        config, inputs = compiled_scoped_policy(self)
        scoped = requires_scoped_publication(self, inputs)
        compatible_defaults = (
            scoped
            and not self._scoped_publication_enabled
            and not features.intersection(SCOPED_PUBLISH_FEATURES)
            and not inputs.authority.rows
            and not inputs.authority.command_expressions
            and inputs.authority.managed is None
            and inputs.authority.managed_config is None
            and not self._source_memory_required
            and len(inputs.sources) == 1
            and inputs.sources[0].get("kind") == "signed-bundle"
        )
        cloud_inputs: NativeCloudPolicyInputs | NativeVerifiedPolicyInputs
        if not scoped or compatible_defaults:
            cloud_inputs = _v3_inputs_from_capture(self, inputs, allow_signed_defaults=compatible_defaults)
            scoped = False
        else:
            cloud_inputs = inputs
        with self._condition:
            if self._closed or self._epoch != publish_epoch:
                return None
            self._scoped_publication_enabled = scoped
        required = (
            (_REQUIRED_PUBLISH_FEATURES - {"policy-snapshot-v3", "policy-snapshot-push-v1"}) | SCOPED_PUBLISH_FEATURES
            if scoped
            else _REQUIRED_PUBLISH_FEATURES
        )
        if not required.issubset(features):
            raise NativePolicySnapshotError("native_policy_snapshot_protocol_unsupported")
        client = self._client_request
        if client is None:
            from .native_resident_client import native_resident_client_request

            client = native_resident_client_request
        with self._condition:
            if self._closed or self._epoch != publish_epoch:
                return None
            return identity, capabilities, material[0], config, client, cloud_inputs
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error):
        with self._condition:
            if not self._closed and self._epoch == publish_epoch:
                self._acked = False
        raise
    finally:
        material = None


def _context_error(publisher: NativePolicySnapshotPublisher, reason: str, *, publish_epoch: int) -> None:
    with publisher._condition:
        if publisher._closed or publisher._epoch != publish_epoch:
            return
        if publisher._scoped_publication_enabled or reason == "native_policy_snapshot_integrity_key_unavailable":
            publisher._acked = False
        publisher._record_error(reason)


@contextmanager
def capture_for_reservation(
    publisher: NativePolicySnapshotPublisher,
    *,
    expected: PublicationContext,
    publish_epoch: int,
    deadline_monotonic: float,
) -> Iterator[PublicationContext]:
    """Capture each attempt while rotation cannot retire and replace its source.

    The caller reserves signed bytes inside this scope and releases it before
    transport. A native retirement then fences any older prepared request.
    """
    from .native_policy_snapshot_publisher_scoped import _capture_metadata_equal

    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    with hold_policy_publication_mutation(publisher.guard_home, timeout_seconds=min(5.0, remaining)):
        for capture_attempt in range(2):
            with publisher._condition:
                if publisher._closed or publisher._epoch != publish_epoch:
                    raise NativePolicySnapshotError("native_policy_authority_source_changed")
            if capture_attempt > 0 and time.monotonic() >= deadline_monotonic:
                raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
            with managed_policy_cache_read_only(), publisher.store._connect() as connection:
                version = connection.execute("pragma data_version").fetchone()[0]
                before = publisher._current_input_fingerprint()[0]
                current = publisher._publication_context(publish_epoch=publish_epoch)
                after = publisher._current_input_fingerprint()[0]
                if current is None:
                    raise NativePolicySnapshotError("native_policy_snapshot_runtime_unavailable")
                try:
                    identity, capabilities, _, _, _, inputs = current
                    old_identity, old_capabilities, _, _, _, old_inputs = expected
                    if (
                        identity.path != old_identity.path
                        or identity.sha256 != old_identity.sha256
                        or capabilities.rule_digest != old_capabilities.rule_digest
                        or frozenset(capabilities.features) != frozenset(old_capabilities.features)
                        or getattr(capabilities, "extension_catalog_digest", None)
                        != getattr(old_capabilities, "extension_catalog_digest", None)
                        or isinstance(inputs, NativeVerifiedPolicyInputs)
                        != isinstance(old_inputs, NativeVerifiedPolicyInputs)
                    ):
                        raise NativePolicySnapshotError("native_policy_snapshot_inputs_changed")
                    with publisher._condition:
                        if publisher._closed or publisher._epoch != publish_epoch:
                            raise NativePolicySnapshotError("native_policy_authority_source_changed")
                    if (
                        not _capture_metadata_equal(before, after, str(publisher.guard_home / "guard.db"))
                        or connection.execute("pragma data_version").fetchone()[0] != version
                    ):
                        # A startup bookkeeping commit can race the first capture.
                        # Retry once while the barrier is unacknowledged.
                        # Ready renewals retain their existing failure handling.
                        with publisher._condition:
                            retry_capture = (
                                capture_attempt == 0
                                and not publisher._closed
                                and publisher._epoch == publish_epoch
                                and not publisher._acked
                            )
                        if retry_capture:
                            continue
                        raise NativePolicySnapshotError("native_policy_authority_capture_changed")
                    if time.monotonic() >= deadline_monotonic:
                        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
                    yield current
                    return
                finally:
                    current = None
