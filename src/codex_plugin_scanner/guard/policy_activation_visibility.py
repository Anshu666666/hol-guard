"""Desired, durable, and resident policy-activation stages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class NativeSnapshotPublisherView(Protocol):
    def is_ready(self) -> bool: ...

    def current_snapshot_binding(self) -> dict[str, object] | None: ...

    @property
    def last_error(self) -> str | None: ...


def policy_activation_visibility(
    *,
    desired_revision: str | None,
    desired_digest: str | None = None,
    durable_bundle: Mapping[str, object] | None,
    acknowledgement: Mapping[str, object] | None = None,
    publisher: NativeSnapshotPublisherView | None = None,
) -> dict[str, object]:
    """Separate SQLite authority from native resident publication."""

    durable_revision = None
    durable_digest = None
    if isinstance(durable_bundle, Mapping):
        version = durable_bundle.get("bundleVersion")
        digest = durable_bundle.get("bundleHash") or durable_bundle.get("payloadHash")
        durable_revision = version if isinstance(version, str) and version else None
        durable_digest = digest if isinstance(digest, str) and digest else None
    ack_status = acknowledgement.get("status") if isinstance(acknowledgement, Mapping) else None
    ack_revision = acknowledgement.get("bundleVersion") if isinstance(acknowledgement, Mapping) else None
    acknowledged = ack_status in {"synced", "applied"} and (
        ack_revision in {None, desired_revision} or ack_revision == durable_revision
    )
    resident_ready = publisher.is_ready() if publisher is not None else False
    binding = publisher.current_snapshot_binding() if publisher is not None and resident_ready else None
    resident_digest = binding.get("policy_digest") if isinstance(binding, Mapping) else None
    publication_pending = bool(desired_revision) and desired_revision == durable_revision and not resident_ready
    applied = bool(desired_revision) and desired_revision == durable_revision and acknowledged and resident_ready
    return {
        "desired_revision": desired_revision,
        "desired_digest": desired_digest,
        "durable_revision": durable_revision,
        "durable_digest": durable_digest,
        "resident_ready": resident_ready,
        "resident_digest": resident_digest if isinstance(resident_digest, str) else None,
        "acknowledged": acknowledged,
        "publication_pending": publication_pending,
        "publication_error": publisher.last_error if publisher is not None else None,
        "applied": applied,
        "deployment_complete": applied,
    }


__all__ = ["policy_activation_visibility"]
