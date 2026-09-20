"""Fresh off-hook consumer preconditions; no stored observation grants authority."""

from __future__ import annotations

import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from .mdm.policy import managed_policy_cache_read_only
from .native_mode import native_mode_requires_rust
from .native_policy_authority_contract import NativePolicyAuthorityCapabilities
from .native_policy_publication_lock import hold_policy_publication_mutation
from .native_policy_snapshot_constants import _REQUIRED_PUBLISH_FEATURES, NativePolicySnapshotError
from .native_policy_snapshot_control import _remaining
from .native_policy_snapshot_publisher_context import CapturedV3PublicationInputs, _v3_inputs_from_capture
from .native_policy_snapshot_publisher_scoped import (
    SCOPED_PUBLISH_FEATURES,
    _capture_metadata_equal,
    _policy_fingerprint,
    compiled_scoped_policy,
)
from .native_policy_snapshot_source_requirement import refresh_source_requirement
from .native_policy_snapshot_v3_renewal import _external_source_metadata
from .native_runtime import NativeRuntimeStatus, native_runtime_status
from .oauth_connection_authority import OAuthConnectionSnapshot
from .policy_canonical_rollout import canonical_policy_enforcement_enabled
from .store_base import _DEVICE_ROW_KEY

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

# Only opaque instance names are retained. No credentials, runtime status,
# source inputs, snapshot or positive readiness result is cached here.
_INSTANCES: WeakKeyDictionary[NativePolicySnapshotPublisher, str] = WeakKeyDictionary()
_INSTANCE_LOCK = threading.Lock()
_FEATURES = (
    _REQUIRED_PUBLISH_FEATURES
    | SCOPED_PUBLISH_FEATURES
    | {
        "pre-tool-generic-authority-v1",
        "policy-snapshot-control-v1",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class NativeConsumerCapture:
    """Local-only typed capture. Wire encoding must project explicit fields."""

    publisher_instance: str
    publisher_epoch: int
    snapshot_version: int
    generation: int
    policy_digest: str
    source_input_digest: str
    resident_generation: int
    expires_at_ms: int
    runtime: NativeRuntimeStatus = field(repr=False)
    snapshot: dict[str, object] = field(repr=False, compare=False)


def _refuse() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_policy_consumer_authority_unavailable")


def _instance(publisher: NativePolicySnapshotPublisher) -> str:
    with _INSTANCE_LOCK:
        value = _INSTANCES.get(publisher)
        if value is None:
            value = secrets.token_hex(16)
            _INSTANCES[publisher] = value
        return value


def _positive_counter(value: object) -> int:
    if type(value) is not int or not 1 <= value <= (1 << 64) - 1:
        raise _refuse()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise _refuse()
    return value


def _runtime() -> NativeRuntimeStatus:
    status = native_runtime_status()
    if (
        not native_mode_requires_rust()
        or status.mode not in {"auto", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or status.capabilities.protocol_version != 1
        or not _FEATURES.issubset(status.capabilities.features)
    ):
        raise _refuse()
    return status


@contextmanager
def _condition_until(publisher: NativePolicySnapshotPublisher, deadline: float) -> Iterator[None]:
    if not publisher._condition.acquire(timeout=_remaining(deadline)):
        raise _refuse()
    try:
        yield
    finally:
        publisher._condition.release()


def _binding(
    publisher: NativePolicySnapshotPublisher,
    runtime: NativeRuntimeStatus,
    deadline: float,
) -> NativeConsumerCapture:
    with _condition_until(publisher, deadline):
        publisher._mark_expired_locked()
        snapshot = publisher._snapshot
        if publisher._closed or not publisher._acked or snapshot is None or snapshot.get("mode") != "enforce":
            raise _refuse()
        if runtime.identity is None or runtime.capabilities is None:
            raise _refuse()
        if (
            snapshot.get("runtime_identity") != runtime.identity.sha256
            or snapshot.get("rule_digest") != runtime.capabilities.rule_digest
            or snapshot.get("protocol_version") != runtime.capabilities.protocol_version
        ):
            raise _refuse()
        version = snapshot.get("version")
        if type(version) is not int or version not in {3, 4}:
            raise _refuse()
        if type(publisher._epoch) is not int or not 0 <= publisher._epoch <= (1 << 64) - 1:
            raise _refuse()
        if version == 4:
            binding = publisher._v4_binding
            publication = publisher._v4_publication
            if binding is None or publication is None or publisher._v4_epoch != publisher._epoch:
                raise _refuse()
            source = binding.source_input_digest
            resident = binding.resident_generation
            if (
                binding.generation != snapshot.get("generation")
                or binding.policy_digest != snapshot.get("policy_digest")
                or publication.candidate.inputs.input_digest != source
                or publication.resident_generation != resident
            ):
                raise _refuse()
        else:
            inputs = publisher._published_cloud_inputs
            if (
                publisher._v4_publication is not None
                or not isinstance(inputs, CapturedV3PublicationInputs)
                or publisher._published_v3_source_fingerprint is None
                or publisher._published_v3_resident_fingerprint is None
            ):
                raise _refuse()
            source = inputs.input_digest
            resident = publisher._published_v3_resident_generation
        return NativeConsumerCapture(
            _instance(publisher),
            publisher._epoch,
            version,
            _positive_counter(snapshot.get("generation")),
            _digest(snapshot.get("policy_digest")),
            _digest(source),
            _positive_counter(resident),
            _positive_counter(snapshot.get("expires_at_ms")),
            runtime,
            snapshot,
        )


def _lane(connection: OAuthConnectionSnapshot, observer: sqlite3.Connection) -> None:
    workspace = connection.credentials().get("workspace_id")
    row = observer.execute(
        "select installation_id from guard_devices where device_key = ?",
        (_DEVICE_ROW_KEY,),
    ).fetchone()
    if (
        row is None
        or not isinstance(workspace, str)
        or not canonical_policy_enforcement_enabled(device_id=str(row[0]), workspace_id=workspace)
    ):
        raise _refuse()


def _fresh_sources(publisher: NativePolicySnapshotPublisher, expected: NativeConsumerCapture) -> None:
    refresh_source_requirement(publisher)
    extensions = publisher._compiled_command_extensions()
    if extensions != expected.snapshot.get("command_extensions", {}):
        raise _refuse()
    config, inputs = compiled_scoped_policy(publisher, command_extensions=extensions)
    if inputs.input_digest != expected.source_input_digest or _policy_fingerprint(config) != (
        expected.snapshot.get("config_digest"),
        "enforce",
    ):
        raise _refuse()
    if expected.snapshot_version == 3:
        published = publisher._published_cloud_inputs
        if (
            not isinstance(published, CapturedV3PublicationInputs)
            or _v3_inputs_from_capture(
                publisher,
                inputs,
                allow_signed_defaults=published.source_identity is not None,
                command_extensions=extensions,
            )
            != published
        ):
            raise _refuse()
    else:
        capabilities = expected.runtime.capabilities
        assert capabilities is not None
        _ = inputs.authority.for_snapshot(
            NativePolicyAuthorityCapabilities(
                4,
                frozenset(capabilities.features),
                capabilities.extension_catalog_digest,
            )
        )
    if inputs.expires_at_ms is not None and inputs.expires_at_ms <= int(publisher._wall_clock() * 1000):
        raise _refuse()


@contextmanager
def capture_native_consumer(
    publisher: NativePolicySnapshotPublisher,
    *,
    connection: OAuthConnectionSnapshot,
    deadline_monotonic: float,
) -> Iterator[NativeConsumerCapture]:
    """Hold local authority across IPC/signing, with a full fresh final capture.

    Remote HTTP must be outside this context. A final refusal discards a signed
    body produced inside it. The owning bounded worker must reject late results.
    Complete capture owns its own credential lock, so that lock is retained
    only across the yielded IPC/signing interval and the final commit checks.
    """
    store = publisher.store
    with (
        hold_policy_publication_mutation(
            publisher.guard_home,
            timeout_seconds=_remaining(deadline_monotonic),
        ),
        managed_policy_cache_read_only(),
        store._connect() as observer,
    ):
        with store.hold_oauth_credential_lock(timeout_seconds=_remaining(deadline_monotonic)):
            store._require_oauth_connection_unlocked(connection)
        _lane(connection, observer)
        identity = store.path.stat()
        database_identity = identity.st_dev, identity.st_ino
        version = observer.execute("pragma data_version").fetchone()[0]
        runtime = _runtime()
        expected = _binding(publisher, runtime, deadline_monotonic)
        before = publisher._current_input_fingerprint()
        _fresh_sources(publisher, expected)
        after = publisher._current_input_fingerprint()
        if (
            not _capture_metadata_equal(before[0], after[0], str(store.path))
            or before[1] != after[1]
            or observer.execute("pragma data_version").fetchone()[0] != version
        ):
            raise _refuse()
        if expected.snapshot_version == 3:
            published_source = publisher._published_v3_source_fingerprint
            if (
                published_source is None
                or _external_source_metadata(published_source, str(store.path))
                != _external_source_metadata(after[0], str(store.path))
                or publisher._published_v3_resident_fingerprint != after[1]
            ):
                raise _refuse()
        _remaining(deadline_monotonic)
        with store.hold_oauth_credential_lock(timeout_seconds=_remaining(deadline_monotonic)):
            store._require_oauth_connection_unlocked(connection)
            if _binding(publisher, _runtime(), deadline_monotonic) != expected:
                raise _refuse()
            yield expected
            store._require_oauth_connection_unlocked(connection)
        _remaining(deadline_monotonic)
        # Neither a native reply nor an unchanged epoch replaces fresh sources.
        _fresh_sources(publisher, expected)
        current_runtime = _runtime()
        _lane(connection, observer)
        with (
            store.hold_oauth_credential_lock(timeout_seconds=_remaining(deadline_monotonic)),
            _condition_until(publisher, deadline_monotonic),
        ):
            store._require_oauth_connection_unlocked(connection)
            # Credential reads may update WAL file metadata without a commit.
            # Sample metadata after them; independent data_version stays bound.
            current = publisher._current_input_fingerprint()
            directory = publisher._resident_directory_fingerprint()
            current_binding = _binding(publisher, current_runtime, deadline_monotonic)
            final_identity = store.path.stat()
            generation_file = f"/generation-{expected.resident_generation:020d}.json"
            if (
                current_binding != expected
                or current_binding.snapshot is not expected.snapshot
                or (final_identity.st_dev, final_identity.st_ino) != database_identity
                or not _capture_metadata_equal(after[0], current[0], str(store.path))
                or after[1] != current[1]
                or publisher._confirm_resident_fingerprint(
                    after[1],
                    current[1],
                    expected.resident_generation,
                    directory,
                )
                is None
                or not any(path.endswith(generation_file) for path, _, _ in current[1])
                or publisher._current_input_fingerprint() != current
                or observer.execute("pragma data_version").fetchone()[0] != version
                or expected.expires_at_ms <= int(publisher._wall_clock() * 1000)
            ):
                raise _refuse()
            _remaining(deadline_monotonic)
