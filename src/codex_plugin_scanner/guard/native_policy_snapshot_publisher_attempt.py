"""Bounded complete attempts behind the asynchronous publication barrier."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias

from .oauth_connection_authority import read_connection_authority

if TYPE_CHECKING:
    from .native_cloud_policy_inputs import NativeCloudPolicyInputs
    from .native_policy_authority_read import NativeVerifiedPolicyInputs
    from .native_policy_snapshot_constants import NativePolicySnapshotError
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from .oauth_connection_authority import ConnectionAuthority

SourceFingerprint: TypeAlias = tuple[tuple[str, tuple[int, int, int, int] | None], ...]


def _publication_error(reason: str) -> NativePolicySnapshotError:
    # Keep the established parent-module constructor lookup live.
    from .native_policy_snapshot_publisher import NativePolicySnapshotError

    return NativePolicySnapshotError(reason)


def _source_free(inputs: NativeCloudPolicyInputs | NativeVerifiedPolicyInputs) -> bool:
    from . import native_policy_snapshot_publisher as api

    return (
        isinstance(inputs, api.CapturedV3PublicationInputs)
        and inputs.defaults is None
        and inputs.source_identity is None
    )


def _source_files(publisher: NativePolicySnapshotPublisher, fingerprint: SourceFingerprint) -> SourceFingerprint:
    database_paths = {
        str(publisher.guard_home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")
    }
    return tuple(entry for entry in fingerprint if entry[0] not in database_paths)


@dataclass(frozen=True)
class StartupPublicationRetry:
    """Eligibility for a new attempt, never acceptance of a rejected ACK."""

    epoch: int
    deadline_monotonic: float
    input_digest: str
    policy_fingerprint: tuple[str, str]
    source_files: SourceFingerprint
    connection_authority: ConnectionAuthority

    def require_inputs(
        self,
        config: Mapping[str, object],
        inputs: NativeCloudPolicyInputs | NativeVerifiedPolicyInputs,
    ) -> None:
        from . import native_policy_snapshot_publisher as api

        if (
            not isinstance(inputs, api.CapturedV3PublicationInputs)
            or not _source_free(inputs)
            or inputs.input_digest != self.input_digest
            or api._policy_fingerprint(config) != self.policy_fingerprint
        ):
            raise _publication_error("native_policy_authority_changed_during_publish")

    def require_deadline(self) -> None:
        if time.monotonic() >= self.deadline_monotonic:
            raise _publication_error("native_policy_snapshot_deadline_exceeded")

    def require_current(self, publisher: NativePolicySnapshotPublisher) -> None:
        self.require_deadline()
        with publisher._condition:
            if publisher._closed or publisher._epoch != self.epoch or publisher._acked:
                raise _publication_error("native_policy_authority_source_changed")
        if _source_files(publisher, publisher._current_input_fingerprint()[0]) != self.source_files:
            raise _publication_error("native_policy_authority_changed_during_publish")
        with publisher.store._connect() as connection:
            authority = read_connection_authority(connection, publisher.store._oauth_local_credentials_state_key)
        if authority != self.connection_authority:
            raise _publication_error("native_policy_authority_changed_during_publish")


def _can_retry(publisher: NativePolicySnapshotPublisher, window: StartupPublicationRetry) -> bool:
    from . import native_policy_snapshot_publisher as api

    if window.connection_authority.state not in {"missing", "ready"}:
        return False
    try:
        window.require_current(publisher)
        with api.managed_policy_cache_read_only(), publisher.store._connect() as observer:
            version = observer.execute("pragma data_version").fetchone()[0]
            before = publisher._current_input_fingerprint()[0]
            config, inputs = api.compiled_v3_compatible_policy(publisher, allow_signed_defaults=False)
            after = publisher._current_input_fingerprint()[0]
            window.require_inputs(config, inputs)
            window.require_current(publisher)
            return (
                api._capture_metadata_equal(before, after, str(publisher.guard_home / "guard.db"))
                and observer.execute("pragma data_version").fetchone()[0] == version
            )
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error):
        return False


def publish_once(self: NativePolicySnapshotPublisher, *, renew_after_generation: int | None = None) -> None:
    from . import native_policy_snapshot_publisher as api

    with self._condition:
        if self._closed:
            return
        if renew_after_generation is None:
            renew_after_generation = self._renewal_after_generation
        publish_epoch = self._epoch
        initially_unacknowledged = not self._acked
    retry_state: StartupPublicationRetry | None = None
    for attempt in range(2):
        with self._condition:
            if self._closed or self._epoch != publish_epoch:
                return
        rejected_window: StartupPublicationRetry | None = None
        v3_capture_active = False
        v3_transport_active = False
        try:
            # Compile and validate policy asynchronously; failures keep the barrier closed.
            if retry_state is not None:
                retry_state.require_current(self)
            context = self._publication_context(publish_epoch=publish_epoch)
            if context is None:
                return
            cloud_inputs = context[5]
            v3_capture_active = isinstance(cloud_inputs, api.CapturedV3PublicationInputs)
            if retry_state is not None:
                retry_state.require_inputs(context[3], cloud_inputs)
                retry_state.require_current(self)
            if isinstance(cloud_inputs, api.NativeVerifiedPolicyInputs):
                try:
                    api.publish_scoped(self, context, publish_epoch, renew_after_generation)
                finally:
                    context = None
                return
            startup_boundary = None
            if (
                attempt == 0
                and initially_unacknowledged
                and renew_after_generation is None
                and isinstance(cloud_inputs, api.CapturedV3PublicationInputs)
                and _source_free(cloud_inputs)
            ):
                with self.store._connect() as connection:
                    authority = read_connection_authority(connection, self.store._oauth_local_credentials_state_key)
                startup_boundary = (
                    cloud_inputs.input_digest,
                    api._policy_fingerprint(context[3]),
                    _source_files(self, self._current_input_fingerprint()[0]),
                    authority,
                )
            resident_fingerprint_before = self._current_input_fingerprint()[1]
            try:
                v3_transport_active = True
                snapshot, resident_generation, cloud_inputs, first_client_deadline = api._publish_snapshot_v3(
                    publisher=self,
                    context=context,
                    publish_epoch=publish_epoch,
                    renew_after_generation=renew_after_generation,
                    startup_retry=retry_state,
                )
                v3_transport_active = False
            finally:
                # The master is only an ephemeral input to derivation/signing;
                # never retain it in publisher state or an exception context.
                context = None
            window = (
                StartupPublicationRetry(publish_epoch, first_client_deadline, *startup_boundary)
                if startup_boundary is not None
                else None
            )
            if retry_state is not None:
                retry_state.require_current(self)
            resident_fingerprint = self._current_input_fingerprint()[1]
            resident_directory_fingerprint = self._resident_directory_fingerprint()
            from .native_policy_snapshot_publisher import ExitStack

            with api.managed_policy_cache_read_only(), ExitStack() as capture:
                source_observer = None
                source_version = None
                source_fingerprint = None
                if isinstance(cloud_inputs, api.CapturedV3PublicationInputs):
                    source_observer = capture.enter_context(self.store._connect())
                    source_version = source_observer.execute("pragma data_version").fetchone()[0]
                    before_source = self._current_input_fingerprint()[0]
                    current_config, current_cloud_inputs = api.compiled_v3_compatible_policy(
                        self, allow_signed_defaults=cloud_inputs.source_identity is not None
                    )
                    source_fingerprint = self._current_input_fingerprint()[0]
                    if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                        raise _publication_error("native_cloud_policy_changed_during_publish")
                    if (
                        current_cloud_inputs.input_digest != cloud_inputs.input_digest
                        or api._policy_fingerprint(current_config) != (snapshot["config_digest"], snapshot["mode"])
                    ):
                        raise _publication_error("native_policy_authority_changed_during_publish")
                    if (
                        not api._capture_metadata_equal(
                            before_source, source_fingerprint, str(self.guard_home / "guard.db")
                        )
                        or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                    ):
                        if window is not None and _source_files(self, source_fingerprint) == window.source_files:
                            rejected_window = window
                        raise _publication_error("native_policy_authority_changed_during_publish")
                else:
                    current_cloud_inputs = api.read_native_cloud_policy_inputs(self.store, now=self._wall_clock())
                    if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                        raise _publication_error("native_cloud_policy_changed_during_publish")
                with self._condition:
                    # A mutation may have invalidated the barrier while this
                    # request was in flight. Do not let an older ACK make that
                    # newer policy appear ready.
                    if self._closed or self._epoch != publish_epoch:
                        return
                    # Bind the ACK to the resident observed before publication,
                    # after publication, and at the barrier commit point.
                    resident_fingerprint_confirmed = self._confirm_resident_fingerprint(
                        resident_fingerprint_before,
                        resident_fingerprint,
                        resident_generation,
                        resident_directory_fingerprint,
                    )
                    if resident_fingerprint_confirmed is None:
                        self._acked = False
                        raise _publication_error("native_policy_snapshot_resident_changed")
                    # Resident confirmation performs filesystem reads. Source
                    # authority must still match after that observation completes.
                    if self._closed or self._epoch != publish_epoch:
                        return
                    if retry_state is not None:
                        retry_state.require_current(self)
                    final_source = self._current_input_fingerprint()[0] if source_observer is not None else None
                    if source_observer is not None and (
                        final_source != source_fingerprint
                        or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                    ):
                        self._acked = False
                        if (
                            window is not None
                            and final_source is not None
                            and _source_files(self, final_source) == window.source_files
                        ):
                            rejected_window = window
                        raise _publication_error("native_policy_authority_changed_during_publish")
                    # The first client request may create the resident generation
                    # state files. Treat those files as the state of this ACK,
                    # otherwise the observer loop immediately mistakes its own
                    # startup for a resident restart and withdraws the barrier
                    # under a concurrent hook. Keep the policy-input half from
                    # before publication so a config change observed during the
                    # request still forces a republish on the next poll.
                    if retry_state is not None:
                        retry_state.require_deadline()
                    if self._input_fingerprint is not None:
                        self._input_fingerprint = (self._input_fingerprint[0], resident_fingerprint_confirmed)
                    self._v4_publication = None
                    self._v4_epoch = None
                    self._v4_binding = None
                    self._snapshot = snapshot
                    self._published_v3_source_fingerprint = source_fingerprint
                    self._published_v3_resident_generation = resident_generation
                    self._published_v3_resident_fingerprint = resident_fingerprint_confirmed
                    from .native_policy_snapshot_publisher import cast

                    self._published_config_digest = cast(str, snapshot["config_digest"])
                    self._published_policy_fingerprint = (
                        cast(str, snapshot["config_digest"]),
                        cast(str, snapshot["mode"]),
                    )
                    self._observed_policy_fingerprint = self._published_policy_fingerprint
                    self._published_cloud_inputs = cloud_inputs
                    self._observed_cloud_inputs = cloud_inputs
                    if isinstance(cloud_inputs, api.CapturedV3PublicationInputs):
                        self._observed_scoped_digest = cloud_inputs.input_digest
                    self._acked = True
                    self._last_error = None
                    self._renewal_after_generation = None
                    self._failure_count = 0
                    self._retry_not_before_monotonic = None
                    self._schedule_renewal_locked(snapshot)
                    self._condition.notify_all()
            return
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, api.sqlite3.Error) as error:
            context = None
            # Only our own rejected post-ACK window can start a new publication.
            # The provisional ACK is discarded; no final validation is relaxed.
            if attempt == 0 and rejected_window is not None and _can_retry(self, rejected_window):
                retry_state = rejected_window
                continue
            api.record_publication_error(
                self,
                error=error,
                publish_epoch=publish_epoch,
                renew_after_generation=renew_after_generation,
                v3_capture_active=v3_capture_active,
                v3_transport_active=v3_transport_active,
            )
            return
