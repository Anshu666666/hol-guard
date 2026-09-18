"""Asynchronous native policy snapshot publication barrier."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .mdm.policy import managed_policy_cache_read_only
from .native_cloud_policy_inputs import NativeCloudPolicyInputs, read_native_cloud_policy_inputs
from .native_policy_authority_read import NativeVerifiedPolicyInputs
from .native_policy_decision_context import NativePolicyDecisionContext
from .native_policy_snapshot_constants import (
    _PUBLISH_RETRY_MAX_SECONDS,
    _PUBLISH_RETRY_SECONDS,
    _PUBLISH_TIMEOUT_SECONDS,
    _RENEWAL_JITTER_MAX_SECONDS,
    _RENEWAL_LEAD_SECONDS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_publisher_context import (
    CapturedV3PublicationInputs,
    PublicationContext,
    compiled_v3_compatible_policy,
    publication_context,
)
from .native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
from .native_policy_snapshot_publisher_scoped import (
    ScopedSnapshotBinding,
    _capture_metadata_equal,
    _policy_fingerprint,
    capture_scoped_decision,
    publish_scoped,
    scoped_binding,
    scoped_result_is_current,
    scoped_rule_identity,
)
from .native_policy_snapshot_publisher_transport import _decode_ack_v3, _publish_snapshot_v3
from .native_policy_snapshot_source_requirement import refresh_source_requirement
from .native_policy_snapshot_v3_renewal import retain_source_free_v3_lease
from .native_policy_snapshot_v4_transport import NativeV4Publication
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .policy_rule_identity import PolicyRuleIdentity
    from .store import GuardStore


def _snapshot_api() -> Any:
    """Resolve the façade lazily so compatibility monkeypatches remain live."""

    from . import native_policy_snapshot

    return native_policy_snapshot


class NativePolicySnapshotPublisher(NativePolicySnapshotPublisherInputs):
    """Asynchronously publish an authenticated snapshot and expose its barrier."""

    def __init__(
        self,
        *,
        store: GuardStore,
        status_provider: Callable[[], Any] | None = None,
        client_request: Callable[..., bytes | None] | None = None,
        poll_interval_seconds: float = _PUBLISH_RETRY_SECONDS,
        wall_clock: Callable[[], float] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.guard_home = Path(store.guard_home)
        self._status_provider = status_provider
        self._client_request = client_request
        self._poll_interval_seconds = max(0.05, min(5.0, poll_interval_seconds))
        self._wall_clock = wall_clock or time.time
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self._closed = False
        self._started = False
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, object] | None = None
        self._acked = False
        self._published_v3_source_fingerprint: tuple[tuple[str, tuple[int, int, int, int] | None], ...] | None = None
        self._published_v3_resident_generation: int | None = None
        self._published_v3_resident_fingerprint: tuple[tuple[str, int, int], ...] | None = None
        self._scoped_publication_enabled = False
        self._source_authority_required = True
        self._source_memory_required = True
        self._v4_publication: NativeV4Publication | None = None
        self._v4_epoch: int | None = None
        self._v4_binding: ScopedSnapshotBinding | None = None
        self._observed_scoped_digest: str | None = None
        self._epoch = 0
        self._last_error: str | None = None
        self._published_config_digest: str | None = None
        self._published_policy_fingerprint: tuple[str, str] | None = None
        self._observed_policy_fingerprint: tuple[str, str] | None = None
        self._published_cloud_inputs = NativeCloudPolicyInputs()
        self._observed_cloud_inputs = NativeCloudPolicyInputs()
        self._renewal_due_monotonic: float | None = None
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 0
        self._workspace_paths: set[Path] = set()
        self._input_fingerprint: (
            tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]] | None
        ) = None
        api = _snapshot_api()
        with api._PUBLISHER_LOCK:
            api._PUBLISHERS.setdefault(api._publisher_key(self.guard_home), set()).add(self)
        refresh_source_requirement(self)

    def start(self) -> None:
        with self._condition:
            if self._started or self._closed:
                return
            self._started = True
        # Provision the verifier before the worker can publish.  GuardStore has
        # completed its schema setup by the time a publisher is constructed;
        # keeping this one-time key bootstrap synchronous prevents the worker
        # from racing a partially initialized ``sync_state`` table.  Effective
        # policy compilation and resident publication remain asynchronous.
        try:
            self._provision_verifier_key()
        except NativePolicySnapshotError as error:
            self._record_error(str(error))
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error) as error:
            self._record_error(type(error).__name__)
        with self._condition:
            if self._closed:
                return
            self._thread = threading.Thread(
                target=self._run,
                name="hol-guard-native-policy-publisher",
                daemon=True,
            )
            self._thread.start()
        self.request_publish()

    def close(self, *, timeout_seconds: float = 1.0) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._acked = False
            self._condition.notify_all()
        self._publish_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout_seconds))
        api = _snapshot_api()
        with api._PUBLISHER_LOCK:
            publishers = api._PUBLISHERS.get(api._publisher_key(self.guard_home))
            if publishers is not None:
                publishers.discard(self)
                if not publishers:
                    api._PUBLISHERS.pop(api._publisher_key(self.guard_home), None)

    def request_publish(self, *, require_source_authority: bool = False) -> None:
        with self._condition:
            if self._closed:
                return
            self._source_authority_required |= require_source_authority
            self._epoch += 1
            self._acked = False
            self._last_error = None
            self._renewal_due_monotonic = None
            self._renewal_after_generation = None
            self._retry_not_before_monotonic = None
            self._failure_count = 0
            self._condition.notify_all()
        self._publish_event.set()

    notify_policy_changed = request_publish

    def register_workspace(self, workspace: Path | None) -> bool:
        """Track workspace override files without reading them on a hook."""

        if workspace is None:
            return False
        candidate = self._resolved_workspace(workspace)
        with self._condition:
            if candidate in self._workspace_paths:
                return False
            self._workspace_paths.add(candidate)
            # A newly observed workspace can add a stricter local overlay.
            # Invalidate the barrier immediately so no request can continue
            # on a home-only snapshot while the overlay is being compiled.
            self._input_fingerprint = None
        self.request_publish()
        return True

    def _provision_verifier_key(self) -> None:
        material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
        if not callable(material_getter):
            raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
        material: object = None
        master_key: bytes | None = None
        try:
            material = material_getter(create=True)
            if (
                not isinstance(material, tuple)
                or len(material) != 2
                or not isinstance(material[0], bytes)
                or not isinstance(material[1], str)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
            master_key = material[0]
            provision_native_policy_verifier_key(self.guard_home, master_key)
        finally:
            # Keep the master key only for the derivation call.  The derived
            # verifier is the only value written to native runtime state.
            master_key = None
            material = None

    def _mark_expired_locked(self) -> None:
        snapshot = self._snapshot
        if not self._acked or snapshot is None:
            return
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int) or expires_at_ms > int(self._wall_clock() * 1_000):
            return
        generation = snapshot.get("generation")
        self._acked = False
        self._last_error = "native_policy_snapshot_expired"
        self._renewal_due_monotonic = None
        self._renewal_after_generation = generation if isinstance(generation, int) and generation > 0 else None
        self._retry_not_before_monotonic = self._monotonic_clock()
        self._condition.notify_all()
        self._publish_event.set()

    @staticmethod
    def _renewal_jitter_seconds(snapshot: Mapping[str, object], remaining_seconds: float) -> float:
        digest = snapshot.get("policy_digest")
        generation = snapshot.get("generation")
        if not isinstance(digest, str) or not isinstance(generation, int) or remaining_seconds <= 0:
            return 0.0
        seed = hashlib.sha256(f"{generation}:{digest}".encode("ascii")).digest()
        fraction = int.from_bytes(seed[:4], "big") / float(1 << 32)
        return min(_RENEWAL_JITTER_MAX_SECONDS, remaining_seconds * 0.05) * fraction

    def _schedule_renewal_locked(self, snapshot: Mapping[str, object]) -> None:
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int):
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        remaining_seconds = expires_at_ms / 1_000 - self._wall_clock()
        if remaining_seconds <= 0:
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        lead_seconds = min(_RENEWAL_LEAD_SECONDS, max(1.0, remaining_seconds * 0.1))
        jitter_seconds = self._renewal_jitter_seconds(snapshot, remaining_seconds)
        due_in = max(0.0, remaining_seconds - lead_seconds - jitter_seconds)
        self._renewal_due_monotonic = self._monotonic_clock() + due_in

    def is_ready(self) -> bool:
        with self._condition:
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def requires_scoped_authority(self) -> bool:
        """A scoped negotiation failure must not become availability fallback."""
        with self._condition:
            return self._scoped_publication_enabled

    @property
    def requires_policy_authority(self) -> bool:
        with self._condition:
            return self._source_authority_required or self._scoped_publication_enabled

    def current_snapshot(self) -> dict[str, object] | None:
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            return cast(dict[str, object], json.loads(json.dumps(self._snapshot)))

    def current_snapshot_binding(self) -> dict[str, object] | None:
        """Return the small immutable request binding for the hot hook path.

        The resident owns the authenticated full snapshot after publication.
        Hook requests only need the values that bind them to that resident
        snapshot; avoid serializing and copying policy rules on every hook.
        """
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            snapshot = self._snapshot
            if self._v4_publication is not None:
                return scoped_binding(self)
            return {
                "generation": snapshot.get("generation"),
                "policy_digest": snapshot.get("policy_digest"),
                "runtime_identity": snapshot.get("runtime_identity"),
                "mode": snapshot.get("mode"),
            }

    def result_binding_is_current(self, binding: Mapping[str, object]) -> bool:
        """Fence a V4 response before exposing its decision or receipt."""
        with self._condition:
            self._mark_expired_locked()
            return scoped_result_is_current(self, binding)

    def policy_rule_identity_for_result(self, binding: Mapping[str, object]) -> PolicyRuleIdentity | None:
        """Resolve only the accepted snapshot's captured canonical identity."""
        with self._condition:
            self._mark_expired_locked()
            return scoped_rule_identity(self, binding)

    def capture_policy_decision_context(
        self, binding: Mapping[str, object], receipt: object
    ) -> tuple[bool, NativePolicyDecisionContext | None]:
        return capture_scoped_decision(self, binding, receipt)

    @property
    def last_error(self) -> str | None:
        with self._condition:
            return self._last_error

    def wait_until_ready(self, deadline_monotonic: float | None = None) -> bool:
        deadline = (
            deadline_monotonic if deadline_monotonic is not None else self._monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS
        )
        with self._condition:
            while not self._closed:
                self._mark_expired_locked()
                if self._acked and self._snapshot is not None:
                    return True
                remaining = deadline - self._monotonic_clock()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    def _run(self) -> None:
        while True:
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
            fingerprint = self._current_input_fingerprint()
            if self._input_fingerprint is None:
                self._input_fingerprint = fingerprint
            elif fingerprint[1] != self._input_fingerprint[1]:
                # Resident generation files are created on every managed
                # restart. Re-push the last snapshot before a hook can rely
                # on the replacement resident's in-memory policy.
                self._input_fingerprint = fingerprint
                self.request_publish()
            elif fingerprint[0] != self._input_fingerprint[0]:
                previous_inputs = dict(self._input_fingerprint[0])
                current_inputs = dict(fingerprint[0])
                changed_paths = {
                    path
                    for path in previous_inputs.keys() | current_inputs.keys()
                    if previous_inputs.get(path) != current_inputs.get(path)
                }
                self._input_fingerprint = fingerprint
                if self._policy_input_changed(changed_paths):
                    self.request_publish()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                wait_seconds = self._poll_interval_seconds
                if self._retry_not_before_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._retry_not_before_monotonic - now),
                    )
                if self._acked and self._renewal_due_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._renewal_due_monotonic - now),
                    )
            self._publish_event.wait(timeout=wait_seconds)
            self._publish_event.clear()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                if self._acked and self._renewal_due_monotonic is not None and now >= self._renewal_due_monotonic:
                    snapshot = self._snapshot
                    generation = snapshot.get("generation") if snapshot is not None else None
                    self._renewal_due_monotonic = None
                    self._renewal_after_generation = (
                        generation if isinstance(generation, int) and generation > 0 else None
                    )
                    self._retry_not_before_monotonic = now
                    self._failure_count = 0
                should_publish = (
                    not self._closed
                    and (not self._acked or self._renewal_after_generation is not None)
                    and (self._retry_not_before_monotonic is None or now >= self._retry_not_before_monotonic)
                )
                renewal_after_generation = self._renewal_after_generation
            if should_publish:
                self._publish_once(renew_after_generation=renewal_after_generation)

    def _record_error(self, error: str) -> None:
        safe = error.strip().lower()
        if not safe or len(safe) > 128 or not all(character.isalnum() or character in "_-=,:?" for character in safe):
            safe = "native_policy_snapshot_publish_failed"
        with self._condition:
            self._last_error = safe
            expires = self._snapshot.get("expires_at_ms") if self._snapshot else None
            if not (self._acked and isinstance(expires, int) and expires > int(self._wall_clock() * 1_000)):
                self._acked = False
            self._failure_count += 1
            delay = min(
                _PUBLISH_RETRY_MAX_SECONDS,
                self._poll_interval_seconds * (2 ** min(self._failure_count - 1, 5)),
            )
            retry_seed = hashlib.sha256(f"{self._failure_count}:{safe}".encode("ascii")).digest()
            retry_fraction = int.from_bytes(retry_seed[:2], "big") / float(1 << 16)
            self._retry_not_before_monotonic = (
                self._monotonic_clock()
                + delay
                + min(
                    0.1,
                    self._poll_interval_seconds * 0.25,
                )
                * retry_fraction
            )
            self._condition.notify_all()

    def _publish_once(self, *, renew_after_generation: int | None = None) -> None:
        with self._condition:
            if self._closed:
                return
            if renew_after_generation is None:
                renew_after_generation = self._renewal_after_generation
            publish_epoch = self._epoch
        v3_capture_active = False
        v3_transport_active = False
        try:
            # Compile and validate policy asynchronously; failures keep the barrier closed.
            context = self._publication_context()
            if context is None:
                return
            identity, capabilities, master_key, config, client, cloud_inputs = context
            v3_capture_active = isinstance(cloud_inputs, CapturedV3PublicationInputs)
            if isinstance(cloud_inputs, NativeVerifiedPolicyInputs):
                try:
                    publish_scoped(self, context, publish_epoch, renew_after_generation)
                finally:
                    master_key = None
                    context = None
                return
            resident_fingerprint_before = self._current_input_fingerprint()[1]
            try:
                v3_transport_active = True
                snapshot, resident_generation = _publish_snapshot_v3(
                    publisher=self,
                    identity=identity,
                    capabilities=capabilities,
                    config=config,
                    master_key=master_key,
                    client=client,
                    renew_after_generation=renew_after_generation,
                    authority_expires_at_ms=cloud_inputs.expires_at_ms,
                )
                v3_transport_active = False
            finally:
                # The master is only an ephemeral input to derivation/signing;
                # never retain it in publisher state or an exception context.
                master_key = None
            resident_fingerprint = self._current_input_fingerprint()[1]
            resident_directory_fingerprint = self._resident_directory_fingerprint()
            with managed_policy_cache_read_only(), ExitStack() as capture:
                source_observer = None
                source_version = None
                source_fingerprint = None
                if isinstance(cloud_inputs, CapturedV3PublicationInputs):
                    source_observer = capture.enter_context(self.store._connect())
                    source_version = source_observer.execute("pragma data_version").fetchone()[0]
                    before_source = self._current_input_fingerprint()[0]
                    current_config, current_cloud_inputs = compiled_v3_compatible_policy(
                        self, allow_signed_defaults=cloud_inputs.source_identity is not None
                    )
                    source_fingerprint = self._current_input_fingerprint()[0]
                    if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                        raise NativePolicySnapshotError("native_cloud_policy_changed_during_publish")
                    if (
                        current_cloud_inputs.input_digest != cloud_inputs.input_digest
                        or _policy_fingerprint(current_config) != (snapshot["config_digest"], snapshot["mode"])
                        or not _capture_metadata_equal(
                            before_source, source_fingerprint, str(self.guard_home / "guard.db")
                        )
                        or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                    ):
                        raise NativePolicySnapshotError("native_policy_authority_changed_during_publish")
                else:
                    current_cloud_inputs = read_native_cloud_policy_inputs(self.store, now=self._wall_clock())
                    if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                        raise NativePolicySnapshotError("native_cloud_policy_changed_during_publish")
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
                        raise NativePolicySnapshotError("native_policy_snapshot_resident_changed")
                    # Resident confirmation performs filesystem reads. Source
                    # authority must still match after that observation completes.
                    if self._closed or self._epoch != publish_epoch:
                        return
                    if source_observer is not None and (
                        self._current_input_fingerprint()[0] != source_fingerprint
                        or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                    ):
                        self._acked = False
                        raise NativePolicySnapshotError("native_policy_authority_changed_during_publish")
                    # The first client request may create the resident generation
                    # state files. Treat those files as the state of this ACK,
                    # otherwise the observer loop immediately mistakes its own
                    # startup for a resident restart and withdraws the barrier
                    # under a concurrent hook. Keep the policy-input half from
                    # before publication so a config change observed during the
                    # request still forces a republish on the next poll.
                    if self._input_fingerprint is not None:
                        self._input_fingerprint = (self._input_fingerprint[0], resident_fingerprint_confirmed)
                    self._v4_publication = None
                    self._v4_epoch = None
                    self._v4_binding = None
                    self._snapshot = snapshot
                    self._published_v3_source_fingerprint = source_fingerprint
                    self._published_v3_resident_generation = resident_generation
                    self._published_v3_resident_fingerprint = resident_fingerprint_confirmed
                    self._published_config_digest = cast(str, snapshot["config_digest"])
                    self._published_policy_fingerprint = (
                        cast(str, snapshot["config_digest"]),
                        cast(str, snapshot["mode"]),
                    )
                    self._observed_policy_fingerprint = self._published_policy_fingerprint
                    self._published_cloud_inputs = cloud_inputs
                    self._observed_cloud_inputs = cloud_inputs
                    if isinstance(cloud_inputs, CapturedV3PublicationInputs):
                        self._observed_scoped_digest = cloud_inputs.input_digest
                    self._acked = True
                    self._last_error = None
                    self._renewal_after_generation = None
                    self._failure_count = 0
                    self._retry_not_before_monotonic = None
                    self._schedule_renewal_locked(snapshot)
                    self._condition.notify_all()
        except NativePolicySnapshotError as error:
            retained = (
                v3_transport_active
                and v3_capture_active
                and retain_source_free_v3_lease(
                    self, publish_epoch=publish_epoch, renew_after_generation=renew_after_generation
                )
            )
            if not retained and (
                self._scoped_publication_enabled or v3_capture_active or str(error).startswith("native_cloud_policy_")
            ):
                with self._condition:
                    self._acked = False
            self._record_error(str(error))
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error) as error:
            retained = (
                v3_transport_active
                and v3_capture_active
                and retain_source_free_v3_lease(
                    self, publish_epoch=publish_epoch, renew_after_generation=renew_after_generation
                )
            )
            if not retained and (self._scoped_publication_enabled or v3_capture_active):
                with self._condition:
                    self._acked = False
            self._record_error(type(error).__name__)

    def _publication_context(self) -> PublicationContext | None:
        return publication_context(self)

    @staticmethod
    def _decode_ack(output: bytes | None) -> dict[str, object] | None:
        return _decode_ack_v3(output)
