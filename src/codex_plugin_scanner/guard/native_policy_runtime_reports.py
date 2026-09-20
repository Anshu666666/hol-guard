"""Fresh authenticated resident observations for off-hook runtime reports.

These are client reports, not delivery permits or remote native attestations.
The serving digest identifies the confirmed resident generation in this scope;
it is not a globally unique process-start identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial

from .native_policy_application import current_native_policy_application
from .native_policy_bundle_acceptance import NativeAcceptedPolicyBundle, accepted_policy_bundle_locked
from .native_policy_consumer_capture import NativeConsumerCapture, capture_native_consumer
from .native_policy_control_transport import _native_policy_control_request_owned, run_native_control_worker
from .native_policy_snapshot import NativePolicySnapshotPublisher
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS, NativePolicySnapshotError
from .native_policy_snapshot_control import NativeAuthorityObservation, _remaining, observe_native_authority
from .oauth_connection_authority import OAuthConnectionSnapshot
from .synced_policy import validated_synced_policy_bundle

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class NativeRuntimeReports:
    application: dict[str, object] | None = None
    delivery: dict[str, object] | None = None


def _active(cancelled: threading.Event, deadline: float) -> None:
    _remaining(deadline)
    if cancelled.is_set():
        raise NativePolicySnapshotError("native_policy_report_unavailable")


def _timestamp(milliseconds: int) -> str:
    return (
        datetime.fromtimestamp(milliseconds / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _milliseconds(value: object) -> int:
    if not isinstance(value, str):
        raise ValueError("native_policy_report_unavailable")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("native_policy_report_unavailable")
    return int(parsed.timestamp() * 1000)


def _serving_digest(observed: NativeAuthorityObservation) -> str:
    identity = {
        "runtimeIdentity": observed.runtime_identity,
        "scopeDigest": observed.scope_digest,
        "residentGeneration": str(observed.resident_generation),
    }
    return hashlib.sha256(
        b"guard.runtime-serving-generation.v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _join(captured: NativeConsumerCapture, observed: NativeAuthorityObservation) -> None:
    identity = captured.runtime.identity
    authority = observed.authority
    if (
        identity is None
        or authority is None
        or not authority.usable_snapshot
        or observed.runtime_identity != identity.sha256
        or observed.resident_generation != captured.resident_generation
        or authority.generation_floor != captured.generation
        or authority.policy_digest != captured.policy_digest
    ):
        raise NativePolicySnapshotError("native_policy_report_unavailable")


def _application(
    publisher: NativePolicySnapshotPublisher,
    captured: NativeConsumerCapture,
    accepted: NativeAcceptedPolicyBundle | None,
    bundle: dict[str, object] | None,
    *,
    workspace: str,
    device_id: str,
    common: dict[str, object],
    now_ms: int,
) -> dict[str, object] | None:
    if accepted is None or bundle is None or captured.snapshot_version != 4 or len(device_id) > 256:
        return None
    binding = accepted.binding
    bundle_hash, version = bundle.get("bundleHash"), bundle.get("bundleVersion")
    with publisher._condition:
        current = accepted_policy_bundle_locked(publisher, bundle=bundle, installation_id=device_id)
    if (
        current != accepted
        or accepted.epoch != captured.publisher_epoch
        or binding.generation != captured.generation
        or binding.policy_digest != captured.policy_digest
        or binding.source_input_digest != captured.source_input_digest
        or binding.resident_generation != captured.resident_generation
        or binding.runtime_identity != common["runtimeIdentity"]
        or binding.mode != "enforce"
        or bundle.get("workspaceId") != workspace
        or not isinstance(bundle_hash, str)
        or not bundle_hash.startswith("sha256:")
        or _DIGEST.fullmatch(bundle_hash[7:]) is None
        or type(version) is not int
        or not 1 <= version <= 9007199254740991
        or validated_synced_policy_bundle(publisher.store) != bundle
    ):
        return None
    issued = _milliseconds(bundle.get("issuedAt"))
    bounds = [accepted.expires_at_ms, captured.expires_at_ms, now_ms + 900_000]
    if bundle.get("expiresAt") is not None:
        bounds.append(_milliseconds(bundle["expiresAt"]))
    expires = min(bounds)
    if not issued <= now_ms < expires:
        return None
    return {
        "state": "current",
        "mode": "enforce",
        "workspaceId": workspace,
        "deviceId": device_id,
        "bundleHash": bundle_hash,
        "bundleVersion": version,
        "snapshotVersion": 4,
        "policyGeneration": str(captured.generation),
        "policyDigest": captured.policy_digest,
        "sourceInputDigest": captured.source_input_digest,
        **common,
        "expiresAt": _timestamp(expires),
    }


def capture_native_runtime_reports(
    publisher: NativePolicySnapshotPublisher | None,
    connection: OAuthConnectionSnapshot | None,
    *,
    device_id: object,
) -> NativeRuntimeReports:
    """One bounded native observation; final source checks precede any HTTP.

    A source-free, actually usable V3 capture can report installed restrictive
    artifact support. Application requires the exact accepted signed V4 bundle.
    Unavailable authority produces explicit withdrawals, never cached positives.
    """
    if publisher is None or connection is None or not isinstance(device_id, str):
        return NativeRuntimeReports()
    credentials = connection.credentials()
    workspace = credentials.get("workspace_id")
    if (
        not isinstance(workspace, str)
        or _UUID.fullmatch(workspace) is None
        or credentials.get("machine_id") != device_id
        or not 1 <= len(device_id) <= 1024
        or any(not 0x21 <= ord(c) <= 0x7E for c in device_id)
    ):
        return NativeRuntimeReports()
    deadline = time.monotonic() + _PUBLISH_TIMEOUT_SECONDS

    def operation(cancelled: threading.Event) -> NativeRuntimeReports:
        _active(cancelled, deadline)
        bundle = validated_synced_policy_bundle(publisher.store)
        accepted = None
        if bundle is not None:
            accepted, _ = current_native_policy_application(publisher, bundle=bundle, installation_id=device_id)
        _active(cancelled, deadline)
        with capture_native_consumer(publisher, connection=connection, deadline_monotonic=deadline) as captured:
            identity = captured.runtime.identity
            if identity is None:
                raise NativePolicySnapshotError("native_policy_report_unavailable")
            material = publisher.store._policy_integrity_secret_material(create=False)
            master = material[0]
            if not isinstance(master, bytes):
                raise NativePolicySnapshotError("native_policy_report_unavailable")
            verifier = derive_native_policy_verifier_key(master)
            del master, material
            observed = observe_native_authority(
                executable=identity.path,
                guard_home=publisher.guard_home,
                runtime_identity=identity.sha256,
                verifier_key=verifier,
                deadline_monotonic=deadline,
                challenge_nonce=secrets.token_hex(32),
                client=partial(_native_policy_control_request_owned, cancelled=cancelled),
            )
            del verifier
            _active(cancelled, deadline)
            _join(captured, observed)
            now_ms = int(time.time() * 1000)
            common: dict[str, object] = {
                "runtimeIdentity": observed.runtime_identity,
                "residentGeneration": str(observed.resident_generation),
                "servingInstanceDigest": _serving_digest(observed),
                "sourceObservedAt": _timestamp(now_ms),
            }
            application = _application(
                publisher,
                captured,
                accepted,
                bundle,
                workspace=workspace,
                device_id=device_id,
                common=common,
                now_ms=now_ms,
            )
            # The report's fixed minute must fit inside this actual capture.
            delivery = None
            if captured.expires_at_ms >= now_ms + 60_000:
                delivery = {
                    "state": "available",
                    "profileId": "guard.native-artifact-restrictive.v1",
                    "workspaceId": workspace,
                    "deviceId": device_id,
                    **common,
                    "expiresAt": _timestamp(now_ms + 60_000),
                }
            result = NativeRuntimeReports(application, delivery)
        _active(cancelled, deadline)
        return result

    try:
        result = run_native_control_worker(operation, deadline_monotonic=deadline)
    except (OSError, RuntimeError, ValueError, TypeError, NativePolicySnapshotError):
        return NativeRuntimeReports()
    return result if isinstance(result, NativeRuntimeReports) else NativeRuntimeReports()
