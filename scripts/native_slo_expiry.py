"""Publish and observe a real expired resident authority in a private fixture."""

from __future__ import annotations

import json
import time
from typing import Any


def expire_acknowledged_authority(session: Any) -> dict[str, bool]:
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store
    from codex_plugin_scanner.guard.native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
    from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _decode_ack_v3
    from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import _isolated_environment, native_runtime_status
    from scripts.native_benchmark_oracle import synthetic_payload

    worker = session.daemon._server.hook_worker
    publisher = worker.policy_snapshot_publisher
    previous = publisher.current_snapshot()
    if previous is None:
        raise RuntimeError("expiry fixture requires an acknowledged starting generation")
    config = publisher._compiled_effective_policy()
    publisher.close()  # Suspend renewal; this alone is not evidence of expiry.
    if publisher._thread is not None and publisher._thread.is_alive():
        raise RuntimeError("expiry fixture could not suspend publication")
    status = native_runtime_status()
    if status.identity is None or status.capabilities is None:
        raise RuntimeError("expiry fixture runtime unavailable")
    material = session.store._policy_integrity_secret_material(create=False)
    if not isinstance(material, tuple) or not isinstance(material[0], bytes):
        raise RuntimeError("expiry fixture signing material unavailable")
    issued = int(time.time() * 1000)
    expires = issued + 3_000
    try:
        snapshot = native_policy_snapshot_v3(
            config=config,
            guard_home=session.guard_home,
            runtime_identity=status.identity.sha256,
            rule_digest=status.capabilities.rule_digest,
            policy_integrity_key=material[0],
            issued_at_ms=issued,
            expires_at_ms=expires,
            renew_after_generation=int(previous["generation"]),
            deadline_monotonic=time.monotonic() + 2.0,
        )
    finally:
        material = None
    if snapshot.get("expires_at_ms") != expires or snapshot["generation"] <= previous["generation"]:
        raise RuntimeError("expiry fixture reused a long-lived generation")
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=session.guard_home,
        environment=_isolated_environment(),
        payload=_policy_snapshot_push_bytes_v3(snapshot),
        deadline_monotonic=time.monotonic() + 2.0,
    )
    ack = _decode_ack_v3(output)
    binding = acked_snapshot_binding_for_store(session.store)
    if (
        ack is None
        or ack.get("status") != "accepted"
        or ack.get("generation") != snapshot["generation"]
        or ack.get("policy_digest") != snapshot["policy_digest"]
        or binding is None
        or binding.get("generation") != snapshot["generation"]
    ):
        raise RuntimeError("expiry fixture did not authenticate its short-lived publication")
    while int(time.time() * 1000) <= expires:
        time.sleep(0.01)
    if acked_snapshot_binding_for_store(session.store) is not None:
        raise RuntimeError("expired resident authority remained valid")
    encoded = _encode_hook_envelope(
        payload=synthetic_payload(0),
        harness="claude-code",
        event="PostToolUse",
        guard_home=session.guard_home,
        home_dir=session.root,
        cwd=session.workspace,
        source_ref_external_allowed=False,
        deadline_budget_ms=1000,
        snapshot=binding,
    )
    if encoded is None:
        raise RuntimeError("expiry probe envelope unavailable")
    rejected = native_resident_client_request(
        executable=status.identity.path,
        guard_home=session.guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        raw_hook_envelope=True,
        deadline_monotonic=time.monotonic() + 1.0,
    )
    response = json.loads(rejected) if rejected else None
    if not isinstance(response, dict) or response.get("error") != "snapshot_expired":
        raise RuntimeError("resident did not explicitly reject the expired authority")
    prepared = worker.prepare_workspace_policy(session.workspace, deadline=time.monotonic() + 0.4)
    return {
        "expired_resident_authority": True,
        "policy_prepare_rejected": prepared is None,
        "refresh_suspended": publisher.closed and (publisher._thread is None or not publisher._thread.is_alive()),
    }
