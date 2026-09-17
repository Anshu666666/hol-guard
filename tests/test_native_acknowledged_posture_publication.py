"""Connect ACK publication/expiry to the request delivery posture contract.

The real snapshot builder/ACK decoder/barrier run with an injected resident
transport. This is source contract evidence, not installed native execution.
"""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher

from . import test_native_acknowledged_posture as posture_tests
from .native_policy_snapshot_test_fixtures import _ack, _config, _DeterministicClock, _status

setup_worker = posture_tests.setup_worker
_review = posture_tests._review


@pytest.mark.parametrize("incoming", ["observe", "enforce"])
@pytest.mark.parametrize("fault", ["missing", "digest", "epoch", "resident"])
def test_transition_delivery_opens_only_after_matching_current_ack(
    setup_worker, tmp_path, monkeypatch, incoming, fault
):
    worker, store, state = setup_worker
    clock = _DeterministicClock()
    old = "enforce" if incoming == "observe" else "observe"
    publication = {"mode": old, "fault": None}
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"p" * 32, "test-master"))

    def client(**kwargs):
        # Even though the signed candidate has been built and offered, it is
        # not a delivery-mode binding until this exact ACK is committed.
        assert publisher.current_snapshot_binding() is None
        payload = kwargs["payload"]
        assert json.loads(payload)["request"]["snapshot"]["mode"] == publication["mode"]
        current_fault = publication["fault"]
        if current_fault == "missing":
            return None
        if current_fault == "epoch":
            publisher.request_publish()
        ack = json.loads(_ack(payload, resident_generation=2 if current_fault == "resident" else 1))
        if current_fault == "digest":
            ack["policy_digest"] = "f" * 64
        return json.dumps(ack).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._provision_verifier_key()
    resident_dir = store.guard_home / "native-runtime" / "resident-v3-posture"
    resident_dir.mkdir(mode=0o700)
    (resident_dir / "generation-1.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        publisher,
        "_compiled_effective_policy",
        lambda: {
            **_config(),
            "mode": publication["mode"],
            "protection_posture": "watch" if publication["mode"] == "observe" else "protected",
        },
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_a, **_k: publisher.current_snapshot_binding())
    state["edge"]["result"].update(minimum_action="block", policy_action="block")
    try:
        publisher._publish_once()
        first = publisher.current_snapshot_binding()
        assert first is not None and first["mode"] == old, publisher.last_error
        assert _review(worker, tmp_path)["hookSpecificOutput"]["permissionDecision"] == (
            "allow" if old == "observe" else "deny"
        )

        publication.update(mode=incoming, fault=fault)
        publisher.request_publish()
        assert publisher.current_snapshot_binding() is None
        publisher._publish_once()
        assert publisher.current_snapshot_binding() is None
        assert not publisher.is_ready()

        publication["fault"] = None
        publisher.request_publish()
        publisher._publish_once()
        second = publisher.current_snapshot_binding()
        assert second is not None and second["mode"] == incoming
        assert second["generation"] > first["generation"]
        assert second["policy_digest"] != first["policy_digest"]
        assert _review(worker, tmp_path)["hookSpecificOutput"]["permissionDecision"] == (
            "allow" if incoming == "observe" else "deny"
        )

        # Expiry withdraws both the snapshot and its delivery posture proof.
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        clock.wall = snapshot["expires_at_ms"] / 1000 + 1
        assert publisher.current_snapshot_binding() is None
        assert not publisher.is_ready()
    finally:
        publisher.close()
