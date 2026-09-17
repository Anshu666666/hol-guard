"""Expiry qualification must renew the same command authority before expiring it."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts import native_slo_expiry as expiry


@pytest.mark.parametrize(
    "with_commands,fault",
    [(False, "none"), (True, "none")]
    + [
        (True, fault)
        for fault in (
            "ack_incomplete",
            "ack_retry",
            "binding_absent",
            "generation",
            "policy_digest",
            "runtime_identity",
            "command_extensions_bound",
        )
    ],
)
def test_expiry_renews_complete_acknowledged_authority(monkeypatch, tmp_path, with_commands, fault):
    from codex_plugin_scanner.guard import (
        native_hook_edge,
        native_policy_snapshot_acked,
        native_policy_snapshot_contract,
        native_policy_snapshot_generation,
        native_resident_client,
        native_runtime,
    )

    extensions = {"schema": "synthetic-complete-command-authority", "program": {"digest": "c" * 64}}
    previous = {"generation": 1, **({"command_extensions": extensions} if with_commands else {})}
    digest, runtime_digest = "a" * 64, "b" * 64
    published = []
    captured = []
    binding = {"generation": 2, "policy_digest": digest, "runtime_identity": runtime_digest, "mode": "enforce"}
    if with_commands:
        binding["command_extensions_bound"] = True

    class Publisher:
        _thread = None
        closed = False

        def current_snapshot(self):
            return previous

        def _compiled_effective_policy(self):
            return {"guard": {"mode": "enforce"}}

        def close(self):
            self.closed = True

    publisher = Publisher()
    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=lambda *_a, **_kw: None)
    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
        store=SimpleNamespace(_policy_integrity_secret_material=lambda **_kw: (b"synthetic", None)),
        guard_home=tmp_path / "guard",
        root=tmp_path,
        workspace=tmp_path / "workspace",
    )

    def snapshot(**kwargs):
        assert publisher.closed
        assert kwargs.get("command_extensions") == (extensions if with_commands else None)
        assert kwargs["renew_after_generation"] == 1
        assert kwargs["expires_at_ms"] - kwargs["issued_at_ms"] == 3000
        value = {"generation": 2, "policy_digest": digest, "expires_at_ms": kwargs["expires_at_ms"]}
        if with_commands:
            value["command_extensions"] = extensions
        published.append(value)
        return value

    def client(**kwargs):
        captured.append(kwargs)
        if len(captured) == 1:
            assert kwargs["payload"] == b"complete-publication"
            ack = {
                "status": "accepted",
                "generation": 2,
                "policy_digest": digest,
                "idempotent": False,
                "resident_generation": 7,
            }
            if fault == "ack_incomplete":
                del ack["resident_generation"]
            if fault == "ack_retry":
                ack["status"] = "native_policy_snapshot_requires_new_generation"
            return json.dumps(ack).encode()
        assert kwargs["raw_hook_envelope"] is True
        assert kwargs["payload"] == b"expired-hook"
        return b'{"error":"snapshot_expired"}'

    def encode(**kwargs):
        assert kwargs["snapshot"] == binding
        assert kwargs["deadline_budget_ms"] == 1000
        return b"expired-hook"

    observed_binding = dict(binding)
    if fault in {"generation", "policy_digest", "runtime_identity", "command_extensions_bound"}:
        observed_binding[fault] = {
            "generation": 3,
            "policy_digest": "f" * 64,
            "runtime_identity": "f" * 64,
            "command_extensions_bound": False,
        }[fault]
    calls = iter([None if fault == "binding_absent" else observed_binding, None])
    times = iter([100.0, 104.0])
    monkeypatch.setattr(expiry.time, "time", lambda: next(times))
    monkeypatch.setattr(
        native_runtime,
        "native_runtime_status",
        lambda: SimpleNamespace(
            identity=SimpleNamespace(path=tmp_path / "runtime", sha256=runtime_digest),
            capabilities=SimpleNamespace(rule_digest="d" * 64),
        ),
    )
    monkeypatch.setattr(native_runtime, "_isolated_environment", lambda: {})

    def legacy_snapshot(
        *,
        config,
        guard_home,
        runtime_identity,
        rule_digest,
        policy_integrity_key,
        issued_at_ms,
        expires_at_ms,
        renew_after_generation,
        deadline_monotonic,
    ):
        # This is the exact legacy keyword profile: an unconditional None keyword
        # is a regression even though a permissive **kwargs stub would accept it.
        return snapshot(
            config=config,
            guard_home=guard_home,
            runtime_identity=runtime_identity,
            rule_digest=rule_digest,
            policy_integrity_key=policy_integrity_key,
            issued_at_ms=issued_at_ms,
            expires_at_ms=expires_at_ms,
            renew_after_generation=renew_after_generation,
            deadline_monotonic=deadline_monotonic,
        )

    monkeypatch.setattr(
        native_policy_snapshot_generation, "native_policy_snapshot_v3", snapshot if with_commands else legacy_snapshot
    )
    monkeypatch.setattr(
        native_policy_snapshot_contract,
        "_policy_snapshot_push_bytes_v3",
        lambda value: b"complete-publication" if value is published[0] else b"wrong",
    )
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", client)
    monkeypatch.setattr(native_policy_snapshot_acked, "acked_snapshot_binding_for_store", lambda _store: next(calls))
    monkeypatch.setattr(native_hook_edge, "_encode_hook_envelope", encode)
    if fault != "none":
        with pytest.raises(RuntimeError, match="did not authenticate"):
            expiry.expire_acknowledged_authority(session)
        assert len(captured) == 1  # Never run the raw-hook expiry probe without its exact ACK/binding.
        return
    result = expiry.expire_acknowledged_authority(session)
    assert result == {"expired_resident_authority": True, "policy_prepare_rejected": True, "refresh_suspended": True}
    assert len(captured) == 2
