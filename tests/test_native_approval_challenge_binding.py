"""Bind presentation challenges to the exact outgoing request reference."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_approval_bridge as api
from tests.test_native_approval_v4_transport import _challenge, _status


@pytest.mark.parametrize("entry", ["instance", "default"])
def test_outer_request_identity_is_forwarded_without_changing_raw_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    challenge = _challenge()
    challenge["request_id"] = "synthetic-outer-request"
    calls: list[dict[str, object]] = []

    def client(**kwargs: object) -> bytes:
        payload_bytes = kwargs["payload"]
        assert isinstance(payload_bytes, bytes)
        calls.append(cast(dict[str, object], json.loads(payload_bytes)))
        return json.dumps(challenge).encode()

    bridge = api.NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )
    monkeypatch.setattr(api, "_DEFAULT_BRIDGE", bridge)
    create = bridge.create_v4_challenge if entry == "instance" else api.create_native_approval_v4_challenge
    payload: dict[str, object] = {
        "event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo synthetic"},
    }
    snapshot: dict[str, object] = {
        "generation": 7,
        "policy_digest": "c" * 64,
        "runtime_identity": "a" * 64,
        "source_input_digest": "e" * 64,
    }
    session = create(
        payload=payload,
        harness="claude-code",
        guard_home=tmp_path / "guard",
        home_dir=tmp_path,
        cwd=tmp_path,
        policy_snapshot=snapshot,
        request_id="synthetic-outer-request",
        deadline=100.5,
    )
    assert session is not None and session.request_id == "synthetic-outer-request"
    assert len(calls) == 1
    request = calls[0]["request"]
    assert isinstance(request, dict)
    envelope = request["envelope"]
    assert isinstance(envelope, dict)
    assert envelope["request_id"] == "synthetic-outer-request"
    assert envelope["raw_payload"] == payload and "request_id" not in payload
    assert envelope["policy_snapshot"] == snapshot


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "synthetic-other"),
        ("harness", "codex"),
        ("policy_generation", 8),
        ("policy_digest", "0" * 64),
        ("runtime_identity", "0" * 64),
    ],
)
def test_internally_valid_alternate_challenge_is_not_bound_to_this_request(
    tmp_path: Path, field: str, value: object
) -> None:
    challenge = _challenge()
    challenge["request_id"] = "synthetic-outer-request"
    challenge[field] = value

    def client(**_kwargs: object) -> bytes:
        return json.dumps(challenge).encode()

    bridge = api.NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )
    session = bridge.create_v4_challenge(
        payload={"event": "PreToolUse", "tool_name": "Bash"},
        harness="claude-code",
        guard_home=tmp_path / "guard",
        home_dir=tmp_path,
        cwd=tmp_path,
        policy_snapshot={"generation": 7, "policy_digest": "c" * 64, "runtime_identity": "a" * 64},
        request_id="synthetic-outer-request",
        deadline=100.5,
    )
    assert session is None
    assert bridge.last_error_code == "native_approval_binding_mismatch"
