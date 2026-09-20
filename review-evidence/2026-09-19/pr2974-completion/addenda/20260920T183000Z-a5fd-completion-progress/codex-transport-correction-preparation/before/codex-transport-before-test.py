"""Original ingress and resume must forward the same semantic native input."""

from __future__ import annotations

import json
import time
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_bridge import _with_browser_wait_process
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import _with_remaining_hint
from codex_plugin_scanner.guard.daemon.codex_native_live_decision import _decode_hook_input
from codex_plugin_scanner.guard.daemon.server_helpers_values import _runtime_hook_remaining_hint
from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope


def _envelope(payload: dict[str, object], root: Path) -> dict[str, object]:
    encoded = _encode_hook_envelope(
        payload=payload,
        harness="codex",
        event="PreToolUse",
        guard_home=root / "guard",
        home_dir=root,
        cwd=root / "workspace",
        source_ref_external_allowed=False,
        deadline_budget_ms=2000,
        snapshot={"generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64},
    )
    assert encoded is not None
    return json.loads(encoded)


def _paths(hints: dict[str, object]) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    original: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env", "guard_remaining_ms": 17},
        "tool_use_id": "installed-corpus-fixed-native-identity",
        **hints,
    }
    bound = _with_browser_wait_process(json.dumps(original), wait_timeout_seconds=8)
    retained = json.loads(bound)
    transport = json.loads(_with_remaining_hint(bound, time.monotonic() + 2))
    assert 1 <= transport["guard_remaining_ms"] <= 2000
    assert retained == json.loads(bound) and original["tool_input"] == retained["tool_input"]
    _runtime_hook_remaining_hint(transport)
    assert "guard_remaining_ms" not in transport and "guard_remaining_seconds" not in transport
    resumed = _decode_hook_input({"hook_input": bound})
    assert resumed is not None
    return retained, transport, resumed


@pytest.mark.parametrize(
    "hints",
    ({}, {"guard_remaining_ms": 4000}, {"guard_remaining_seconds": 4},
     {"guard_remaining_ms": 4000, "guard_remaining_seconds": 4}),
    ids=("no-original-hint", "original-ms", "original-seconds", "both-original-hints"),
)
def test_resume_preserves_original_ingress_native_input(tmp_path: Path, hints: dict[str, object]) -> None:
    retained, ingress, resumed = _paths(hints)
    # The original retained hint is distinct from the HTTP transport's new
    # hint. Ingress already consumes both root aliases before native review.
    assert all(retained[key] == value for key, value in hints.items())
    assert ingress["tool_input"] == resumed["tool_input"] == {
        "command": "cat .env", "guard_remaining_ms": 17,
    }
    assert _envelope(resumed, tmp_path) == _envelope(ingress, tmp_path)


def test_resume_does_not_discard_nested_or_other_native_identity_inputs(tmp_path: Path) -> None:
    _, ingress, resumed = _paths({})
    baseline = _envelope(ingress, tmp_path)
    assert _envelope(resumed, tmp_path) == baseline
    for name, value in (("guard_remaining_ms", 18), ("command", "cat other.env")):
        changed = deepcopy(resumed)
        changed["tool_input"][name] = value
        assert _envelope(changed, tmp_path) != baseline
    changed = deepcopy(resumed)
    changed["tool_use_id"] = "different-original-correlation"
    assert _envelope(changed, tmp_path) != baseline
    assert _envelope(resumed, tmp_path / "different-home") != baseline
