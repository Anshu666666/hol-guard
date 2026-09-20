from __future__ import annotations

import copy
import hashlib
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.daemon.server_helpers_values import _runtime_hook_remaining_hint
from scripts.ci.priority_launcher_phase import projection
from scripts.ci.priority_launcher_phase.capture import json_bytes
from scripts.ci.priority_launcher_phase.projection import consumed_input_matches, exit_facts, freeze_input
from scripts.native_slo_priority_launchers import launcher_payload


def _payload(harness: str, event: str, browser: bool = False):
    payload = cast(dict[str, Any], launcher_payload(event, 0))
    if browser:
        payload.update(
            guard_codex_browser_wait_process={"pid": 2, "startToken": "posix:synthetic"},
            guard_codex_browser_wait_timeout_seconds=20,
        )
    return payload, freeze_input(payload, harness)


@pytest.mark.parametrize(
    "harness,event,browser",
    [
        ("claude-code", "PreToolUse", False),
        ("claude-code", "PostToolUse", False),
        ("codex", "PreToolUse", False),
        ("codex", "PostToolUse", False),
        ("codex", "PreToolUse", True),
    ],
    ids=["claude-pre", "claude-post", "codex-pre", "codex-post", "codex-browser"],
)
def test_actual_selected_handler_budget_consumer_preserves_closed_entry(harness, event, browser):
    payload, entry = _payload(harness, event, browser)
    original = copy.deepcopy(payload)
    entry_facts = entry.facts()
    assert server._runtime_hook_remaining_hint is _runtime_hook_remaining_hint
    assert consumed_input_matches(entry, payload) is False
    assert server._runtime_hook_remaining_hint(payload) == original["guard_remaining_ms"] / 1000.0
    assert payload == {key: value for key, value in original.items() if key != "guard_remaining_ms"}
    # This is the exact old reader failure, after the real product helper ran.
    with pytest.raises(ValueError, match="phase_payload_fields_missing"):
        freeze_input(payload, harness)
    assert consumed_input_matches(entry, payload) is True
    assert entry.facts() == entry_facts
    facts = exit_facts(entry, payload)
    assert facts["only_transport_hint_removed"] is True
    assert facts["exit_projection_valid"] is True
    assert facts["mutation_detected"] is True
    assert facts["exit_projection_sha256"] != entry_facts["entry_projection_sha256"]


@pytest.mark.parametrize(
    "mutation",
    ["command", "response", "browser-pid", "browser-token", "browser-timeout", "extra", "restore-budget", "event"],
)
def test_budget_consumption_does_not_admit_other_nested_or_top_level_changes(mutation):
    event = "PostToolUse" if mutation == "response" else "PreToolUse"
    browser = mutation.startswith("browser")
    payload, entry = _payload("codex", event, browser)
    _runtime_hook_remaining_hint(payload)
    if mutation == "command":
        payload["tool_input"]["command"] = "rm -rf /"
    elif mutation == "response":
        payload["tool_response"][0]["text"] = "changed"
    elif mutation == "browser-pid":
        payload["guard_codex_browser_wait_process"]["pid"] = 3
    elif mutation == "browser-token":
        payload["guard_codex_browser_wait_process"]["startToken"] = "posix:other"
    elif mutation == "browser-timeout":
        payload["guard_codex_browser_wait_timeout_seconds"] = 21
    elif mutation == "extra":
        payload["unexpected"] = True
    elif mutation == "restore-budget":
        payload["guard_remaining_ms"] = 5000
    else:
        payload["hook_event_name"] = "PostToolUse"
    assert consumed_input_matches(entry, payload) is False
    facts = exit_facts(entry, payload)
    assert facts["only_transport_hint_removed"] is False
    assert facts["exit_projection_valid"] is False


def test_later_live_nested_mutation_cannot_rewrite_consumed_entry_comparison():
    payload, entry = _payload("codex", "PreToolUse", True)
    facts = entry.facts()
    _runtime_hook_remaining_hint(payload)
    assert consumed_input_matches(entry, payload) is True
    payload["guard_codex_browser_wait_process"]["pid"] = 3
    assert consumed_input_matches(entry, payload) is False
    assert entry.facts() == facts


def test_exit_validity_digest_and_mutation_share_one_actual_snapshot(monkeypatch):
    payload, entry = _payload("codex", "PreToolUse", True)
    _runtime_hook_remaining_hint(payload)
    original = projection._freeze
    snapshot = original(payload)
    calls = []

    def freeze_then_mutate(value, *, depth=0, budget=None):
        result = original(value, depth=depth, budget=budget)
        if depth == 0:
            calls.append(value)
            value["guard_codex_browser_wait_process"]["pid"] = 3
        return result

    monkeypatch.setattr(projection, "_freeze", freeze_then_mutate)
    facts = exit_facts(entry, payload)
    assert calls == [payload]
    assert facts["exit_projection_sha256"] == hashlib.sha256(json_bytes(snapshot)).hexdigest()
    assert facts["exit_projection_valid"] is True
    assert facts["only_transport_hint_removed"] is True
    assert facts["mutation_detected"] is True
    assert payload["guard_codex_browser_wait_process"]["pid"] == 3
