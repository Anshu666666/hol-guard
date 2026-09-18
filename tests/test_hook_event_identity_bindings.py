"""Hook identity stays stable across the CLI compatibility import boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as artifacts
from codex_plugin_scanner.guard.cli import commands_support_runtime_resolution as resolution
from codex_plugin_scanner.guard.runtime.hook_event_names import _hook_event_name
from scripts.ci import rust_io_ownership_gate as gate

SOURCE_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = "src/codex_plugin_scanner/guard/cli/commands_support_runtime_artifacts.py"
RESOLUTION = "src/codex_plugin_scanner/guard/cli/commands_support_runtime_resolution.py"
EVENTS = "src/codex_plugin_scanner/guard/runtime/hook_event_names.py"
ADAPTERS = "src/codex_plugin_scanner/guard/adapters/__init__.py"


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (" UserPromptSubmitted ", "UserPromptSubmit"),
        (" PRETOOLUSE ", "PreToolUse"),
        (" PostToolUse ", "PostToolUse"),
        (" PermissionRequest ", "PermissionRequest"),
        (" PermissionRequestV2 ", "PermissionRequest"),
        (" FutureEvent ", "FutureEvent"),
    ],
)
def test_event_aliases_and_unknown_names_preserve_wire_identity(event: str, expected: str) -> None:
    assert _hook_event_name({"event": event}) == expected


@pytest.mark.parametrize("key", ["event", "hook_event_name", "hookEventName", "hook_name"])
def test_all_supported_payload_keys_reach_the_same_identity(key: str) -> None:
    assert _hook_event_name({key: "pretooluse"}) == "PreToolUse"


@pytest.mark.parametrize("invalid", [None, 0, False, [], {}, "  "])
def test_unusable_earlier_field_does_not_hide_a_later_valid_event(invalid: object) -> None:
    assert _hook_event_name({"event": invalid, "hook_name": "posttooluse"}) == "PostToolUse"
    assert _hook_event_name({"event": invalid}) is None


def test_valid_earlier_field_keeps_existing_precedence() -> None:
    assert _hook_event_name({"event": "pretooluse", "hook_name": "posttooluse"}) == "PreToolUse"


def test_existing_cli_exports_keep_actual_function_and_adapter_identity() -> None:
    assert artifacts._hook_event_name is _hook_event_name
    assert resolution.get_adapter is get_adapter
    for adapter in list_adapters():
        assert resolution._canonical_harness_name(adapter.harness) == adapter.harness
        for alias in getattr(adapter, "aliases", ()):
            assert resolution._canonical_harness_name(alias) == adapter.harness
    assert resolution._canonical_harness_name("synthetic-unregistered-harness") == "synthetic-unregistered-harness"


def copied_records(tmp_path: Path) -> dict[tuple[str, str], list[gate.FunctionRecord]]:
    for relative in (ARTIFACTS, RESOLUTION, EVENTS, ADAPTERS):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((SOURCE_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    return gate._function_map(tmp_path)


def test_real_caller_reaches_pure_event_helper_without_wildcard_builtin_ambiguity(tmp_path: Path) -> None:
    records = copied_records(tmp_path)
    caller = records[(ARTIFACTS, "_artifact_id_from_event")][0]
    target = gate.resolve_call(tmp_path, caller, "_hook_event_name", records)
    assert target is not None and target.path == EVENTS
    assert gate.resolve_call(tmp_path, target, "isinstance", records) is None
    assert not tuple(gate._observations(target))


def test_real_harness_caller_resolves_actual_registry_function_after_wildcard_imports(tmp_path: Path) -> None:
    records = copied_records(tmp_path)
    caller = records[(RESOLUTION, "_canonical_harness_name")][0]
    target = gate.resolve_call(tmp_path, caller, "get_adapter", records)
    assert target is not None and target.path == ADAPTERS and target.qualname == "get_adapter"
