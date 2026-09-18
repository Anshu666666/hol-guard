"""Bounded, opt-in observations of the existing Claude fallback entry."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge import _FALLBACK_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.adapters.claude_hook_argv import guard_hook_command_parts
from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
    isolated_hook_environment,
    run_isolated_hook_process,
)
from tests.test_guard_claude_adapter import _build_context

_IMPORT_MODULES = (
    "codex_plugin_scanner.cli",
    "codex_plugin_scanner.guard.cli.commands",
    "codex_plugin_scanner.guard.cli.commands_parser",
    "codex_plugin_scanner.guard.cli.commands_support",
    "codex_plugin_scanner.guard.cli._commands_shared",
    "codex_plugin_scanner.guard.cli.commands_router",
    "codex_plugin_scanner.guard.cli.commands_hook",
    "codex_plugin_scanner.guard.cli.commands_hook_native_authority",
    "codex_plugin_scanner.guard.daemon.hook_worker",
    "codex_plugin_scanner.guard.runtime.runner",
)
_IMPORT_LINE = re.compile(r"import time:\s+(\d+)\s+\|\s+(\d+)\s+\|\s+(.+)")


def _import_observations(stderr: str) -> dict[str, object]:
    observations: dict[str, object] = {}
    for module in _IMPORT_MODULES:
        samples: list[tuple[int, int]] = []
        for line in stderr.splitlines():
            match = _IMPORT_LINE.fullmatch(line)
            if (
                match is not None and match.group(3).strip() == module
                and len(match.group(1)) <= 12 and len(match.group(2)) <= 12
            ):
                samples.append((int(match.group(1)), int(match.group(2))))
        observations[module] = {
            "samples": len(samples),
            "self_us": samples[0][0] if len(samples) == 1 else None,
            "cumulative_us": samples[0][1] if len(samples) == 1 else None,
        }
    return observations


def _decision(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        return "unavailable"
    hook = payload.get("hookSpecificOutput") if isinstance(payload, dict) else None
    if not isinstance(hook, dict) or hook.get("hookEventName") != "PreToolUse":
        return "unavailable"
    value = hook.get("permissionDecision")
    return value if value in ("allow", "ask", "deny") else "unavailable"


def test_import_observations_emit_only_fixed_modules_and_numeric_samples() -> None:
    stderr = (
        "private-path-and-payload\n"
        "import time:       7 |         19 | codex_plugin_scanner.guard.cli.commands\n"
        "import time:       8 |         21 | private.module\n"
        "import time: invalid | value | codex_plugin_scanner.cli\n"
    )
    result = _import_observations(stderr)
    assert result["codex_plugin_scanner.guard.cli.commands"] == {
        "samples": 1, "self_us": 7, "cumulative_us": 19,
    }
    assert result["codex_plugin_scanner.cli"] == {
        "samples": 0, "self_us": None, "cumulative_us": None,
    }
    assert "private" not in json.dumps(result)
    duplicate = "import time: 1 | 2 | codex_plugin_scanner.cli\n" * 2
    assert _import_observations(duplicate)["codex_plugin_scanner.cli"] == {
        "samples": 2, "self_us": None, "cumulative_us": None,
    }


def test_decision_observation_never_emits_payload_or_unknown_values() -> None:
    for output in ("not-json", "[]", '{"hookSpecificOutput":{"permissionDecision":"private-value"}}'):
        assert _decision(output) == "unavailable"
    assert _decision(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": "private-value",
    }})) == "ask"


@pytest.mark.parametrize("profile_imports", [False, True], ids=["original", "importtime"])
def test_existing_fallback_entry_completes_native_ask(
    tmp_path: Path,
    profile_imports: bool,
) -> None:
    context = _build_context(tmp_path)
    assert context.workspace_dir is not None
    command = guard_hook_command_parts(context)
    original_form = command[1] == "-c" and command[3:5] == ("guard", "hook")
    assert original_form is True
    if profile_imports:
        command = (command[0], "-X", "importtime", *command[1:])
    request = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(context.workspace_dir / ".env")},
    })
    started = time.monotonic_ns()
    result = run_isolated_hook_process(
        command,
        input_text=request,
        cwd=Path.home(),
        environment=isolated_hook_environment(),
        timeout_seconds=_FALLBACK_TIMEOUT_SECONDS,
    )
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    decision = _decision(result.stdout)
    native = os.environ.get("HOL_GUARD_NATIVE", "unset")
    report = {
        "observation": "direct-fallback-importtime" if profile_imports else "direct-fallback-original",
        "budget_ms": int(_FALLBACK_TIMEOUT_SECONDS * 1000),
        "elapsed_ms": elapsed_ms,
        "process": "zero" if result.returncode == 0 else "nonzero-or-unavailable",
        "timed_out": result.timed_out,
        "output_limit_exceeded": result.output_limit_exceeded,
        "containment_failed": result.containment_failed,
        "stderr_empty": result.stderr == "",
        "decision": decision,
        "native_selection": native if native in ("off", "auto", "force", "unset") else "other",
        "test_mode": os.environ.get("HOL_GUARD_TEST_MODE") == "1",
        "python_oracle_boundary": os.environ.get("HOL_GUARD_PYTHON_ORACLE") == "1",
        "imports": _import_observations(result.stderr) if profile_imports else None,
    }
    print("CLAUDE_FALLBACK_STARTUP_OBSERVATION " + json.dumps(report, sort_keys=True))
    completed = (
        result.returncode == 0 and not result.timed_out
        and not result.output_limit_exceeded and not result.containment_failed
    )
    assert completed is True
    if not profile_imports:
        stderr_empty = result.stderr == ""
        assert stderr_empty is True
    assert decision == "ask"
