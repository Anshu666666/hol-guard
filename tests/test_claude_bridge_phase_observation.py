"""Real Claude bridge timing without changing its phase arguments or deadline."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from claude_bridge_phase_observation import MARKER, observe_bridge_main

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter, _shell_command
from tests.test_guard_claude_adapter import _build_context

_NAMES = ("_post_to_loopback_daemon", "_run_recovery_command", "_run_local_fallback")


def test_phase_observer_preserves_arguments_results_and_restores_functions(monkeypatch, capsys) -> None:
    token = object()
    result = object()
    calls = []
    deadline = 1_000_000_000.0

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    for name in _NAMES:
        monkeypatch.setattr(bridge, name, original)

    def main(*, unchanged):
        assert unchanged is token
        for name in _NAMES:
            assert getattr(bridge, name)(token, deadline=deadline) is result
        return result

    assert observe_bridge_main(main, unchanged=token) is result
    assert calls == [((token,), {"deadline": deadline})] * 3
    assert all(getattr(bridge, name) is original for name in _NAMES)
    output = capsys.readouterr()
    assert output.out == ""
    report = json.loads(output.err.removeprefix(MARKER))
    assert [event["phase"] for event in report["events"]] == ["daemon", "recovery", "fallback"]
    assert all(event["outcome"] == "returned" for event in report["events"])
    assert report["shared_deadline"] is True
    assert report["observation_failed"] is False
    assert report["overflow"] is False


def test_phase_observer_preserves_exception_identity_and_restores_functions(monkeypatch, capsys) -> None:
    error = RuntimeError("synthetic-private-detail")

    def original(*args, **kwargs):
        raise error

    for name in _NAMES:
        monkeypatch.setattr(bridge, name, original)

    def main():
        return bridge._run_local_fallback(
            "synthetic-private-argument", "synthetic-private-input", ("synthetic-private-command",),
            deadline=1_000_000_000.0,
        )

    with pytest.raises(RuntimeError) as caught:
        observe_bridge_main(main)
    assert caught.value is error
    assert all(getattr(bridge, name) is original for name in _NAMES)
    output = capsys.readouterr()
    assert output.out == ""
    assert "synthetic-private" not in output.err
    report = json.loads(output.err.removeprefix(MARKER))
    assert report["events"][0]["outcome"] == "raised"
    assert set(report) == {"events", "observation_failed", "overflow", "shared_deadline"}
    assert set(report["events"][0]) == {"phase", "outcome", "elapsed_ms", "incoming_remaining_ms"}


def test_original_daemon_miss_path_with_observed_phase_budget(tmp_path: Path) -> None:
    context = _build_context(tmp_path)
    assert context.workspace_dir is not None
    adapter = ClaudeCodeHarnessAdapter()
    original = adapter._daemon_hook_command_parts(context)
    original_shell_matches = _shell_command(original) == adapter._daemon_hook_command(context)
    assert original_shell_matches is True
    target = "raise SystemExit(main("
    original_shape = len(original) == 4 and original[1] == "-c" and original[2].count(target) == 1
    assert original_shape is True
    observer = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "claude_bridge_phase_observation.py"
    injection = f"import runpy;_observe=runpy.run_path({str(observer)!r})['observe_bridge_main'];"
    observed_code = original[2].replace(target, injection + "raise SystemExit(_observe(main,", 1)
    command = (original[0], original[1], observed_code, original[3])
    result = subprocess.run(
        ["/bin/sh", "-c", _shell_command(command)],
        input=json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(context.workspace_dir / ".env")},
        }),
        text=True,
        capture_output=True,
        timeout=40,
        check=False,
    )
    reports = [line.removeprefix(MARKER) for line in result.stderr.splitlines() if line.startswith(MARKER)]
    exactly_one_report = len(reports) == 1
    assert exactly_one_report is True
    report = json.loads(reports[0])
    valid_shape = (
        isinstance(report, dict) and set(report) == {"events", "observation_failed", "overflow", "shared_deadline"}
        and isinstance(report["events"], list) and len(report["events"]) <= 8
        and all(isinstance(report[key], bool) for key in ("observation_failed", "overflow", "shared_deadline"))
        and all(isinstance(event, dict)
            and set(event) == {"phase", "outcome", "elapsed_ms", "incoming_remaining_ms"}
            and event["phase"] in ("daemon", "recovery", "fallback")
            and event["outcome"] in ("returned", "raised")
            and all(value is None or (isinstance(value, int) and 0 <= value <= 40_000)
                for value in (event["elapsed_ms"], event["incoming_remaining_ms"]))
            for event in report["events"])
    )
    assert valid_shape is True
    payload = json.loads(result.stdout)
    hook = payload.get("hookSpecificOutput") if isinstance(payload, dict) else None
    hook_valid = isinstance(hook, dict) and hook.get("hookEventName") == "PreToolUse"
    decision = hook.get("permissionDecision") if hook_valid else None
    reason = hook.get("permissionDecisionReason") if hook_valid else None
    summary = {
        **report,
        "decision": decision if decision in ("allow", "ask", "deny") else "unavailable",
        "fallback_timeout_marker": isinstance(reason, str) and "; fallback timed out" in reason,
        "process_zero": result.returncode == 0,
        "other_stderr_present": any(line and not line.startswith(MARKER) for line in result.stderr.splitlines()),
    }
    print(MARKER + json.dumps(summary, sort_keys=True))
    assert summary["process_zero"] is True
    assert hook_valid is True
    assert summary["observation_failed"] is False
    assert summary["overflow"] is False
    assert summary["decision"] == "ask"
