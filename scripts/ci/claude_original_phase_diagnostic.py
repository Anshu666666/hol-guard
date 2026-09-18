"""Observe the exact existing Claude assertion without replacing its test body."""

from __future__ import annotations

import json
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest
from claude_bridge_phase_observation import admission_flags

TARGET = (
    "tests/test_guard_claude_adapter.py::"
    "test_claude_daemon_hook_command_falls_back_to_native_ask_on_daemon_miss"
)
MARKER = "CLAUDE_ORIGINAL_PHASE_OBSERVATION "
_RECORDS: list[dict[str, object]] = []


@contextmanager
def observe_command_parts(adapter, report_path: Path):
    descriptor = vars(adapter)["_daemon_hook_command_parts"]
    original = adapter._daemon_hook_command_parts
    state = {"calls": 0, "injected": False, "shape_supported": False}
    helper = Path(__file__).with_name("claude_bridge_phase_observation.py")

    def observed(context):
        parts = original(context)
        state["calls"] += 1
        target = "raise SystemExit(main("
        supported = (
            isinstance(parts, tuple) and len(parts) == 4
            and all(isinstance(part, str) for part in parts)
            and parts[1] == "-c" and parts[2].count(target) == 1
        )
        state["shape_supported"] = supported
        if state["calls"] != 1 or not supported:
            return parts
        injection = f"import runpy;_observe=runpy.run_path({str(helper)!r})['observe_bridge_main'];"
        replacement = injection + f"raise SystemExit(_observe(main,observation_path={str(report_path)!r},"
        code = parts[2].replace(target, replacement, 1)
        state["injected"] = True
        return (parts[0], parts[1], code, parts[3])

    try:
        adapter._daemon_hook_command_parts = staticmethod(observed)
        yield state
    finally:
        adapter._daemon_hook_command_parts = descriptor


def _valid_admission(value):
    return (
        isinstance(value, dict)
        and set(value) == {"native_mode", "test_mode", "python_oracle", "native_diagnostic"}
        and value["native_mode"] in ("off", "auto", "force", "shadow", "unset", "other")
        and all(type(value[key]) is bool for key in ("test_mode", "python_oracle", "native_diagnostic"))
    )


def _read_report(path: Path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return None
        with path.open(encoding="utf-8") as source:
            text = source.read(4097)
        if len(text) > 4096:
            return None
        report = json.loads(text)
        valid = (
            isinstance(report, dict)
            and set(report) == {"events", "admission", "observation_failed", "overflow", "shared_deadline"}
            and _valid_admission(report["admission"])
            and all(type(report[key]) is bool for key in ("observation_failed", "overflow", "shared_deadline"))
            and isinstance(report["events"], list) and len(report["events"]) <= 8
            and all(
                isinstance(event, dict)
                and set(event) == {"phase", "outcome", "elapsed_ms", "incoming_remaining_ms"}
                and event["phase"] in ("daemon", "recovery", "fallback")
                and event["outcome"] in ("returned", "raised")
                and all(
                    value is None or (type(value) is int and 0 <= value <= 40_000)
                    for value in (event["elapsed_ms"], event["incoming_remaining_ms"])
                )
                for event in report["events"]
            )
        )
        return report if valid else None
    except Exception:
        return None


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    if item.nodeid != TARGET:
        return (yield)
    from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter

    original_test = getattr(item.module, TARGET.split("::")[1], None)
    tmp_path = item.funcargs.get("tmp_path")
    binding = item.obj is original_test and isinstance(tmp_path, Path)
    record = {"binding": binding, "parent_admission": admission_flags(), "report": None}
    report_path = tmp_path / "claude-phase-observation.json" if binding else None
    if report_path is None or report_path.exists():
        record["observation_available"] = False
        try:
            return (yield)
        finally:
            if not _RECORDS:
                _RECORDS.append(record)
    try:
        with observe_command_parts(ClaudeCodeHarnessAdapter, report_path) as state:
            try:
                return (yield)
            finally:
                record["command"] = dict(state)
    finally:
        record["report"] = _read_report(report_path)
        record["observation_available"] = record["report"] is not None
        if not _RECORDS:
            _RECORDS.append(record)


def pytest_terminal_summary(terminalreporter):
    for record in _RECORDS:
        terminalreporter.write_line(MARKER + json.dumps(record, sort_keys=True))
