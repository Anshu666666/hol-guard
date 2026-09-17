"""Actual registration, child execution, response and concurrent count contracts."""

from __future__ import annotations

import copy
import json
import os
import shlex
import sys
import threading
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts import native_slo_priority_launchers as module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_priority_launchers import LauncherSession, RegisteredLauncher


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.routes: Counter[str] = Counter()

    def add(self, route: str = "native_resident") -> None:
        with self.lock:
            self.routes[route] += 1

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {"routes": dict(self.routes)}


@pytest.fixture
def session(tmp_path: Path) -> LauncherSession:
    root = tmp_path / "home with spaces 'quote 雪"
    workspace = root / "workspace"
    guard_home = root / "guard-home"
    workspace.mkdir(parents=True)
    guard_home.mkdir()
    return cast(
        LauncherSession,
        cast(
            object,
            SimpleNamespace(
                root=root,
                workspace=workspace,
                guard_home=guard_home,
                daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=Metrics()))),
            ),
        ),
    )


@pytest.fixture
def registrations(session: LauncherSession, monkeypatch: pytest.MonkeyPatch) -> tuple[RegisteredLauncher, ...]:
    # Match existing installer tests: no attestation bypass. This owned
    # executable fixture is used only for registration, never launched.
    interpreter = session.root / "owned registration interpreter"
    interpreter.write_bytes(b"qualification registration interpreter\n")
    interpreter.chmod(0o700)
    monkeypatch.setattr(codex_adapter, "_guard_python_executable", lambda: str(interpreter))
    return module.install_priority_launchers(session)


def _response(launcher: RegisteredLauncher, case: str) -> dict[str, object]:
    allowed = case == "benign"
    specific: dict[str, object] = {"hookEventName": launcher.event}
    response: dict[str, object] = {"hookSpecificOutput": specific}
    if launcher.event == "PreToolUse":
        specific["permissionDecision"] = "allow" if allowed else "deny"
        if allowed:
            response["continue"] = True
        else:
            specific["permissionDecisionReason"] = "HOL Guard blocked a destructive command before execution."
    elif not allowed:
        reason = "HOL Guard blocked this output because it contains sensitive content."
        response.update(decision="block", reason=reason, stopReason=reason, **{"continue": True})
        specific["additionalContext"] = reason
    if launcher.harness == "claude-code":
        response["policy_action"] = "allow" if allowed else "block"
        if launcher.event == "PreToolUse":
            response["reason_code"] = "native_exact_safe_command" if allowed else "native_destructive_command"
        elif not allowed:
            response.update(
                reason_code="output_secret_match",
                model_output_action="block",
                notice="warning",
                risk_summary=response["reason"],
            )
    return response


def _launcher(registrations: tuple[RegisteredLauncher, ...], harness: str, event: str) -> RegisteredLauncher:
    return next(item for item in registrations if item.harness == harness and item.event == event)


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _list(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _event_group(configuration: Mapping[str, object], event: str) -> dict[str, object]:
    return _mapping(_list(_mapping(configuration["hooks"])[event])[0])


def test_install_reads_all_four_real_registrations(registrations: tuple[RegisteredLauncher, ...]) -> None:
    assert {(item.harness, item.event) for item in registrations} == {
        ("claude-code", "PreToolUse"),
        ("claude-code", "PostToolUse"),
        ("codex", "PreToolUse"),
        ("codex", "PostToolUse"),
    }
    for item in registrations:
        assert module.registered_launcher(item.config_path, item.harness, item.event) == item
        assert len(item.registration_sha256) == 64
        if item.harness == "codex":
            configuration = module._read_configuration(item.config_path, is_toml=True)
            command = _mapping(_list(_event_group(configuration, item.event)["hooks"])[0])["command"]
            assert shlex.join(item.argv) == command
            assert "owned registration interpreter" in item.argv[0]
            assert item.environment
        else:
            configuration = json.loads(item.config_path.read_text())
            handler = configuration["hooks"][item.event][0]["hooks"][0]
            assert item.argv == (handler["command"], *handler["args"])


def test_readback_preserves_registered_arguments_and_environment(registrations: tuple[RegisteredLauncher, ...]) -> None:
    item = _launcher(registrations, "claude-code", "PreToolUse")
    configuration = json.loads(item.config_path.read_text())
    handler = configuration["hooks"][item.event][0]["hooks"][0]
    handler["args"].append("literal $() `backtick` ; 雪")
    handler["env"] = {"QUALIFICATION_LITERAL": "literal $() ; 雪"}
    item.config_path.write_text(json.dumps(configuration))
    changed = module.registered_launcher(item.config_path, item.harness, item.event)
    assert changed.argv[-1] == "literal $() `backtick` ; 雪"
    assert changed.environment == (("QUALIFICATION_LITERAL", "literal $() ; 雪"),)
    assert changed.registration_sha256 != item.registration_sha256


@pytest.mark.parametrize("kind", ("disabled", "duplicate", "http", "shell", "bad_env"))
def test_invalid_or_ambiguous_registration_fails(registrations: tuple[RegisteredLauncher, ...], kind: str) -> None:
    item = _launcher(registrations, "codex", "PreToolUse")
    configuration = dict(module._read_configuration(item.config_path, is_toml=True))
    group = _event_group(configuration, item.event)
    handler = _mapping(_list(group["hooks"])[0])
    if kind == "disabled":
        _mapping(configuration["features"])["hooks"] = False
    elif kind == "duplicate":
        _list(group["hooks"]).append(copy.deepcopy(handler))
    elif kind == "http":
        handler["type"] = "http"
    elif kind == "shell":
        assert isinstance(handler["command"], str)
        handler["command"] += " ; echo bypass"
    else:
        handler["env"] = {"bad": 1}
    item.config_path.write_text(dump_toml(configuration))
    with pytest.raises(RuntimeError, match="priority_launcher_"):
        module.registered_launcher(item.config_path, item.harness, item.event)


def test_configuration_read_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_bytes(b"x" * 1_000_001)
    with pytest.raises(RuntimeError, match="configuration_limit"):
        module.registered_launcher(path, "claude-code", "PreToolUse")


def test_all_priority_stdout_shapes_are_checked(registrations: tuple[RegisteredLauncher, ...]) -> None:
    for item in registrations:
        for case in ("benign", "block"):
            module.validate_launcher_stdout(item, _response(item, case), case=case)
            with pytest.raises(RuntimeError):
                module.validate_launcher_stdout(item, {}, case=case)
            wrong = _response(item, case)
            _mapping(wrong["hookSpecificOutput"])["hookEventName"] = "UserPromptSubmit"
            with pytest.raises(RuntimeError, match="event_mismatch"):
                module.validate_launcher_stdout(item, wrong, case=case)


def test_codex_filtered_stdout_cannot_be_treated_as_daemon_json(registrations: tuple[RegisteredLauncher, ...]) -> None:
    item = _launcher(registrations, "codex", "PostToolUse")
    response = _response(item, "block")
    assert "reason_code" not in response
    module.validate_launcher_stdout(item, response, case="block")
    with pytest.raises(RuntimeError, match="schema_mismatch"):
        module.validate_launcher_stdout(item, {**response, "reason_code": "output_secret_match"}, case="block")
    response["reason"] = "native evaluation unavailable"
    with pytest.raises(RuntimeError, match="reason_mismatch"):
        module.validate_launcher_stdout(item, response, case="block")


def test_actual_child_process_receives_payload_and_returns_stdout(session: LauncherSession, tmp_path: Path) -> None:
    # This is a real subprocess mechanics test, not installed Guard evidence.
    script = tmp_path / "child.py"
    script.write_text(
        "import json,sys\n"
        "payload=json.load(sys.stdin)\n"
        "assert payload['hook_event_name']=='PreToolUse'\n"
        "assert payload['tool_input']['command']=='pwd'\n"
        "print(json.dumps({'continue':True,'policy_action':'allow','reason_code':'native_exact_safe_command',"
        "'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'allow'}}))\n"
    )
    item = RegisteredLauncher(
        "claude-code", "PreToolUse", (sys.executable, str(script)), (), "a" * 64, tmp_path / "registration"
    )
    result = module.observe_priority_launcher(session, item, sample=3)
    assert result.allowed
    assert result.route == "pending_batch_validation"
    assert result.latency_ms > 0


@pytest.mark.parametrize("failure", ("exit", "timeout", "containment", "output_limit", "bad_json"))
def test_process_failure_is_not_a_fast_semantic_sample(
    session: LauncherSession,
    registrations: tuple[RegisteredLauncher, ...],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    item = registrations[0]
    result = BoundedHookProcessResult(0, json.dumps(_response(item, "benign")), False, False)
    changes = {
        "exit": {"returncode": 2},
        "timeout": {"timed_out": True},
        "containment": {"containment_failed": True},
        "output_limit": {"output_limit_exceeded": True},
        "bad_json": {"stdout": "not JSON"},
    }[failure]
    monkeypatch.setattr(module, "run_isolated_hook_process", lambda *_args, **_kwargs: replace(result, **changes))
    with pytest.raises(RuntimeError, match="priority_launcher_"):
        module.observe_priority_launcher(session, item, sample=1)


def test_registered_environment_applies_only_to_child(
    session: LauncherSession, registrations: tuple[RegisteredLauncher, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    item = replace(registrations[0], environment=(("QUALIFICATION_VALUE", "literal"),))
    before = dict(os.environ)
    captured: dict[str, object] = {}

    def run(argv, **kwargs):
        captured["argv"] = tuple(argv)
        captured.update(kwargs)
        return BoundedHookProcessResult(0, json.dumps(_response(item, "benign")), False, False)

    monkeypatch.setattr(module, "run_isolated_hook_process", run)
    module.observe_priority_launcher(session, item, sample=4)
    assert captured["argv"] == item.argv
    assert captured["cwd"] == session.workspace
    environment = _mapping(captured["environment"])
    assert environment["QUALIFICATION_VALUE"] == "literal"
    assert environment["HOME"] == str(session.root)
    assert dict(os.environ) == before


def test_c16_launches_overlap_and_routes_are_checked_after_wave(
    session: LauncherSession, registrations: tuple[RegisteredLauncher, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    item = registrations[0]
    active = 0
    peak = 0
    lock = threading.Lock()
    metrics = cast(Metrics, session.daemon._server.hook_worker.metrics)
    samples: list[int] = []

    def observe(_session, launcher, *, sample, case="benign", stop_event=None):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            samples.append(sample)
        time.sleep(0.02)
        metrics.add()
        with lock:
            active -= 1
        return Observation(launcher.harness, launcher.event, "small", 20.0, "pending_batch_validation", True)

    monkeypatch.setattr(module, "observe_priority_launcher", observe)
    values = module._concurrent_series(session, item, 17)
    assert len(values) == 32
    assert peak == 16
    assert len(set(samples)) == 32
    assert metrics.routes == {"native_resident": 32}


def test_concurrent_wrong_native_route_fails(
    session: LauncherSession, registrations: tuple[RegisteredLauncher, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics = cast(Metrics, session.daemon._server.hook_worker.metrics)

    def observe(_session, launcher, *, sample, case="benign", stop_event=None):
        metrics.add("python_semantic")
        return Observation(launcher.harness, launcher.event, "small", 1.0, "pending_batch_validation", True)

    monkeypatch.setattr(module, "observe_priority_launcher", observe)
    with pytest.raises(RuntimeError, match="batch left native"):
        module._concurrent_series(session, registrations[0], 2)


def test_full_measurement_preserves_counts_and_cold_boundary(
    session: LauncherSession, registrations: tuple[RegisteredLauncher, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics = cast(Metrics, session.daemon._server.hook_worker.metrics)
    monkeypatch.setattr(module, "install_priority_launchers", lambda _: registrations)

    def observe(_session, launcher, *, sample, case="benign", stop_event=None):
        metrics.add()
        return Observation(launcher.harness, launcher.event, "small", 1.0, "pending_batch_validation", case == "benign")

    monkeypatch.setattr(module, "observe_priority_launcher", observe)
    report, raw = module.measure_priority_launchers(session, {"priority_per_run": 2, "cold_per_run": 20})
    assert len(raw) == 12
    for item in registrations:
        name = f"{item.harness}.{item.event}"
        assert len(raw[f"INSTALLED_LAUNCHER.{name}"]) == 2
        assert len(raw[f"INSTALLED_LAUNCHER.c16.{name}"]) == 16
        assert len(raw[f"INSTALLED_LAUNCHER.cold.{name}"]) == 20
    assert report["cold_state"] == "fresh_launcher_process_resident_prepared"
    assert report["resident_cold_measured"] is False
    assert metrics.routes == {"native_resident": 4 * (2 + 20 + 2 + 16)}


def test_registration_drift_is_rejected_before_measurement(
    session: LauncherSession, registrations: tuple[RegisteredLauncher, ...]
) -> None:
    item = registrations[0]
    payload = json.loads(item.config_path.read_text())
    payload["hooks"][item.event][0]["hooks"][0]["args"].append("drift")
    item.config_path.write_text(json.dumps(payload))
    with pytest.raises(RuntimeError, match="registration_changed"):
        module._serial_series(session, item, 1, offset=0)


@pytest.mark.parametrize("count", (0, -1, True, 100001))
def test_bad_plan_counts_fail_before_install(session: LauncherSession, count: int) -> None:
    with pytest.raises(ValueError, match="sample_count_invalid"):
        module.measure_priority_launchers(session, {"priority_per_run": count, "cold_per_run": 2})
