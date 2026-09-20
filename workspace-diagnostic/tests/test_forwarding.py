"""Original fixture forwarding and bounded record admission controls."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from workspace_cause import child
from workspace_cause.capture import Capture
from workspace_cause.parent import FixtureForwarding
from workspace_cause.reader import read_cell, summarize, validate_cell


def valid_cell(home: Path) -> dict[str, Any]:
    capture = Capture(home)
    owner = SimpleNamespace(
        guard_home=home,
        _condition=threading.Condition(),
        _epoch=1,
        _acked=True,
        _closed=False,
        _last_error=None,
    )
    capture.call("await_ack", lambda: None, (), {}, publisher=owner, details={"deadline_from_origin_ms": 400.0})
    capture.call("await_ack", lambda: None, (), {}, publisher=owner, details={"deadline_from_origin_ms": 900.0})
    return {
        "schema": "hol-guard.workspace-cause-cell.v1",
        "scenario": "key_rotation",
        "registered_workspaces": 100,
        "original_dispatch_calls": 1,
        "matching_dispatch_calls": 1,
        "original_return": "dict",
        "original_result_flags": {
            "registered_workspaces": True,
            "scenario_matches": True,
            "passed": False,
            "status_completed": True,
            "publisher_contained": True,
            "recovered_request_present": False,
            "failure_present": True,
        },
        "setup_failed": False,
        "hooks_restored": True,
        "dispatch_patch_restored": True,
        "original_serve_exit": 0,
        "observation": capture.freeze(),
        "original_readiness_deadline_ms": 400,
        "original_result_or_exception_preserved": True,
        "additional_native_or_http_probes": 0,
        "headline_timing_eligible": False,
        "qualification_complete": False,
    }


def test_actual_records_roundtrip_without_promoting_failed_original(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    report = valid_cell(tmp_path)
    path = tmp_path / "00.json"
    child.write_report(path, report)
    returned = read_cell(path, "key_rotation")
    assert returned == report
    summary = summarize(returned)
    assert summary["original_result_flags"]["passed"] is False
    assert summary["recovered_deadline_in_dispatch_origin_ms"] == 900.0
    assert summary["acceptance_in_dispatch_origin_derived_from_original_deadline_ms"] == 500.0
    assert summary["state_transition_instant_or_exact_unwrapped_predicate_inferred"] is False


def test_unknown_keys_types_loss_and_changed_budget_are_refused(tmp_path: Path) -> None:
    paths = (
        (("observation", "overflow"), True),
        (("observation", "observation_lost"), True),
        (("observation", "calls_in_flight"), 1),
        (("original_readiness_deadline_ms",), 401),
        (("matching_dispatch_calls",), 2),
        (("hooks_restored",), False),
        (("original_result_flags", "publisher_contained"), False),
        (("registered_workspaces",), True),
        (("headline_timing_eligible",), True),
        (("private_payload",), "never admitted"),
    )
    for path, value in paths:
        report = valid_cell(tmp_path)
        current = report
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        with pytest.raises(ValueError):
            validate_cell(report, "key_rotation")


def test_duplicate_nonfinite_and_truncated_files_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "00.json"
    report = valid_cell(tmp_path)
    encoded = json.dumps(report)
    cases = (
        encoded.replace(
            '"registered_workspaces": 100', '"registered_workspaces": 100, "registered_workspaces": 100', 1
        ),
        encoded.replace('"parent": null', '"parent": NaN', 1),
        encoded[:-1],
    )
    for raw in cases:
        path.write_text(raw, encoding="utf-8")
        with pytest.raises((ValueError, json.JSONDecodeError)):
            read_cell(path, "key_rotation")


def test_bad_state_clock_and_parent_are_refused(tmp_path: Path) -> None:
    for field, value in (("call_return_ms", -1), ("parent", 0), ("finished_ms", float("inf"))):
        report = valid_cell(tmp_path)
        report["observation"]["rows"][0][field] = value
        with pytest.raises(ValueError):
            validate_cell(report, "key_rotation")
    report = valid_cell(tmp_path)
    report["observation"]["rows"][0]["after"]["sample_after_ms"] = 120000
    with pytest.raises(ValueError):
        validate_cell(report, "key_rotation")


def test_output_is_exclusive_private_bounded_and_cannot_follow_symlink(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "00.json"
    child.write_report(path, {"owned": True})
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        child.write_report(path, {"owned": False})
    assert path.read_bytes() == before and path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="bound"):
        child.write_report(tmp_path / "01.json", {"owned": "x" * child.MAX_REPORT_BYTES})
    assert not (tmp_path / "01.json").exists()
    target = tmp_path / "target"
    target.write_text("untouched", encoding="utf-8")
    (tmp_path / "02.json").symlink_to(target)
    with pytest.raises(FileExistsError):
        child.write_report(tmp_path / "02.json", {"owned": False})
    assert target.read_text(encoding="utf-8") == "untouched"


def test_dispatch_preserves_original_objects_even_when_setup_or_retention_fails(tmp_path: Path) -> None:
    fixture = SimpleNamespace(session=SimpleNamespace(guard_home=tmp_path), workspaces=tuple(range(100)))
    request = {"op": "workspace_lifecycle", "scenario": "key_rotation", "receipt_profile": "candidate"}
    result = {"status": "completed", "passed": False, "scenario": "key_rotation", "registered_workspaces": 100}
    error = RuntimeError("original error identity")
    for original_failure in (False, True):
        calls = []

        def original(
            current: Any,
            operation: str,
            forwarded: Any,
            bound_calls: list[Any] = calls,
            bound_failure: bool = original_failure,
        ) -> Any:
            bound_calls.append((current, operation, forwarded))
            if bound_failure:
                raise error
            return result

        def cannot_retain(_report: dict[str, Any]) -> None:
            raise OSError("diagnostic export failure")

        with patch.object(child.OwnedHooks, "__enter__", side_effect=RuntimeError("setup failure")):
            if original_failure:
                with pytest.raises(RuntimeError) as raised:
                    child.observe_dispatch(
                        original, fixture, "workspace_lifecycle", request, scenario="key_rotation", retain=cannot_retain
                    )
                assert raised.value is error
            else:
                assert (
                    child.observe_dispatch(
                        original, fixture, "workspace_lifecycle", request, scenario="key_rotation", retain=cannot_retain
                    )
                    is result
                )
        assert len(calls) == 1 and calls[0][0] is fixture and calls[0][2] is request


def test_successful_dispatch_restores_hooks_before_retaining_record(tmp_path: Path) -> None:
    fixture = SimpleNamespace(session=SimpleNamespace(guard_home=tmp_path), workspaces=tuple(range(100)))
    request = {"op": "workspace_lifecycle", "scenario": "key_rotation", "receipt_profile": "candidate"}
    result = {
        "status": "completed",
        "passed": False,
        "scenario": "key_rotation",
        "registered_workspaces": 100,
        "publisher_contained": True,
    }
    retained = []
    assert (
        child.observe_dispatch(
            lambda *_args: result,
            fixture,
            "workspace_lifecycle",
            request,
            scenario="key_rotation",
            retain=retained.append,
        )
        is result
    )
    assert len(retained) == 1 and retained[0]["hooks_restored"] is True
    assert retained[0]["original_result_flags"]["passed"] is False


def test_parent_changes_only_owned_entrypoint_and_preserves_spawn_and_cleanup(tmp_path: Path) -> None:
    from scripts import native_slo_daemon_fixture as module
    from scripts import native_slo_workspace_lifecycle_runner as runner

    source = Path(module.__file__).resolve().parents[1]
    runtime = tmp_path / "owned-runtime"
    environment = {"UNCHANGED": "owned fixture"}
    original_kwargs: dict[str, Any] = {
        "cwd": source,
        "environment": environment,
        "allow_windows_breakaway": False,
        "windows_kill_on_job_close": True,
        "parent_liveness": False,
    }
    spawns, exits, factories = [], [], []

    def spawn(argv: Any, **kwargs: Any) -> tuple[object, object, object]:
        spawns.append((argv, kwargs))
        return object(), object(), object()

    class Inner:
        def __enter__(self) -> Inner:
            module._spawn_hook_process(
                (
                    sys.executable,
                    "-u",
                    str(source / "scripts/native_slo_daemon_fixture.py"),
                    "--serve",
                    str(runtime),
                    "none",
                    "normal",
                    "100",
                ),
                **original_kwargs,
            )
            return self

        def __exit__(self, *args: Any) -> bool:
            exits.append(args)
            return False

    def factory(*args: Any, **kwargs: Any) -> Inner:
        factories.append((args, kwargs))
        return Inner()

    error = RuntimeError("original body")
    with patch.object(module, "_spawn_hook_process", spawn), patch.object(runner, "DaemonFixture", factory):
        forwarding = FixtureForwarding(source, tmp_path)
        with pytest.raises(RuntimeError) as raised, forwarding:
            for index in range(3):
                with runner.DaemonFixture(runtime, policy="normal", workspace_count=100):
                    if index == 2:
                        raise error
        assert raised.value is error
        assert runner.DaemonFixture is factory and module._spawn_hook_process is spawn
    assert len(factories) == len(spawns) == len(exits) == 3
    for index, (argv, kwargs) in enumerate(spawns):
        assert argv[0:2] == (sys.executable, "-u")
        assert argv[-5:] == ("--serve", str(runtime), "none", "normal", "100")
        assert argv[8] == child.SCENARIOS[index]
        assert kwargs == original_kwargs and kwargs["environment"] is environment
    assert exits[-1][1] is error
    assert forwarding.report()["patches_restored"] is True


def test_parent_refuses_changed_original_args_before_spawning(tmp_path: Path) -> None:
    source = tmp_path / "source"
    script = source / "scripts" / "native_slo_daemon_fixture.py"
    script.parent.mkdir(parents=True)
    script.write_text("# owned source marker\n", encoding="utf-8")
    forwarding = FixtureForwarding(source, tmp_path)
    original = (sys.executable, "-u", str(script), "--serve", "/owned/runtime", "none", "normal", "100")
    for altered in ((*original, "--native-phases"), (*original[:-1], "10"), (*original[:-2], "strict", "100")):
        with pytest.raises(ValueError):
            forwarding.rewrite(altered, 0)
    assert forwarding.forwarded == 0
