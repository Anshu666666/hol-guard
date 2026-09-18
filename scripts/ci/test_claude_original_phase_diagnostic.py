"""Noninterference controls for the original-node phase diagnostic."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import claude_original_phase_diagnostic as diagnostic
import pytest
from claude_bridge_phase_observation import observe_bridge_main

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge

_NAMES = ("_post_to_loopback_daemon", "_run_recovery_command", "_run_local_fallback")


def test_phase_report_preserves_real_arguments_results_and_streams(monkeypatch, tmp_path, capsys):
    token = object()
    result = object()
    calls = []
    deadline = time.monotonic() + 8
    report_path = tmp_path / "report.json"
    monkeypatch.setenv("HOL_GUARD_NATIVE", "synthetic-private-detail")

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

    assert observe_bridge_main(main, observation_path=str(report_path), unchanged=token) is result
    assert calls == [((token,), {"deadline": deadline})] * 3
    assert all(getattr(bridge, name) is original for name in _NAMES)
    output = capsys.readouterr()
    assert output.out == output.err == ""
    report = diagnostic._read_report(report_path)
    assert report is not None
    assert report["admission"]["native_mode"] == "other"
    assert report["shared_deadline"] is True
    assert report["observation_failed"] is False
    assert report["overflow"] is False
    assert [event["phase"] for event in report["events"]] == ["daemon", "recovery", "fallback"]
    assert "synthetic-private-detail" not in report_path.read_text()


def test_phase_report_preserves_exception_identity_and_restores(monkeypatch, tmp_path, capsys):
    error = RuntimeError("synthetic-private-error")

    def original(*args, **kwargs):
        raise error

    for name in _NAMES:
        monkeypatch.setattr(bridge, name, original)

    def main():
        return bridge._run_local_fallback("private", "private", ("private",), deadline=time.monotonic() + 8)

    report_path = tmp_path / "report.json"
    with pytest.raises(RuntimeError) as caught:
        observe_bridge_main(main, observation_path=str(report_path))
    assert caught.value is error
    assert all(getattr(bridge, name) is original for name in _NAMES)
    output = capsys.readouterr()
    assert output.out == output.err == ""
    report = diagnostic._read_report(report_path)
    assert report is not None and report["events"][0]["outcome"] == "raised"
    assert "private" not in report_path.read_text()


@pytest.mark.parametrize("raises", [False, True])
def test_exact_node_preserves_call_boundary_and_restores_descriptor(monkeypatch, tmp_path, raises):
    from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter

    token = object()
    original_parts = ("python", "-c", "raise SystemExit(main(query='unchanged'))", "opaque-config")
    calls = []

    def original(context):
        calls.append(context)
        return original_parts

    descriptor = staticmethod(original)
    monkeypatch.setattr(ClaudeCodeHarnessAdapter, "_daemon_hook_command_parts", descriptor)
    monkeypatch.setattr(diagnostic, "_RECORDS", [])

    def existing_test():
        pass

    item = SimpleNamespace(
        nodeid=diagnostic.TARGET,
        module=SimpleNamespace(**{diagnostic.TARGET.split("::")[1]: existing_test}),
        obj=existing_test,
        funcargs={"tmp_path": tmp_path},
    )
    hook = diagnostic.pytest_runtest_call(item)
    next(hook)
    observed = ClaudeCodeHarnessAdapter._daemon_hook_command_parts(token)
    assert calls == [token]
    assert observed[0:2] == original_parts[0:2] and observed[3] == original_parts[3]
    assert observed[2].endswith("query='unchanged'))")
    assert "observation_path=" in observed[2]
    error = RuntimeError("synthetic-private-error")
    if raises:
        with pytest.raises(RuntimeError) as caught:
            hook.throw(error)
        assert caught.value is error
    else:
        result = object()
        with pytest.raises(StopIteration) as caught:
            hook.send(result)
        assert caught.value.value is result
    assert vars(ClaudeCodeHarnessAdapter)["_daemon_hook_command_parts"] is descriptor
    record = diagnostic._RECORDS[0]
    assert record["binding"] is True
    assert record["command"] == {"calls": 1, "injected": True, "shape_supported": True}
    assert record["observation_available"] is False
    assert "synthetic-private-error" not in json.dumps(record)


def test_unrelated_node_and_unsupported_command_remain_unchanged(tmp_path):
    token = object()
    result = object()
    hook = diagnostic.pytest_runtest_call(SimpleNamespace(nodeid="unrelated"))
    next(hook)
    with pytest.raises(StopIteration) as caught:
        hook.send(result)
    assert caught.value.value is result

    class Adapter:
        @staticmethod
        def _daemon_hook_command_parts(context):
            assert context is token
            return result

    descriptor = vars(Adapter)["_daemon_hook_command_parts"]
    with diagnostic.observe_command_parts(Adapter, tmp_path / "report.json") as state:
        assert Adapter._daemon_hook_command_parts(token) is result
        assert state == {"calls": 1, "injected": False, "shape_supported": False}
    assert vars(Adapter)["_daemon_hook_command_parts"] is descriptor


def test_report_refuses_private_fields_and_oversized_data(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"private": "synthetic-private-value"}))
    assert diagnostic._read_report(path) is None
    path.write_text("x" * 4097)
    assert diagnostic._read_report(path) is None
