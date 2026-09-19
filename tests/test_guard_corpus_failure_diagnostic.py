"""Controls for the real pinned runner's terminal-only diagnostic boundary."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests import guard_command_corpus_runner as runner
from tests import guard_corpus_failure_diagnostic as diagnostic


def admitted(monkeypatch):
    monkeypatch.setenv(diagnostic.OPT_IN, "1")
    monkeypatch.setitem(runner.__dict__, "__name__", "__main__")
    monkeypatch.setattr(sys, "argv", [str(Path(runner.__file__).resolve())])


def caught(action):
    try:
        action()
    except BaseException as error:
        return error, error.__traceback__
    raise AssertionError("the control must fail")


def test_disabled_gate_does_not_read_source_or_change_hook(monkeypatch):
    monkeypatch.delenv(diagnostic.OPT_IN, raising=False)
    reads = []
    monkeypatch.setattr(Path, "read_bytes", lambda self: reads.append(True))
    before = sys.excepthook
    assert diagnostic.install_terminal_hook(runner.__dict__) is False
    assert reads == []
    assert sys.excepthook is before


def test_wrong_runner_and_source_refuse_installation(monkeypatch):
    admitted(monkeypatch)
    before = sys.excepthook
    monkeypatch.setattr(sys, "argv", ["other-private-canary.py"])
    assert diagnostic.install_terminal_hook(runner.__dict__) is False
    monkeypatch.setattr(sys, "argv", [runner.__file__])
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"changed source")
    assert diagnostic.install_terminal_hook(runner.__dict__) is False
    assert sys.excepthook is before


@pytest.mark.parametrize("error_type", [PermissionError, RuntimeError])
def test_source_read_error_preserves_original_hook(monkeypatch, error_type):
    admitted(monkeypatch)
    before = sys.excepthook

    def denied(_self):
        raise error_type("private-canary")

    monkeypatch.setattr(Path, "read_bytes", denied)
    assert diagnostic.install_terminal_hook(runner.__dict__) is False
    assert sys.excepthook is before


def test_real_worker_import_failure_is_finite_and_retains_identity(monkeypatch):
    original = RuntimeError("private-canary@example.invalid /private/canary --token=canary")

    def fail():
        raise original

    monkeypatch.setattr(runner, "_install_evaluator_packages", fail)
    error, terminal = caught(lambda: runner._worker_report(2, 4))
    value = diagnostic.project_failure(error, terminal, runner.__dict__)
    assert error is original
    assert value["kind"] == "RuntimeError"
    assert value["phase"] == "worker-import"
    assert value["worker"] == 2
    assert value["mismatchCases"] is None
    assert "canary" not in json.dumps(value)


def test_real_worker_decoder_failure_projects_only_its_phase():
    error, terminal = caught(lambda: runner._decode_worker('{"private-canary": true}'))
    value = diagnostic.project_failure(error, terminal, runner.__dict__)
    assert value["kind"] == "ValueError"
    assert value["phase"] == "worker-decode"
    assert "canary" not in json.dumps(value)
    foreign = diagnostic.project_failure(error, terminal, dict(runner.__dict__))
    assert foreign["phase"] == "unknown"
    raw = json.dumps(
        {"groups": {"owner": ["private-canary", "private-canary"], "next": False}, "elapsed": 1, "rss_mib": 2}
    )
    counted_error, counted_trace = caught(lambda: runner._decode_worker(raw))
    counted = diagnostic.project_failure(counted_error, counted_trace, runner.__dict__)
    assert counted["mismatchGroups"] == 1 and counted["mismatchCases"] == 2
    assert "canary" not in json.dumps(counted)


def test_real_worker_subprocess_preserves_child_marker_and_original_arguments(monkeypatch):
    child_error, child_trace = caught(lambda: runner._decode_worker("{}"))
    child = diagnostic.project_failure(child_error, child_trace, runner.__dict__)
    raw = diagnostic.MARKER + json.dumps(child) + "\n"
    original = subprocess.CalledProcessError(1, ["private-canary"], stderr=raw)
    calls = []

    def fail(args, **kwargs):
        calls.append((args, kwargs))
        raise original

    monkeypatch.setattr(runner.subprocess, "run", fail)
    error, terminal = caught(lambda: runner._run_worker(3))
    value = diagnostic.project_failure(error, terminal, runner.__dict__)
    assert error is original
    assert value["kind"] == "CalledProcessError"
    assert value["phase"] == "worker-subprocess"
    assert value["exit"] == 1 and value["worker"] == 3
    assert value["child"] == child
    assert calls == [
        (
            [sys.executable, str(Path(runner.__file__).resolve()), "--worker", "3"],
            {"check": True, "capture_output": True, "text": True, "timeout": 60},
        )
    ]
    assert "canary" not in json.dumps(value)


def test_marker_parser_rejects_spoofs_duplicates_oversize_and_unknown_fields():
    error, terminal = caught(lambda: runner._decode_worker("{}"))
    value = diagnostic.project_failure(error, terminal, runner.__dict__)
    valid = diagnostic.MARKER + json.dumps(value)
    assert diagnostic.read_marker(valid) == value
    invalid = [
        valid + "\n" + valid,
        "x" * 65537,
        diagnostic.MARKER + "x" * 2049,
        diagnostic.MARKER + "{",
        diagnostic.MARKER + json.dumps({**value, "private-canary": True}),
        diagnostic.MARKER + json.dumps({**value, "producer": "other"}),
        diagnostic.MARKER + json.dumps({**value, "kind": ["private-canary"]}),
        diagnostic.MARKER + json.dumps({**value, "worker": True}),
        diagnostic.MARKER + json.dumps({**value, "child": {"private-canary": True}}),
    ]
    assert all(diagnostic.read_marker(item) is None for item in invalid)


@pytest.mark.parametrize("failure", ["none", "output", "projector"])
def test_terminal_hook_delegates_identical_exception_once(monkeypatch, failure):
    admitted(monkeypatch)
    calls = []
    monkeypatch.setattr(sys, "excepthook", lambda *args: calls.append(args))
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    assert diagnostic.install_terminal_hook(runner.__dict__) is True
    hook = sys.excepthook
    error, terminal = caught(lambda: runner._decode_worker("{}"))

    def fail(*_args):
        raise RuntimeError("private-canary")

    if failure == "output":
        monkeypatch.setattr(stream, "write", fail)
    elif failure == "projector":
        monkeypatch.setattr(diagnostic, "project_failure", fail)
    hook(type(error), error, terminal)
    assert calls == [(type(error), error, terminal)]
    if failure == "none":
        assert diagnostic.read_marker(stream.getvalue())["phase"] == "worker-decode"
    else:
        assert stream.getvalue() == ""


def test_successful_original_decoder_has_no_observer_output(monkeypatch):
    admitted(monkeypatch)
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    monkeypatch.setattr(sys, "excepthook", lambda *_args: None)
    assert diagnostic.install_terminal_hook(runner.__dict__) is True
    value = runner._decode_worker('{"groups": {}, "elapsed": 0.1, "rss_mib": 1}')
    assert value == {"groups": {}, "elapsed": 0.1, "rss_mib": 1.0}
    assert stream.getvalue() == ""
