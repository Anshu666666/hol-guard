"""Exercise output, source, and observer boundaries before the hosted proof."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

from heredoc_proof_common import (
    GENERATOR, check_sources, exception_metadata, git_blob, private_output, source_id,
)
from heredoc_proof_observer import executed_source_binding, metric_observer


def output_control():
    with private_output() as captured:
        print("private-python-stdout")
        print("private-python-stderr", file=sys.stderr)
        os.write(1, b"private-fd-stdout\n")
        os.write(2, b"private-fd-stderr\n")
        sys.stdout.flush()
        sys.stderr.flush()
        captured.seek(0)
        value = captured.read()
        assert all(marker in value for marker in (
            "private-python-stdout", "private-python-stderr",
            "private-fd-stdout", "private-fd-stderr",
        ))


def exception_control():
    class Unprintable:
        def __str__(self):
            raise AssertionError("private_argument_stringified")

        def __repr__(self):
            raise AssertionError("private_argument_rendered")

    assert exception_metadata(ValueError("resource_receipt_failed")) == {
        "class": "ValueError", "diagnosticCode": "resource_receipt_failed",
    }
    for error in (
        ValueError(Unprintable()), ValueError("private-sentinel"),
        ValueError("resource_receipt_failed\nprivate-sentinel"),
        ValueError("resource_receipt_failed", "private-sentinel"),
    ):
        assert exception_metadata(error) == {"class": "ValueError"}
    error = type("private-class", (ValueError,), {})("resource_receipt_failed")
    assert exception_metadata(error) == {"class": "OtherException"}


def fixture_call():
    root = Path.cwd().resolve()
    command = [sys.executable, str(root / GENERATOR), "--metrics"]
    environment = {"PYTHONHASHSEED": "1", "TZ": "UTC", "LC_ALL": "C"}
    keywords = {"check": True, "capture_output": True, "timeout": 75, "env": environment}
    payload = json.dumps({
        "elapsed_seconds": 12.5, "rss_mib": 128.0, "report_framed_sha256": "a" * 64,
    }).encode()
    completed = subprocess.CompletedProcess(command, 0, payload, b"private-child-stderr")
    return root, command, keywords, completed


def forwarding_control():
    root, command, keywords, completed = fixture_call()
    received, records = [], []

    def original(*arguments, **forwarded):
        received.append((arguments, forwarded))
        return completed

    result = metric_observer(original, root, records)(command, **keywords)
    assert result is completed and result.stdout is completed.stdout and result.stderr is completed.stderr
    assert received[0][0][0] is command and received[0][1] == keywords
    assert received[0][1]["env"] is keywords["env"]
    assert len(records) == 1 and records[0]["metrics"]["elapsed_seconds"] == 12.5
    assert records[0]["childTimeoutSeconds"] == 75 and records[0]["childReturnCode"] == 0
    assert "private-child-stderr" not in json.dumps(records)


def unrelated_control():
    root, _command, _keywords, completed = fixture_call()
    records = []
    marker = object()
    returned = metric_observer(lambda *args, **kwargs: completed, root, records)(marker, private=marker)
    assert returned is completed and records == []


def failure_control():
    root, command, keywords, _completed = fixture_call()
    sentinel = subprocess.TimeoutExpired(command, 75, output=b"private-child-output")

    def failed(*_arguments, **_keywords):
        raise sentinel

    records = []
    try:
        metric_observer(failed, root, records)(command, **keywords)
    except subprocess.TimeoutExpired as error:
        assert error is sentinel and records == []
    else:
        raise AssertionError("original_exception_not_preserved")


def invalid_measurement_control():
    root, command, keywords, completed = fixture_call()
    completed.stdout = json.dumps({
        "elapsed_seconds": float("nan"), "rss_mib": 128, "report_framed_sha256": "a" * 64,
    }).encode()
    records = []
    try:
        metric_observer(lambda *args, **kwargs: completed, root, records)(command, **keywords)
    except ValueError:
        assert records == []
    else:
        raise AssertionError("invalid_measurement_accepted")


def source_control():
    with tempfile.TemporaryDirectory(prefix="heredoc-proof-control-") as temporary:
        root = Path(temporary)
        payload = b"source-control"
        (root / "tracked.py").write_bytes(payload)
        expected = {"tracked.py": git_blob(payload)}
        assert check_sources(root, expected) == 1
        (root / "tracked.py").write_bytes(b"changed-control")
        try:
            check_sources(root, expected)
        except ValueError:
            pass
        else:
            raise AssertionError("changed_source_accepted")


def executed_source_control():
    with tempfile.TemporaryDirectory(prefix="heredoc-execution-control-") as temporary:
        root = Path(temporary)
        path = root / "tests" / "heredoc_source_control.py"
        path.parent.mkdir()
        payload = b"def probe():\n    return 7\n"
        path.write_bytes(payload)
        code = compile(payload, str(path), "exec")
        unknown = compile(payload, str(root / "unknown.py"), "exec")
        expected = {"tests/heredoc_source_control.py": git_blob(payload)}
        records = {}
        enabled = True

        def observe(event, arguments):
            if enabled and event == "exec" and any(arguments[0] is item for item in (code, unknown)):
                binding = executed_source_binding(arguments[0], root, expected, ())
                if binding is not None:
                    records[binding[0]] = binding[1]

        sys.addaudithook(observe)
        name = "tests.heredoc_source_control"
        module = ModuleType(name)
        module.__file__ = str(path)
        try:
            sys.modules[name] = module
            exec(code, module.__dict__)
            assert module.probe() == 7
            del sys.modules[name]
            assert records == {source_id("tests/heredoc_source_control.py"): git_blob(payload)}
            for changed, wanted in (
                (unknown, "untracked_executed_source"),
                (code, "executed_source_changed"),
            ):
                if changed is code:
                    path.write_bytes(b"def probe():\n    return 8\n")
                try:
                    exec(changed, {})
                except ValueError as error:
                    assert error.args == (wanted,)
                    assert exception_metadata(error) == {"class": "ValueError", "diagnosticCode": wanted}
                else:
                    raise AssertionError("execution_source_refusal_missing")
        finally:
            enabled = False
            sys.modules.pop(name, None)


def self_test():
    controls = (
        output_control, exception_control, forwarding_control, unrelated_control,
        failure_control, invalid_measurement_control, source_control, executed_source_control,
    )
    passed = 0
    for control in controls:
        control()
        passed += 1
    assert passed == len(controls)
    return {"passed": passed, "total": len(controls)}
