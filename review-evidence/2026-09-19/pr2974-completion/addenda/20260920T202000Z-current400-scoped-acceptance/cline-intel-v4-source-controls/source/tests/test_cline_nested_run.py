"""Original nested-call forwarding, closed output and actual generated workers."""

from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.adapters.cline_hooks import _hook_source
from scripts.ci.cline_witness import installation, invocation, nested_run

PRIVATE = "private payload/output/exception must not escape"


def model(monkeypatch: pytest.MonkeyPatch, operation: Any) -> tuple[Any, nested_run.NestedRun, list[Any]]:
    source = "def main(args, kwargs):\n    return subprocess.run(*args, **kwargs)\n"
    namespace: dict[str, Any] = {"__name__": "__main__", "subprocess": subprocess}
    exec(compile(source, "/owned/original-worker.py", "exec"), namespace)
    monkeypatch.setattr(subprocess, "run", operation)
    reports: list[Any] = []
    config = {
        "nested_callsite": {"file": "/owned/original-worker.py", "first_line": 1, "call_line": 2},
        "argv": [[], ["exact", "cli"]],
        "configuration_sha256": "a" * 64,
        "output": "/owned/evidence",
    }
    observer = nested_run.NestedRun(config, lambda path, value: reports.append((path, value)))
    return namespace["main"], observer, reports


def arguments() -> tuple[list[str], dict[str, Any]]:
    return ["exact", "cli"], {"input": PRIVATE, "capture_output": True, "text": True, "timeout": 9, "check": False}


def admit(report: object) -> None:
    nested_run.validate(report, {"pid": os.getpid(), "parent_pid": os.getppid()}, "a" * 64)


@pytest.mark.parametrize("returncode", [0, 7, -9])
def test_exact_completed_object_and_argument_values_are_preserved(
    monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    argv, kwargs = arguments()
    result = subprocess.CompletedProcess(argv, returncode, PRIVATE, PRIVATE)
    calls = []

    def original(*args: Any, **options: Any) -> Any:
        calls.append((args, options))
        return result

    main, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        assert main((argv,), kwargs) is result
    finally:
        observer.finish()
    assert len(calls) == 1 and calls[0][0][0] is argv and calls[0][1]["input"] is kwargs["input"]
    assert calls[0][1] == kwargs and subprocess.run is original
    report = reports[0][1]
    assert report["selected_calls"] == 1 and report["outcome"] == "returned" and report["returncode"] == returncode
    admit(report)
    assert PRIVATE not in json.dumps(report)


@pytest.mark.parametrize("kind", ["timeout", "os", "subprocess", "ordinary", "base_group"])
def test_exact_raised_object_and_single_call_survive(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    errors = {
        "timeout": subprocess.TimeoutExpired([PRIVATE], 9, PRIVATE, PRIVATE),
        "os": PermissionError(13, PRIVATE, PRIVATE),
        "subprocess": subprocess.SubprocessError(PRIVATE),
        "ordinary": RuntimeError(PRIVATE),
        "base_group": builtins.BaseExceptionGroup(PRIVATE, [KeyboardInterrupt(PRIVATE), RuntimeError(PRIVATE)]),
    }
    error = errors[kind]
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        raise error

    main, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        with pytest.raises(BaseException) as caught:
            argv, options = arguments()
            main((argv,), options)
        assert caught.value is error
    finally:
        observer.finish()
    assert len(calls) == 1 and subprocess.run is original
    report = reports[0][1]
    assert report["outcome"] == {
        "os": "os_error",
        "subprocess": "subprocess_error",
        "ordinary": "other_exception",
        "base_group": "other_exception",
    }.get(kind, kind)
    assert report["errno"] == (13 if kind == "os" else None)
    admit(report)
    assert PRIVATE not in json.dumps(report)


def test_zero_offer_and_unrelated_original_call_have_no_native_credit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    original_result = object()

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return original_result

    _, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        assert subprocess.run(["unrelated"]) is original_result
    finally:
        observer.finish()
    report = reports[0][1]
    assert len(calls) == 1 and report["selected_calls"] == 0 and report["outcome"] == "not_offered"
    assert report["returncode"] is None and not report["performance_qualified"]
    admit(report)


@pytest.mark.parametrize("stage", ["before", "returned", "raised"])
def test_recorder_failure_does_not_replace_original_result(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    result = subprocess.CompletedProcess([], 7, PRIVATE, PRIVATE)
    error = RuntimeError(PRIVATE)
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        if stage == "raised":
            raise error
        return result

    def broken(*_args: Any) -> Any:
        raise ValueError(PRIVATE)

    main, observer, reports = model(monkeypatch, original)
    monkeypatch.setattr(observer, stage, broken)
    observer.start()
    try:
        argv, options = arguments()
        if stage == "raised":
            with pytest.raises(RuntimeError) as caught:
                main((argv,), options)
            assert caught.value is error
        else:
            assert main((argv,), options) is result
    finally:
        observer.finish()
    assert len(calls) == 1 and not reports[0][1]["observation_complete"]
    assert reports[0][1]["faults"] == ["capture_failed"] and PRIVATE not in json.dumps(reports[0][1])


def test_export_failure_and_finish_twice_preserve_original_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    result = subprocess.CompletedProcess([], 7)
    main, observer, _ = model(monkeypatch, lambda *_args, **_kwargs: result)
    writes = []

    def fail_export(*_args: Any) -> None:
        writes.append(True)
        raise OSError(PRIVATE)

    observer.writer = fail_export
    observer.start()
    argv, options = arguments()
    assert main((argv,), options) is result
    observer.finish()
    observer.finish()
    assert writes == [True] and subprocess.run is observer.original


def test_duplicate_original_calls_are_forwarded_but_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    result = subprocess.CompletedProcess([], 0)
    calls = []

    def original(*_args: Any, **_kwargs: Any) -> Any:
        calls.append(True)
        return result

    main, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        argv, options = arguments()
        assert main((argv,), options) is result
        assert main((argv,), options) is result
    finally:
        observer.finish()
    assert len(calls) == 2 and reports[0][1]["selected_calls"] == 2 and reports[0][1]["count_saturated"]
    with pytest.raises(ValueError):
        admit(reports[0][1])


def test_restoration_never_overwrites_an_unrelated_later_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    _, observer, reports = model(monkeypatch, lambda: None)
    observer.start()

    def later() -> None:
        return None

    subprocess.run = later
    observer.finish()
    assert subprocess.run is later and reports[0][1]["faults"] == ["restore_failed"]
    assert not reports[0][1]["observation_complete"]


@pytest.mark.parametrize("field", ["timeout", "check", "capture_output", "text", "input"])
def test_changed_call_contract_is_forwarded_once_but_not_admitted(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    result = subprocess.CompletedProcess([], 0)
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return result

    main, observer, reports = model(monkeypatch, original)
    argv, options = arguments()
    options[field] = {"timeout": 10, "check": True, "capture_output": False, "text": False, "input": b"private"}[field]
    observer.start()
    try:
        assert main((argv,), options) is result
    finally:
        observer.finish()
    assert len(calls) == 1 and calls[0][1] == options
    assert reports[0][1]["faults"] == ["call_shape"] and not reports[0][1]["observation_complete"]


def test_unknown_return_object_is_never_inspected_or_stringified(monkeypatch: pytest.MonkeyPatch) -> None:
    class Private:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError("unexpected access: " + name)

        def __str__(self) -> str:
            raise AssertionError("unexpected stringify")

    result = Private()
    main, observer, reports = model(monkeypatch, lambda *_args, **_kwargs: result)
    observer.start()
    try:
        argv, options = arguments()
        assert main((argv,), options) is result
    finally:
        observer.finish()
    assert reports[0][1]["faults"] == ["return_shape"]
    assert reports[0][1]["returncode"] is None


def test_hostile_exception_metaclass_is_not_compared(monkeypatch: pytest.MonkeyPatch) -> None:
    touched = []

    class Hostile(type):
        def __eq__(cls, _other: object) -> bool:
            touched.append(True)
            raise AssertionError("exception class equality must not execute")

    class PrivateError(Exception, metaclass=Hostile):
        pass

    error = PrivateError(PRIVATE)

    def original(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    main, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        argv, options = arguments()
        with pytest.raises(PrivateError) as caught:
            main((argv,), options)
        assert caught.value is error
    finally:
        observer.finish()
    assert touched == [] and reports[0][1]["outcome"] == "other_exception"
    admit(reports[0][1])


@pytest.mark.parametrize("value", [-(2**31) - 1, 2**31, True])
@pytest.mark.parametrize("field", ["returncode", "errno"])
def test_unbounded_integer_capture_preserves_original_but_is_refused(
    monkeypatch: pytest.MonkeyPatch, value: int, field: str
) -> None:
    result = subprocess.CompletedProcess([], value)
    error = OSError()
    error.errno = value

    def original(*_args: Any, **_kwargs: Any) -> Any:
        if field == "errno":
            raise error
        return result

    main, observer, reports = model(monkeypatch, original)
    observer.start()
    try:
        argv, options = arguments()
        if field == "errno":
            with pytest.raises(OSError) as caught:
                main((argv,), options)
            assert caught.value is error
        else:
            assert main((argv,), options) is result
    finally:
        observer.finish()
    assert reports[0][1][field] is None and not reports[0][1]["observation_complete"]
    with pytest.raises(ValueError):
        admit(reports[0][1])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", True),
        ("selected_calls", True),
        ("selected_calls", 1),
        ("outcome", "timeout"),
        ("returncode", 0),
        ("errno", 13),
        ("count_saturated", 0),
        ("original_timeout_seconds", 10),
        ("configuration_sha256", "b" * 64),
        ("extra", PRIVATE),
        ("run_installed", False),
    ],
)
def test_strict_zero_offer_reader_rejects_forged_fields(
    monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    _, observer, reports = model(monkeypatch, lambda: None)
    observer.start()
    observer.finish()
    report = copy.deepcopy(reports[0][1])
    report[field] = value
    with pytest.raises(ValueError):
        admit(report)


@pytest.fixture(scope="module")
def interpreter(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("cline-nested-python")
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root)], check=True, timeout=30)
    python = root / "bin/python"
    result = subprocess.run(
        [str(python), "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return python, Path(result.stdout.strip())


@pytest.mark.skipif(os.name != "posix", reason="Declared Intel-only diagnostic uses a POSIX venv")
@pytest.mark.parametrize("mode", ["allow", "nonzero", "no_offer", "timeout"])
def test_actual_generated_worker_retains_original_call_outcome(
    interpreter: tuple[Path, Path], tmp_path: Path, mode: str
) -> None:
    python, site = interpreter
    home = tmp_path / "guard"
    state = home / "managed/cline/adapter-state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"active_transport": "plugin" if mode == "no_offer" else "hooks"}))
    code = (
        "import time;time.sleep(30)"
        if mode == "timeout"
        else (
            "import json;print(json.dumps({'decision':'allow'}));raise SystemExit("
            + ("7" if mode == "nonzero" else "0")
            + ")"
        )
    )
    guard = [str(python), "-I", "-s", "-c", code]
    cli = [*guard, "--harness", "cline", "--json"]
    worker = tmp_path / "actual-worker.py"
    worker.write_text(
        _hook_source(cast(Any, SimpleNamespace(guard_home=home)), event_name="PreToolUse", guard_cli=guard)
    )
    tree = ast.parse(worker.read_bytes())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    call = next(
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
    )
    command = [str(python), "-I", "-s", str(worker)]
    observed, _ = invocation.preflight(str(python), str(python.parent.parent))
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    config = {
        "executable": str(python),
        "parent_pid": os.getpid(),
        "argv": [command, cli],
        "observed_argv": [[observed, *row[1:]] for row in (command, cli)],
        "frames": [],
        "sources": {},
        "nested_callsite": {"file": str(worker), "first_line": main.lineno, "call_line": call.lineno},
        "worker_source_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
    }
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pwd"}})
    with installation.Installation(site, output, config) as installed:
        result = subprocess.run(command, input=payload, capture_output=True, text=True, timeout=15, check=False)
        report = json.loads((output / "nested-run.json").read_bytes())
        worker_report = json.loads((output / "worker.json").read_bytes())
        nested_run.validate(report, worker_report, installed.manifest["configuration_sha256"])
    assert result.returncode == 0 and result.stderr == ""
    assert report["selected_calls"] == (0 if mode == "no_offer" else 1)
    assert report["outcome"] == {"no_offer": "not_offered", "timeout": "timeout"}.get(mode, "returned")
    assert report["returncode"] == (7 if mode == "nonzero" else 0 if mode == "allow" else None)
    assert json.loads(result.stdout)["cancel"] is (mode == "timeout")
    assert not installed.created and not installed.cleanup_faults
    assert not (site / "sitecustomize.py").exists()
