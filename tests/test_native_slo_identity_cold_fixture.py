from __future__ import annotations

import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_identity_cold_fixture as fixture


def _binding():
    return {
        "build_sha": "a" * 40,
        "runtime_sha256": "b" * 64,
        "installed_package_sha256": "c" * 64,
    }


def _arguments(tmp_path, *, configuration=None):
    runtime = tmp_path / "installed runtime with spaces"
    runtime.touch()
    config = (
        configuration
        if configuration is not None
        else {
            "path": str(tmp_path / "lifecycle.jsonl"),
            "binding": _binding(),
        }
    )
    return ["fixture.py", "--serve", str(runtime), "normal", "none", "--identity-lifecycle", json.dumps(config)]


@pytest.fixture
def observed_lifecycle(monkeypatch):
    from scripts import native_slo_identity_lifecycle as lifecycle

    events = []

    class Observer:
        def __init__(self, path, expected):
            events.append(("construct", path, expected))

        def __enter__(self):
            events.append("observer_enter")
            return self

        def __exit__(self, kind, error, traceback):
            events.append(("observer_exit", error))

        @contextmanager
        def preparation(self):
            events.append("preparation_enter")
            try:
                yield
            finally:
                events.append("preparation_exit")

        def phase(self, phase):
            events.append(("phase", phase))

    monkeypatch.setattr(lifecycle, "LifecycleObserver", Observer)
    monkeypatch.setattr(fixture, "_active_observer", None)
    return events


def test_default_fixture_argv_keeps_exact_arguments_and_windows_quoting():
    runtime = Path(r"C:\Program Files\HOL Guard\native runtime.exe")
    session = SimpleNamespace(runtime=runtime, setup=None, policy=None, cold_identity=None)
    expected = (sys.executable, "-u", "fixture with spaces.py", "--serve", str(runtime), "none", "none")
    assert fixture.fixture_command(session, "fixture with spaces.py") == expected
    assert fixture.cold_fixture_arguments(expected, None) is expected


def test_cold_fixture_adds_one_json_argument_without_rewriting_original_argv(tmp_path):
    configuration = {"path": str(tmp_path / "private evidence.jsonl"), "binding": _binding()}
    session = SimpleNamespace(
        runtime=tmp_path / "native runtime", setup="normal", policy=None, cold_identity=configuration
    )
    original = (sys.executable, "-u", "fixture.py", "--serve", str(session.runtime), "normal", "none")
    actual = fixture.fixture_command(session, "fixture.py")
    assert actual[:-2] == original
    assert actual[-2] == "--identity-lifecycle"
    assert json.loads(actual[-1]) == configuration
    assert configuration == {"path": str(tmp_path / "private evidence.jsonl"), "binding": _binding()}


def test_cold_argument_size_is_bounded_before_child_launch():
    with pytest.raises(ValueError, match="options exceeded bound"):
        fixture.cold_fixture_arguments(("unchanged",), {"path": "x" * 4096})


@pytest.mark.parametrize("raises", [False, True])
def test_default_serve_calls_original_once_without_installing_observer(tmp_path, observed_lifecycle, raises):
    arguments = _arguments(tmp_path)[:5]
    arguments[3:5] = ["legacy-setup", "legacy-policy"]
    original_error = RuntimeError("private default fixture failure")
    calls = []

    def serve(*args):
        calls.append(args)
        if raises:
            raise original_error
        return 17

    if raises:
        with pytest.raises(RuntimeError) as caught:
            fixture.serve_fixture_entry(serve, arguments)
        assert caught.value is original_error
    else:
        assert fixture.serve_fixture_entry(serve, arguments) == 17
    assert calls == [(Path(arguments[2]).resolve(), "legacy-setup", "legacy-policy")]
    assert observed_lifecycle == []
    assert fixture._active_observer is None


@pytest.mark.parametrize("raises", [False, True])
def test_observer_precedes_original_constructor_and_preserves_return_or_exception(tmp_path, observed_lifecycle, raises):
    arguments = _arguments(tmp_path)
    original_error = RuntimeError("private startup failure")
    calls = []

    def serve(*args):
        calls.append(args)
        assert fixture._active_observer is not None
        assert observed_lifecycle[-2:] == ["observer_enter", "preparation_enter"]
        observed_lifecycle.append("original_serve")
        fixture.lifecycle_ready()
        try:
            if raises:
                raise original_error
            return 23
        finally:
            fixture.lifecycle_retiring()

    if raises:
        with pytest.raises(RuntimeError) as caught:
            fixture.serve_fixture_entry(serve, arguments)
        assert caught.value is original_error
    else:
        assert fixture.serve_fixture_entry(serve, arguments) == 23
    assert calls == [(Path(arguments[2]).resolve(), "normal", "none")]
    assert observed_lifecycle == [
        ("construct", Path(json.loads(arguments[-1])["path"]), _binding()),
        "observer_enter",
        "preparation_enter",
        "original_serve",
        ("phase", "ready"),
        ("phase", "cleanup"),
        "preparation_exit",
        ("observer_exit", original_error if raises else None),
    ]
    assert fixture._active_observer is None


@pytest.mark.parametrize(
    "invalid",
    [
        "short",
        "extra",
        "wrong_mode",
        "wrong_flag",
        "oversize",
        "invalid_json",
        "not_object",
        "extra_field",
        "missing_field",
        "relative_path",
        "nonstring_path",
        "wrong_setup",
        "wrong_policy",
        "missing_binding",
        "extra_binding",
        "bad_build",
        "bad_runtime",
        "bad_package",
        "existing_observer",
    ],
)
def test_invalid_cold_options_never_enter_observer_or_serve(tmp_path, observed_lifecycle, monkeypatch, invalid):
    arguments = _arguments(tmp_path)
    config = json.loads(arguments[-1])
    previous = None
    if invalid == "short":
        arguments.pop()
    elif invalid == "extra":
        arguments.append("extra")
    elif invalid == "wrong_mode":
        arguments[1] = "--other"
    elif invalid == "wrong_flag":
        arguments[5] = "--other"
    elif invalid == "oversize":
        arguments[-1] = "x" * 4097
    elif invalid == "invalid_json":
        arguments[-1] = "{"
    elif invalid == "not_object":
        arguments[-1] = "[]"
    elif invalid == "wrong_setup":
        arguments[3] = "fault"
    elif invalid == "wrong_policy":
        arguments[4] = "normal"
    elif invalid == "existing_observer":
        previous = object()
        monkeypatch.setattr(fixture, "_active_observer", previous)
    else:
        if invalid == "extra_field":
            config["extra"] = True
        elif invalid == "missing_field":
            del config["path"]
        elif invalid == "relative_path":
            config["path"] = "relative.jsonl"
        elif invalid == "nonstring_path":
            config["path"] = 1
        elif invalid == "missing_binding":
            del config["binding"]["build_sha"]
        elif invalid == "extra_binding":
            config["binding"]["unexpected"] = "a" * 64
        elif invalid == "bad_build":
            config["binding"]["build_sha"] = "A" * 40
        elif invalid == "bad_runtime":
            config["binding"]["runtime_sha256"] = "b" * 63
        elif invalid == "bad_package":
            config["binding"]["installed_package_sha256"] = True
        arguments[-1] = json.dumps(config)

    def forbidden(*_args):
        pytest.fail("invalid options reached the original serve function")

    with pytest.raises(ValueError):
        fixture.serve_fixture_entry(forbidden, arguments)
    assert observed_lifecycle == []
    assert fixture._active_observer is previous


def test_phase_callbacks_without_cold_observer_leave_default_fixture_untouched(monkeypatch):
    monkeypatch.setattr(fixture, "_active_observer", None)
    assert fixture.lifecycle_ready() is None
    assert fixture.lifecycle_retiring() is None


def test_original_startup_failure_has_finite_evidence_without_raw_exception():
    error = OSError(13, "private startup path /not/a/public/value")
    session = SimpleNamespace(cold_identity={})
    fixture.retain_startup_failure(session, error)
    evidence = session.cold_startup_failure
    assert evidence["category"] == "PermissionError" and evidence["errno"] == 13
    assert evidence["diagnostic_digest"] == hashlib.sha256(str(error).encode()).hexdigest()
    assert evidence["reason"] == "unclassified_failure"
    assert "private startup" not in json.dumps(evidence) and "/not/a/public/value" not in json.dumps(evidence)
    assert set(evidence) == {"schema", "category", "reason", "diagnostic_digest", "errno"}


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(2)])
def test_uncaptured_base_exceptions_remain_unknown(error):
    session = SimpleNamespace(cold_identity={})
    fixture.retain_startup_failure(session, error)
    assert not hasattr(session, "cold_startup_failure")


def test_default_fixture_does_not_gain_cold_failure_metadata():
    session = SimpleNamespace(cold_identity=None)
    fixture.retain_startup_failure(session, RuntimeError("private default failure"))
    assert not hasattr(session, "cold_startup_failure")
