from __future__ import annotations

import ctypes
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from scripts import native_slo_windows_open_observer as observations
from scripts.native_slo_failure import failure_evidence


def test_original_exception_arguments_and_single_call_are_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    code = [32]
    error = NativePolicySnapshotError("private-marker C:\\private\\state")
    calls = []
    path = Path("private-marker")

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        code[0] = 5  # Later cleanup must not change the observed API error.
        raise error

    monkeypatch.setattr(ctypes, "get_last_error", lambda: code[0], raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(NativePolicySnapshotError) as caught, observer:
        windows_io._windows_raise_open_error(path, create_new=True)
    assert caught.value is error
    assert calls == [((path,), {"create_new": True})]
    assert windows_io._windows_raise_open_error is original
    original_evidence = failure_evidence(error)
    observed = observer.failure_evidence(error)
    assert {key: value for key, value in observed.items() if key != "windows_open_failure"} == original_evidence
    open_failure = observed["windows_open_failure"]
    assert isinstance(open_failure, dict)
    assert open_failure["winerror"] == 32
    assert "private-marker" not in json.dumps(observed)
    assert "C:\\private" not in json.dumps(observed)
    assert observer.failure_evidence(error) == original_evidence
    assert observer._error is None
    assert observations._OWNERSHIP.acquire(blocking=False)
    observations._OWNERSHIP.release()


@pytest.mark.parametrize("code", [True, -1, 2**32, "32", None])
def test_invalid_codes_leave_the_original_failure_unchanged(monkeypatch: pytest.MonkeyPatch, code) -> None:
    error = NativePolicySnapshotError("original")

    def original(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(ctypes, "get_last_error", lambda: code, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(NativePolicySnapshotError), observer:
        windows_io._windows_raise_open_error(Path("private"), create_new=False)
    assert observer.failure_evidence(error) == failure_evidence(error)


def test_failed_error_lookup_does_not_replace_the_original_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    error = NativePolicySnapshotError("original")
    calls = []

    def original(*_args, **_kwargs):
        calls.append(True)
        raise error

    def unavailable():
        raise OSError("private diagnostic failure")

    monkeypatch.setattr(ctypes, "get_last_error", unavailable, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(NativePolicySnapshotError) as caught, observer:
        windows_io._windows_raise_open_error(Path("private"), create_new=False)
    assert caught.value is error
    assert calls == [True]
    assert observer.failure_evidence(error) == failure_evidence(error)


def test_other_thread_and_handled_error_cannot_be_relabelled(monkeypatch: pytest.MonkeyPatch) -> None:
    error = NativePolicySnapshotError("original")

    def original(*_args, **_kwargs):
        raise error

    def invoke():
        with pytest.raises(NativePolicySnapshotError):
            windows_io._windows_raise_open_error(Path("private"), create_new=False)

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(NativePolicySnapshotError), observer:
        thread = threading.Thread(target=invoke)
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
        raise error
    assert observer.failure_evidence(error) == failure_evidence(error)
    observer = observations.WindowsOpenFailureObserver()
    with observer:
        invoke()  # A caught rejection must not survive successful startup.
    assert observer.failure_evidence(error) == failure_evidence(error)


def test_different_failure_after_an_observed_rejection_has_no_stale_code(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_error = NativePolicySnapshotError("observed")
    outer_error = NativePolicySnapshotError("different")

    def original(*_args, **_kwargs):
        raise observed_error

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(NativePolicySnapshotError) as caught, observer:
        with pytest.raises(NativePolicySnapshotError):
            windows_io._windows_raise_open_error(Path("private"), create_new=False)
        raise outer_error
    assert caught.value is outer_error
    assert observer.failure_evidence(outer_error) == failure_evidence(outer_error)


def test_helper_return_value_and_nonmatching_exception_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = object()
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", lambda *_args, **_kwargs: marker)
    with observations.WindowsOpenFailureObserver():
        assert windows_io._windows_raise_open_error(Path("private"), create_new=False) is marker
    error = OSError(32, "private-marker")

    def original(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    observer = observations.WindowsOpenFailureObserver()
    with pytest.raises(OSError) as caught, observer:
        windows_io._windows_raise_open_error(Path("private"), create_new=False)
    assert caught.value is error
    assert observer.failure_evidence(error) == failure_evidence(error)


def test_missing_api_overlap_and_explicit_retirement_preserve_the_prior_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    original = windows_io._windows_raise_open_error
    monkeypatch.delattr(ctypes, "get_last_error", raising=False)
    with observations.WindowsOpenFailureObserver() as unavailable:
        assert unavailable.identity["installed"] is False
        assert windows_io._windows_raise_open_error is original
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    with observations.WindowsOpenFailureObserver() as first:
        wrapped = windows_io._windows_raise_open_error
        with observations.WindowsOpenFailureObserver() as overlapping:
            assert overlapping.identity["installed"] is False
        assert windows_io._windows_raise_open_error is wrapped
        first.close()
        assert windows_io._windows_raise_open_error is original
    assert windows_io._windows_raise_open_error is original


def test_shipped_traceback_is_bounded_and_excludes_private_frame_values() -> None:
    namespace = {
        "__name__": "codex_plugin_scanner.guard.synthetic",
        "NativePolicySnapshotError": NativePolicySnapshotError,
    }
    source = """
def descend(depth):
    private_value = '/home/private/credential-marker'
    if depth:
        return descend(depth - 1)
    raise NativePolicySnapshotError(private_value)
"""
    exec(compile(source, __file__, "exec"), namespace)
    with pytest.raises(NativePolicySnapshotError) as caught:
        cast(Callable[[int], None], namespace["descend"])(30)
    stack = observations._shipped_traceback(caught.value)
    assert len(stack) == 8
    assert all(set(item) == {"origin", "line"} for item in stack)
    serialized = json.dumps(stack)
    assert "credential-marker" not in serialized
    assert "/home" not in serialized
    assert "private_value" not in serialized
