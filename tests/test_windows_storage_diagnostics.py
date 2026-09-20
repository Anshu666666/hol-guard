"""Bounded failure origins preserve the unchanged writer's semantics."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import TracebackType
from typing import cast

import pytest

_DRIVER = Path(__file__).resolve().parents[1] / "scripts" / "ci"
if str(_DRIVER) not in sys.path:
    sys.path.insert(0, str(_DRIVER))

import windows_storage_failure_capture as capture  # noqa: E402


def _raise_timeout() -> None:
    raise TimeoutError("synthetic private path and payload must not be inspected")


def _error() -> TimeoutError:
    try:
        _raise_timeout()
    except TimeoutError as error:
        return error
    raise AssertionError("fixture did not raise")


def test_only_innermost_known_code_identifies_origin() -> None:
    error = _error()
    assert capture.failure_origin(error, {_raise_timeout.__code__: "storage_gate"}) == "storage_gate"
    assert capture.failure_origin(error, {_error.__code__: "storage_gate"}) == "unattributed"
    assert capture.failure_origin(error, {_raise_timeout.__code__: "/private/other"}) == "unattributed"


def test_builtin_timeout_arguments_are_never_rendered() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise AssertionError("message inspected")

        def __repr__(self) -> str:
            raise AssertionError("message inspected")

    assert capture.failure_origin(TimeoutError(Hostile()), {}) == "unattributed"


def test_timeout_subclass_is_not_inspected() -> None:
    class HostileTimeoutError(TimeoutError):
        def __getattribute__(self, name: str) -> object:
            if name == "__traceback__":
                raise AssertionError("subclass traceback inspected")
            return super().__getattribute__(name)

    assert capture.failure_origin(HostileTimeoutError(), {}) == "not_timeout"


def test_traceback_scan_has_a_fixed_bound() -> None:
    error = _error()
    assert error.__traceback__ is not None
    first = error.__traceback__
    tail = first
    for _ in range(40):
        tail = TracebackType(tail, first.tb_frame, first.tb_lasti, first.tb_lineno)
    error.__traceback__ = tail
    assert capture.failure_origin(error, {}) == "traceback_limit"


def test_failure_callback_returns_original_code_and_restores_after_exception(monkeypatch) -> None:
    error = _error()
    calls = []

    def original(value):
        calls.append(value)
        return "os_timeout"

    monkeypatch.setattr(capture.writer, "evidence_failure_code", original)
    monkeypatch.setattr(capture, "timeout_origins", lambda: {_raise_timeout.__code__: "storage_gate"})
    observation = capture.FailureOriginCapture()
    sentinel = RuntimeError("original caller error")
    with pytest.raises(RuntimeError) as caught, observation:
        assert capture.writer.evidence_failure_code(error) == "os_timeout"
        raise sentinel
    assert caught.value is sentinel
    assert calls == [error]
    assert capture.writer.evidence_failure_code is original
    snapshot = observation.snapshot()
    assert snapshot["diagnostic_complete"] and snapshot["callbacks_restored"]
    assert cast(dict[str, int], snapshot["origin_counts"])["storage_gate"] == 1
    assert "private" not in json.dumps(snapshot)
    assert all(value is not error for value in vars(observation).values())


def test_diagnostic_error_cannot_change_original_classification(monkeypatch) -> None:
    monkeypatch.setattr(capture.writer, "evidence_failure_code", lambda _error: "os_timeout")

    def broken(*_args):
        raise RuntimeError("diagnostic fault")

    monkeypatch.setattr(capture, "failure_origin", broken)
    observation = capture.FailureOriginCapture()
    with observation:
        assert capture.writer.evidence_failure_code(_error()) == "os_timeout"
    assert observation.snapshot()["diagnostic_complete"] is False


def test_original_classifier_exception_is_preserved(monkeypatch) -> None:
    sentinel = ValueError("original classifier exception")

    def original(_error):
        raise sentinel

    monkeypatch.setattr(capture.writer, "evidence_failure_code", original)
    with capture.FailureOriginCapture(), pytest.raises(ValueError) as caught:
        capture.writer.evidence_failure_code(_error())
    assert caught.value is sentinel
    assert capture.writer.evidence_failure_code is original


def test_callback_never_waits_for_diagnostic_lock(monkeypatch) -> None:
    monkeypatch.setattr(capture.writer, "evidence_failure_code", lambda _error: "os_timeout")
    observation = capture.FailureOriginCapture()
    with observation:
        assert observation._lock.acquire(blocking=False)
        try:
            assert capture.writer.evidence_failure_code(_error()) == "os_timeout"
        finally:
            observation._lock.release()
    assert observation.snapshot()["diagnostic_complete"] is False


def test_zero_failure_capture_has_no_observed_origin_and_no_runtime_call() -> None:
    with capture.FailureOriginCapture() as observation:
        pass
    snapshot = observation.snapshot()
    assert snapshot["diagnostic_complete"] is True
    assert not any(cast(dict[str, int], snapshot["origin_counts"]).values())


def test_real_posix_gate_timeout_is_classified_without_changing_timeout(tmp_path) -> None:
    if sys.platform == "win32":
        pytest.skip("complementary POSIX source control")
    from codex_plugin_scanner.guard.store import GuardStore

    spec = importlib.util.spec_from_file_location(
        "storage_diagnostic_driver", _DRIVER / "windows_storage_diagnostics.py"
    )
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    shared = driver._gate_case(store, "shared_connections", "connection", "connection")
    exclusive = driver._gate_case(store, "recovery_blocks_shared", "exclusive", "shared")
    assert shared["waiter_acquired_while_holder_active"] is True
    assert exclusive["waiter_timeout_observed"] is True
    assert exclusive["waiter_failure_origin"] == "storage_gate"
    assert all(result["holder_released"] and result["holder_thread_stopped"] for result in (shared, exclusive))
    assert driver.WRITER_TIMEOUT_SECONDS == 0.05
