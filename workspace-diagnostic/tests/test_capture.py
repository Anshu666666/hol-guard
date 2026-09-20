"""Untimed controls for exact forwarding, context, privacy and finite loss."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from workspace_cause.capture import MAX_ROWS, Capture, current_capture


def publisher(home: Path) -> SimpleNamespace:
    return SimpleNamespace(
        guard_home=home,
        _condition=threading.Condition(),
        _epoch=1,
        _acked=True,
        _closed=False,
        _last_error=None,
    )


def test_identical_arguments_return_and_single_original_call(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    argument, result, calls = object(), object(), []
    keywords = {"value": object()}

    def original(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        assert current_capture() is capture
        return result

    assert capture.call("publication", original, (argument,), keywords) is result
    assert len(calls) == 1
    assert calls[0][0][0] is argument and calls[0][1]["value"] is keywords["value"]
    assert current_capture() is None
    row = capture.freeze()["rows"][0]
    assert row["outcome"] == "value" and row["exception"] == "none"


def test_original_exception_identity_survives_observer_failure(tmp_path: Path) -> None:
    for stage in ("_begin", "_finish"):
        capture = Capture(tmp_path)
        original_error = RuntimeError("owned-secret-exception-do-not-export")
        calls = []

        def original(bound_calls: list[bool] = calls, bound_error: RuntimeError = original_error) -> None:
            bound_calls.append(True)
            raise bound_error

        with (
            patch.object(capture, stage, side_effect=ValueError("observer failure")),
            pytest.raises(RuntimeError) as raised,
        ):
            capture.call("publication", original, (), {})
        assert raised.value is original_error and calls == [True]
        report = capture.freeze()
        assert report["observation_lost"] is True and report["observation_complete"] is False
        assert "owned-secret-exception" not in json.dumps(report)
        assert current_capture() is None


def test_success_survives_summary_and_finish_failures(tmp_path: Path) -> None:
    result = object()
    for mode in ("summary", "finish"):
        capture = Capture(tmp_path)

        def fail(_result: object) -> dict[str, object]:
            raise RuntimeError("diagnostic only")

        if mode == "summary":
            returned = capture.call("publication", lambda: result, (), {}, summarize=fail)
        else:
            with patch.object(capture, "_finish", side_effect=RuntimeError("diagnostic only")):
                returned = capture.call("publication", lambda: result, (), {})
        assert returned is result
        assert capture.freeze()["observation_complete"] is False
        assert current_capture() is None


def test_control_exception_identity_is_preserved(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    error = KeyboardInterrupt()

    def original() -> None:
        raise error

    with pytest.raises(KeyboardInterrupt) as raised:
        capture.call("publication", original, (), {})
    assert raised.value is error
    report = capture.freeze()
    assert report["rows"][0]["exception"] == "other"
    assert report["observation_complete"] is True


def test_nested_calls_preserve_parent_and_state_intervals(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    owner = publisher(tmp_path)

    def nested() -> None:
        owner._epoch += 1
        owner._acked = False

    capture.call(
        "publication", lambda: capture.call("request_publish", nested, (), {}, publisher=owner), (), {}, publisher=owner
    )
    outer, inner = capture.freeze()["rows"]
    assert inner["parent"] == outer["id"]
    assert outer["call_enter_ms"] <= inner["started_ms"] <= inner["finished_ms"] <= outer["call_return_ms"]
    assert inner["before"]["epoch"] == 1 and inner["after"]["epoch"] == 2
    assert inner["before"]["acked"] is True and inner["after"]["acked"] is False
    for row in (outer, inner):
        assert (
            row["started_ms"]
            <= row["before"]["sample_before_ms"]
            <= row["before"]["sample_after_ms"]
            <= row["call_enter_ms"]
        )
        assert (
            row["call_return_ms"]
            <= row["after"]["sample_before_ms"]
            <= row["after"]["sample_after_ms"]
            <= row["finished_ms"]
        )


def test_contended_state_lock_never_blocks_original(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    owner = publisher(tmp_path)
    entered, release = threading.Event(), threading.Event()
    failures = []

    def holder() -> None:
        try:
            with owner._condition:
                entered.set()
                if not release.wait(2):
                    raise TimeoutError("test holder release")
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert entered.wait(2)
        sentinel = object()
        assert capture.call("publication", lambda: sentinel, (), {}, publisher=owner) is sentinel
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and not failures
    report = capture.freeze()
    assert report["observation_complete"] is False and report["observation_lost"] is True


def test_row_cap_keeps_calling_original_and_reports_overflow(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    calls = []

    def original() -> bool:
        calls.append(True)
        return True

    for _ in range(MAX_ROWS + 3):
        assert capture.call("publication", original, (), {}) is True
    report = capture.freeze()
    assert len(calls) == MAX_ROWS + 3 and len(report["rows"]) == MAX_ROWS
    assert report["overflow"] is True and report["observation_complete"] is False


def test_freeze_retains_inflight_instead_of_claiming_tail_completion(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    entered, release = threading.Event(), threading.Event()
    results = []

    def original() -> str:
        entered.set()
        if not release.wait(2):
            raise TimeoutError("test release")
        return "same-result"

    thread = threading.Thread(target=lambda: results.append(capture.call("publication", original, (), {})))
    thread.start()
    try:
        assert entered.wait(2)
        frozen = capture.freeze()
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and results == ["same-result"]
    assert frozen["calls_in_flight"] == 1 and frozen["observation_complete"] is False
    assert frozen["rows"][0]["finished_ms"] is None
    assert capture.freeze()["observation_complete"] is False


def test_unknown_details_and_secret_errors_are_not_exported(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    owner = publisher(tmp_path)
    owner._last_error = "private/path-and-token"
    capture.call("publication", lambda: None, (), {}, publisher=owner)
    sentinel = object()
    assert capture.call("publication", lambda: sentinel, (), {}, details={"secret": "private-secret"}) is sentinel
    report = capture.freeze()
    encoded = json.dumps(report)
    assert "private/path" not in encoded and "private-secret" not in encoded
    assert report["rows"][0]["before"]["error"] == "other"
    assert report["observation_lost"] is True


def test_separate_threads_do_not_inherit_parent_context(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    results = []

    def original() -> None:
        thread = threading.Thread(target=lambda: results.append(capture.call("request_publish", lambda: None, (), {})))
        thread.start()
        thread.join(2)
        if thread.is_alive():
            raise TimeoutError("test child completion")

    capture.call("publication", original, (), {})
    report = capture.freeze()
    assert results == [None]
    assert report["rows"][1]["parent"] is None
    assert report["observation_complete"] is True
