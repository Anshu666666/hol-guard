"""Actual thread ownership and finite span evidence; no native acceptance claim."""

from __future__ import annotations

import json
import sys
import threading
import time
from types import FunctionType
from typing import Any, cast

import pytest

from ci.native_runtime import installed_readiness_spans as spans_module
from ci.native_runtime.installed_readiness_profile import ReadinessProfile
from ci.native_runtime.installed_readiness_spans import SelectedThreadSpans


def _trusted(delay: float = 0.0) -> int:
    if delay:
        time.sleep(delay)
    return 17


def _codes(function: Any, label: str = "command_preparation") -> dict[int, tuple[Any, str]]:
    return {id(function.__code__): (function.__code__, label)}


def _window(profile: ReadinessProfile) -> dict[str, Any]:
    return next(
        item for item in cast(list[dict[str, Any]], profile.snapshot()["windows"]) if item["window"] == "publication"
    )


def test_actual_overlap_attributes_same_code_only_to_selected_thread_preserving_cprofile() -> None:
    foreign_started, foreign_done = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    trace_restored: list[bool] = []
    foreign_elapsed: list[float] = []
    selected_elapsed: list[float] = []

    def foreign() -> None:
        try:
            assert foreign_started.wait(3)
            started = time.perf_counter()
            for _ in range(7):
                _trusted(0.01)
            foreign_elapsed.append((time.perf_counter() - started) * 1000)
        except BaseException as error:
            errors.append(error)
        finally:
            foreign_done.set()

    class Publisher:
        def _publish_once(self) -> int:
            foreign_started.set()
            assert foreign_done.wait(3)
            started = time.perf_counter()
            result = _trusted()
            selected_elapsed.append((time.perf_counter() - started) * 1000)
            return result

    publisher = Publisher()
    observer = ReadinessProfile({"command_preparation": _trusted}, enabled=True, thread_spans=True)
    result: list[int] = []

    def selected() -> None:
        try:
            with observer.attach(publisher):
                result.append(publisher._publish_once())
            trace_restored.append(sys.gettrace() is None)
        except BaseException as error:
            errors.append(error)

    other = threading.Thread(target=foreign)
    owner = threading.Thread(target=selected)
    other.start()
    owner.start()
    try:
        owner.join(4)
    finally:
        foreign_started.set()
        foreign_done.set()
        owner.join(4)
        other.join(4)
    assert not owner.is_alive() and not other.is_alive() and not errors
    assert result == [17] and trace_restored == [True]
    record = _window(observer)
    assert record["available"] is True
    assert record["rows"][0]["calls"] == (8 if sys.version_info >= (3, 12) else 1)
    assert record["thread_spans"]["available"] is True
    assert record["thread_spans"]["rows"][0]["calls"] == 1
    owned_wall = record["thread_spans"]["rows"][0]["inclusive_wall_ms"]
    # The selected span is enclosed by independently measured selected-thread
    # timestamps. It cannot include the already-completed foreign waits.
    assert 0 <= owned_wall <= selected_elapsed[0] + 0.001
    assert foreign_elapsed[0] >= 50
    assert record["thread_spans"]["acceptance_claim"] is False


def test_nested_real_wall_wait_is_attributed_without_claiming_cpu_or_causation() -> None:
    entered, release = threading.Event(), threading.Event()
    errors: list[BaseException] = []

    def child() -> None:
        entered.set()
        assert release.wait(3)

    def parent() -> int:
        child()
        return 19

    def other_thread() -> None:
        try:
            assert entered.wait(3)
            time.sleep(0.04)
        except BaseException as error:
            errors.append(error)
        finally:
            release.set()

    other = threading.Thread(target=other_thread)
    other.start()
    observer = SelectedThreadSpans({**_codes(parent, "publication"), **_codes(child)})
    observer.start()
    try:
        assert parent() == 19
    finally:
        record = observer.close()
        release.set()
        other.join(4)
    assert not other.is_alive() and not errors and record["available"] is True
    rows = {row["label"]: row for row in cast(list[dict[str, Any]], record["rows"])}
    outer, inner = rows["publication"], rows["command_preparation"]
    assert inner["inclusive_wall_ms"] >= 30
    assert outer["first_start_ms"] <= inner["first_start_ms"] <= inner["last_end_ms"] <= outer["last_end_ms"]
    assert (
        abs(outer["inclusive_wall_ms"] - outer["wall_excluding_nested_selected_ms"] - inner["inclusive_wall_ms"])
        <= 0.003
    )
    assert (
        abs(
            outer["inclusive_thread_cpu_ms"]
            - outer["thread_cpu_excluding_nested_selected_ms"]
            - inner["inclusive_thread_cpu_ms"]
        )
        <= 0.003
    )
    assert record["wall_semantics"] == "includes_waits_scheduling_and_instrumentation_not_cpu_or_cause"


def test_equal_code_clone_and_private_label_are_not_admitted(capsys: pytest.CaptureFixture[str]) -> None:
    clone_code = _trusted.__code__.replace()
    assert clone_code == _trusted.__code__ and clone_code is not _trusted.__code__
    clone = FunctionType(clone_code, globals(), "private-canary-function", _trusted.__defaults__)
    observer = SelectedThreadSpans({**_codes(_trusted), id(clone_code): (clone_code, "private-canary-label")})
    observer.start()
    try:
        assert clone() == _trusted() == 17
    finally:
        record = observer.close()
    assert record["available"] is True
    assert len(cast(list[Any], record["rows"])) == 1
    assert cast(list[dict[str, Any]], record["rows"])[0]["calls"] == 1
    encoded = json.dumps(record, allow_nan=False)
    assert "private-canary" not in encoded and __file__ not in encoded
    assert capsys.readouterr() == ("", "")


def test_exception_identity_and_first_call_only_are_preserved() -> None:
    error = RuntimeError("private-canary-exception")

    class Publisher:
        def _publish_once(self) -> None:
            raise error

    publisher = Publisher()
    original = publisher._publish_once
    observer = ReadinessProfile({"publication": original}, enabled=True, thread_spans=True)
    with observer.attach(publisher):
        with pytest.raises(RuntimeError) as first:
            publisher._publish_once()
        first_record = json.dumps(observer.snapshot(), sort_keys=True)
        with pytest.raises(RuntimeError) as second:
            publisher._publish_once()
        assert first.value is second.value is error
        assert json.dumps(observer.snapshot(), sort_keys=True) == first_record
    assert publisher._publish_once == original and sys.gettrace() is None
    assert _window(observer)["thread_spans"]["available"] is True
    assert "private-canary" not in first_record


def test_foreign_trace_is_not_replaced() -> None:
    def foreign(frame: Any, event: str, arg: object) -> Any:
        return foreign

    previous = sys.gettrace()
    sys.settrace(foreign)
    try:
        observer = SelectedThreadSpans(_codes(_trusted))
        observer.start()
        assert _trusted() == 17
        record = observer.close()
        assert sys.gettrace() is foreign
        assert record["available"] is False and record["rows"] == []
    finally:
        sys.settrace(previous)


def test_foreign_replacement_is_preserved_and_marks_observation_unavailable() -> None:
    def foreign(frame: Any, event: str, arg: object) -> Any:
        return foreign

    previous = sys.gettrace()
    observer = SelectedThreadSpans(_codes(_trusted))
    observer.start()
    try:
        assert _trusted() == 17
        sys.settrace(foreign)
        record = observer.close()
        assert sys.gettrace() is foreign and record["available"] is False and record["rows"] == []
    finally:
        sys.settrace(previous)


@pytest.mark.parametrize("failure", ["raise", "nan", "backward"])
def test_bad_clock_never_replaces_actual_result_or_leaks_prose(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    samples = iter([(1.0, 1.0), (2.0, 2.0), (1.0, 1.0)])

    def clock() -> tuple[float, float]:
        if failure == "raise":
            raise OSError("private-canary-clock")
        if failure == "nan":
            return float("nan"), 0.0
        return next(samples)

    monkeypatch.setattr(SelectedThreadSpans, "_clock", staticmethod(clock))
    observer = SelectedThreadSpans(_codes(_trusted))
    observer.start()
    try:
        assert _trusted() == 17
    finally:
        record = observer.close()
    assert record["available"] is False and record["rows"] == [] and sys.gettrace() is None
    assert "private-canary" not in json.dumps(record, allow_nan=False)


@pytest.mark.parametrize("limit", ["_MAX_ACTIVE", "_MAX_CALLS"])
def test_observation_bounds_refuse_evidence_without_changing_calls(monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    monkeypatch.setattr(spans_module, limit, 1)

    def outer() -> int:
        return _trusted() + _trusted()

    observer = SelectedThreadSpans({**_codes(outer, "publication"), **_codes(_trusted)})
    observer.start()
    try:
        assert outer() == 34
    finally:
        record = observer.close()
    assert record["available"] is False and record["rows"] == [] and sys.gettrace() is None


def test_generator_resumptions_are_bounded_complete_spans() -> None:
    def values():
        yield 3
        yield 5

    observer = SelectedThreadSpans(_codes(values))
    observer.start()
    try:
        assert list(values()) == [3, 5]
    finally:
        record = observer.close()
    assert record["available"] is True
    assert cast(list[dict[str, Any]], record["rows"])[0]["calls"] == 3


def test_opt_in_default_leaves_existing_profile_shape_unchanged() -> None:
    class Publisher:
        def _publish_once(self) -> int:
            return _trusted()

    publisher = Publisher()
    observer = ReadinessProfile({"publication": publisher._publish_once}, enabled=True)
    with observer.attach(publisher):
        assert publisher._publish_once() == 17
    assert set(_window(observer)) == {"window", "completed", "available", "rows"}


def test_foreign_thread_cannot_attribute_events_or_clear_owner_trace() -> None:
    observer = SelectedThreadSpans(_codes(_trusted))
    observer.start()
    original_trace = sys.gettrace()
    records: list[dict[str, object]] = []

    def foreign() -> None:
        assert _trusted() == 17
        records.append(observer.close())

    thread = threading.Thread(target=foreign)
    thread.start()
    try:
        thread.join(4)
        assert not thread.is_alive()
        assert sys.gettrace() is original_trace
        assert records[0]["available"] is False and records[0]["rows"] == []
    finally:
        observer.close()
    assert sys.gettrace() is None
