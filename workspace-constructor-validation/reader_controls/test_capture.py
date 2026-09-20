"""Original-call forwarding and finite constructor observation controls."""

from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from constructor.capture import CURRENT, PARENTS, TAIL_ARGUMENTS, TAIL_STAGES, Capture
from constructor.hooks import CALLERS, LocalTime
from constructor.tail_hooks import TAIL_SITES


def capture() -> Capture:
    ticks = iter(range(100))
    return Capture(object(), clock=lambda: float(next(ticks)))


def modeled_tail(value: Capture) -> None:
    for index, stage in enumerate(TAIL_STAGES):
        workers, queue_limit = TAIL_ARGUMENTS[index]
        value.tail_call(stage, TAIL_SITES[stage], lambda: None, (), {}, workers=workers, queue_limit=queue_limit)


def nested(value: Capture, *, fail: BaseException | None = None) -> None:
    def at(index: int) -> Any:
        stage = list(PARENTS)[index]

        def original() -> Any:
            if index < 4:
                if index == 3 and not value.lost:
                    value.store = object()
                    value.adopt(object(), value.store)
                    value.acceptance(value.clock())
                at(index + 1)
                if index == 2:
                    modeled_tail(value)
                return None
            if fail is not None:
                raise fail
            return True

        return value.call(stage, CALLERS[stage], original, (), {})

    value.replacement(at, (0,), {})


def test_real_nested_calls_use_one_thread_stack_and_original_results() -> None:
    value = capture()
    nested(value)
    report = value.freeze()
    assert report["observation_complete"] is True
    assert [row["stage"] for row in report["rows"]] == list(PARENTS)
    assert [row["parent"] for row in report["rows"]] == [None, 0, 1, 2, 3]
    assert [row["returned"] for row in report["rows"]] == ["none"] * 4 + ["true"]
    assert CURRENT.get() is None


def test_identical_arguments_exception_and_partial_return_path() -> None:
    value, error = capture(), RuntimeError("PRIVATE_SENTINEL")
    with pytest.raises(RuntimeError) as caught:
        nested(value, fail=error)
    assert caught.value is error
    assert value.replacement_outcome == "exception"
    assert all(row["outcome"] == "exception" for row in value.rows)
    assert "PRIVATE_SENTINEL" not in json.dumps(value.freeze())
    assert value.freeze()["observation_complete"] is True
    assert CURRENT.get() is None


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(7), OSError("secret")])
def test_base_exception_identity_survives_failed_clock(error: BaseException) -> None:
    value = capture()

    def broken() -> Any:
        raise ValueError("PRIVATE_CLOCK")

    value.clock = broken
    with pytest.raises(type(error)) as caught:
        nested(value, fail=error)
    assert caught.value is error
    assert value.lost and not value.stack
    assert CURRENT.get() is None


def test_return_object_survives_recording_failure_and_arguments_are_unchanged() -> None:
    value, result, arg, kwarg = capture(), object(), object(), object()
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return result

    actual = value.replacement(lambda: value.call("invalid", "unknown", original, (arg,), {"key": kwarg}), (), {})
    assert actual is result and calls == [((arg,), {"key": kwarg})]
    assert value.lost


def test_wrong_thread_and_duplicate_phase_refuse_without_new_original_call() -> None:
    value = capture()
    calls = []

    def original() -> None:
        calls.append(1)

    def run() -> None:
        value.call("service_constructor", CALLERS["service_constructor"], original, (), {})
        value.call("service_constructor", CALLERS["service_constructor"], original, (), {})

    value.replacement(run, (), {})
    assert calls == [1, 1] and value.lost
    other = capture()
    thread = threading.Thread(target=lambda: other.replacement(original, (), {}))
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive() and other.lost and calls == [1, 1, 1]


def test_original_clock_called_once_and_only_matching_acceptance_is_recorded() -> None:
    value, original_value = capture(), 17.25
    calls = []

    class Clock:
        def monotonic(self) -> float:
            calls.append(1)
            return original_value

    class Sites:
        def site(self, _frame: Any) -> str:
            return "scripts.native_slo_workspace_lifecycle:run_lifecycle_cell.<locals>.prepare_service:169"

    proxy = LocalTime(Clock(), value, Sites())
    value.publisher = object()
    assert value.replacement(proxy.monotonic, (), {}) is original_value
    assert calls == [1] and value.accepted is original_value and value.acceptance_calls == 1
    assert proxy.monotonic() is original_value and calls == [1, 1] and value.acceptance_calls == 1


def test_no_activation_is_distinct_from_an_observed_constructor() -> None:
    report = capture().freeze()
    assert report["rows"] == [] and report["replacement_calls"] == 0
    assert report["replacement_outcome"] == "not_called" and report["accepted_monotonic"] is None


def test_factory_requires_original_store_and_parent_without_state_getters() -> None:
    value, store, publisher = capture(), object(), object()
    value.store = store

    def factory_join() -> None:
        with pytest.raises(ValueError, match="factory_parent"):
            value.adopt(publisher, store)
        value.rows = [{"stage": "hook_worker_constructor"}]
        value.stack = [0]
        with pytest.raises(ValueError, match="factory_identity"):
            value.adopt(publisher, object())
        value.adopt(publisher, store)
        with pytest.raises(ValueError, match="factory_identity"):
            value.adopt(publisher, store)
        value.stack.clear()

    value.replacement(factory_join, (), {})
    assert value.publisher is publisher and value.factory_handoffs == 1


def test_row_overflow_forwards_original_and_refuses_complete_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    from constructor import capture as module

    monkeypatch.setattr(module, "MAX_ROWS", 0)
    value = capture()
    nested(value)
    report = value.freeze()
    assert report["overflow"] is report["lost"] is True
    assert report["observation_complete"] is False and report["rows"] == []


def test_finite_schema_never_reads_publisher_condition_or_custom_projection() -> None:
    class Publisher:
        @property
        def _condition(self) -> Any:
            raise AssertionError("must not acquire or inspect")

        def __repr__(self) -> str:
            raise AssertionError("must not render")

    value = capture()
    value.publisher = Publisher()
    report = value.freeze()
    assert report["publisher_state_sampled"] is False
    assert "Publisher" not in json.dumps(report)


def test_exception_classification_never_calls_hostile_attribute_or_metaclass_hooks() -> None:
    calls: list[str] = []

    class HostileMeta(type):
        def __getattribute__(cls, name: str) -> Any:
            calls.append(name)
            raise KeyboardInterrupt("private metaclass")

    class HostileError(RuntimeError, metaclass=HostileMeta):
        def __getattribute__(self, name: str) -> Any:
            calls.append(name)
            raise SystemExit("private attribute")

    value, original = capture(), HostileError("private original")
    caught: BaseException | None = None
    try:
        nested(value, fail=original)
    except BaseException as error:
        caught = error
    assert caught is original and calls == []
    assert all(row["error"] == "runtime_error" for row in value.rows)
    assert value.freeze()["observation_complete"] is True


def test_code_image_refuses_hostile_constant_without_hash_or_class_hooks() -> None:
    from constructor.bindings import code_image

    calls: list[str] = []

    class HostileMeta(type):
        def __hash__(cls) -> int:
            calls.append("hash")
            raise KeyboardInterrupt("private hash")

    class Hostile(metaclass=HostileMeta):
        def __getattribute__(self, name: str) -> Any:
            calls.append(name)
            raise SystemExit("private attribute")

    original = nested.__code__
    changed = original.replace(co_consts=(*original.co_consts, Hostile()))
    with pytest.raises(RuntimeError, match="constructor_code_constant_shape"):
        code_image(changed)
    assert calls == []
