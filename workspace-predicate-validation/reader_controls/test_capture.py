"""Untimed forwarding, privacy, and finite observation controls."""

from __future__ import annotations

import json
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from predicate.bindings import Registry
from predicate.capture import CURRENT, Capture
from predicate.hooks import LocalTime
from predicate.projection import fingerprint, snapshot


def fixture() -> tuple[Capture, Any]:
    publisher = SimpleNamespace(_condition=threading.Condition(), _acked=True, _closed=False, _epoch=1, _snapshot=None)
    worker = SimpleNamespace(policy_snapshot_publisher=publisher)
    session = SimpleNamespace(store=object(), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    return Capture(session), publisher


def test_same_arguments_and_return_object() -> None:
    capture, _ = fixture()
    value, positional, keyword = object(), object(), object()
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return value

    assert capture.call("test", "owned", original, (positional,), {"key": keyword}) is value
    assert calls == [((positional,), {"key": keyword})]
    assert capture.freeze()["observation_complete"] is True


def test_original_base_exception_identity_survives_recording_failure() -> None:
    capture, _ = fixture()
    error = KeyboardInterrupt()

    def original() -> None:
        raise error

    def broken(*_args: Any) -> Any:
        raise ValueError("PRIVATE")

    capture.state = broken
    with pytest.raises(KeyboardInterrupt) as caught:
        capture.call("test", "owned", original, (), {})
    assert caught.value is error
    assert capture.freeze()["observation_complete"] is False


def test_nested_mutation_does_not_rewrite_projection_or_export_private_values() -> None:
    capture, _ = fixture()
    value = {
        "generation": 1,
        "mode": "enforce",
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "command_extensions": {"secret": "PRIVATE_SENTINEL"},
    }
    result = capture.call("snapshot", "owned", lambda: value, (), {}, project=snapshot)
    projected = capture.rows[0]["returned"]
    result["command_extensions"]["secret"] = "MUTATED_SENTINEL"
    assert projected["command_sha256"] == fingerprint({"secret": "PRIVATE_SENTINEL"})
    encoded = json.dumps(capture.freeze())
    assert "PRIVATE_SENTINEL" not in encoded and "MUTATED_SENTINEL" not in encoded


@pytest.mark.parametrize(
    "value",
    [object(), {1: "x"}, float("nan"), [0] * 32769, "x" * (512 * 1024 + 1)],
    ids=["opaque", "nonstring_key", "nonfinite", "nodes", "text"],
)
def test_closed_projection_rejects_unknown_or_over_bound(value: Any) -> None:
    with pytest.raises(ValueError):
        fingerprint(value)


def test_custom_mapping_and_hash_hooks_never_called() -> None:
    calls = []

    class Custom(dict[str, Any]):
        def items(self) -> Any:
            calls.append("items")
            raise AssertionError

    class Hasher:
        def __hash__(self) -> int:
            calls.append("hash")
            raise AssertionError

    with pytest.raises(ValueError):
        snapshot(Custom())
    with pytest.raises(ValueError):
        snapshot({"mode": Hasher()})
    assert calls == []


def test_lock_contention_does_not_skip_original() -> None:
    capture, _ = fixture()
    value = object()
    with capture.lock:
        assert capture.call("test", "owned", lambda: value, (), {}) is value
    assert capture.freeze()["lost"] is True


def test_publisher_try_lock_loss_remains_incomplete() -> None:
    capture, publisher = fixture()
    entered, release = threading.Event(), threading.Event()

    def hold() -> None:
        with publisher._condition:
            entered.set()
            assert release.wait(2)

    worker = threading.Thread(target=hold)
    worker.start()
    try:
        assert entered.wait(2)
        assert capture.call("test", "owned", lambda: True, (), {}) is True
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert capture.freeze()["lost"] is True


def test_overflow_and_inflight_freeze_cannot_pass() -> None:
    capture, _ = fixture()
    for _ in range(1025):
        capture.call("test", "owned", lambda: None, (), {})
    assert len(capture.rows) == 1024
    assert capture.freeze()["observation_complete"] is False
    capture, _ = fixture()
    reports = []
    capture.call("test", "owned", lambda: reports.append(capture.freeze()), (), {})
    assert reports[0]["active_calls"] == 1
    assert reports[0]["observation_complete"] is False
    assert capture.lost is True


def test_local_clock_returns_same_values_and_sleeps_global_untouched() -> None:
    capture, _ = fixture()
    registry = Registry.__new__(Registry)
    registry.codes, registry.sites = {}, {}
    registry.add(sys._getframe().f_code, "control")
    values = iter([12.5, 13.75])
    sleeps = []
    original_global = time.monotonic
    alias = LocalTime(SimpleNamespace(monotonic=lambda: next(values), sleep=sleeps.append), capture, registry)
    assert alias.monotonic() == 12.5
    assert alias.monotonic() == 13.75
    alias.sleep(0.005)
    assert sleeps == [0.005] and time.monotonic is original_global
    assert [row["original_monotonic"] for row in capture.rows] == [12.5, 13.75]


def test_unknown_actual_code_object_is_refused() -> None:
    registry = Registry.__new__(Registry)
    registry.codes, registry.sites = {}, {}
    with pytest.raises(RuntimeError, match="unknown_call_site"):
        registry.site(sys._getframe())


def test_freeze_projection_failure_does_not_replace_original_return() -> None:
    capture, _ = fixture()
    value = object()

    def broken(_value: Any) -> Any:
        raise ValueError("private")

    assert capture.call("test", "owned", lambda: value, (), {}, project=broken) is value
    assert capture.freeze()["observation_complete"] is False
    assert CURRENT.get() is None
