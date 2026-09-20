"""Refuse invented ownership, intervals, privacy fields and partial admission."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from constructor.reader import admit_phases
from reader_controls.test_capture import capture, nested


def good() -> dict[str, Any]:
    value = capture()
    nested(value)
    return value.freeze()


def test_only_matched_successful_exits_derive_adjacent_regions() -> None:
    result = admit_phases(good())
    assert result["all_five_returned"] is True
    assert set(result["matched_exit_regions_ms"]) == {
        "worker_after_wait",
        "services_after_worker",
        "http_after_services",
        "service_after_http",
    }
    assert set(result["matched_exit_regions_ms"].values()) == {1000.0}
    assert result["acceptance_to_successful_returns_ms"] == {
        "service_constructor": 6000.0,
        "http_constructor": 5000.0,
        "request_services": 4000.0,
        "hook_worker_constructor": 3000.0,
        "publisher_wait": 2000.0,
    }
    assert result["inclusive_spans_summed"] is result["leaf_cost_proven"] is False


def test_original_exception_has_no_invented_successful_exit_tails() -> None:
    value = capture()
    with pytest.raises(RuntimeError):
        nested(value, fail=RuntimeError("private"))
    result = admit_phases(value.freeze())
    assert result["all_five_returned"] is False and result["matched_exit_regions_ms"] == {}


def test_zero_activation_remains_distinct_from_constructor_coverage() -> None:
    result = admit_phases(capture().freeze())
    assert result["replacement_calls"] == 0 and result["observed_phases"] == 0
    assert result["all_five_returned"] is False and result["matched_exit_regions_ms"] == {}


def test_partial_constructor_exception_never_invents_worker_or_wait() -> None:
    from constructor.hooks import CALLERS

    value, error, calls = capture(), RuntimeError("private"), []

    def inner() -> None:
        calls.append("http")
        raise error

    def outer() -> None:
        calls.append("service")
        value.call("http_constructor", CALLERS["http_constructor"], inner, (), {})

    with pytest.raises(RuntimeError) as caught:
        value.replacement(
            lambda: value.call("service_constructor", CALLERS["service_constructor"], outer, (), {}), (), {}
        )
    assert caught.value is error and calls == ["service", "http"]
    result = admit_phases(value.freeze())
    assert result["observed_phases"] == 2 and result["matched_exit_regions_ms"] == {}


@pytest.mark.parametrize(
    "field,value",
    [
        ("lost", True),
        ("overflow", True),
        ("observation_complete", False),
        ("active_calls", 1),
        ("factory_handoffs", 0),
        ("acceptance_calls", 0),
        ("replacement_calls", True),
        ("publisher_state_sampled", True),
        ("origin_monotonic", float("nan")),
        ("accepted_monotonic", float("inf")),
        ("accepted_monotonic", -1),
        ("replacement_outcome", "not_called"),
        ("extra", {"private": "value"}),
    ],
)
def test_report_mutations_refuse(field: str, value: Any) -> None:
    report = good()
    report[field] = value
    with pytest.raises((ValueError, TypeError)):
        admit_phases(report)


@pytest.mark.parametrize(
    "index,field,value",
    [
        (0, "parent", 0),
        (1, "parent", None),
        (2, "stage", "unknown"),
        (3, "site", "PRIVATE"),
        (4, "entry_seconds", -1),
        (4, "exit_seconds", 900),
        (0, "exit_seconds", 0),
        (4, "returned", "none"),
        (0, "returned", "true"),
        (2, "error", "PRIVATE"),
        (4, "outcome", "pending"),
        (3, "extra", {"private": "value"}),
    ],
)
def test_phase_mutations_refuse(index: int, field: str, value: Any) -> None:
    report = good()
    report["rows"][index][field] = value
    with pytest.raises((ValueError, TypeError)):
        admit_phases(report)


def test_duplicate_and_missing_phase_refuse_normal_constructor_claim() -> None:
    report = good()
    duplicate = copy.deepcopy(report)
    duplicate["rows"].append(dict(report["rows"][-1]))
    with pytest.raises(ValueError):
        admit_phases(duplicate)
    report["rows"].pop()
    with pytest.raises(ValueError):
        admit_phases(report)
