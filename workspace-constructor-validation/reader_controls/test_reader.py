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


def test_partial_exception_cannot_claim_factory_without_worker() -> None:
    report = good()
    report["rows"] = report["rows"][:2]
    for row in report["rows"]:
        row.update(outcome="exception", returned=None, error="runtime_error")
    report.update(replacement_outcome="exception", accepted_monotonic=None, acceptance_calls=0, factory_handoffs=0)
    assert admit_phases(report)["observed_phases"] == 2
    report["factory_handoffs"] = 1
    with pytest.raises(ValueError, match="constructor_factory_parent"):
        admit_phases(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_dispatch_calls", True),
        ("original_dispatch_calls", 1.0),
        ("matching_dispatch_calls", True),
        ("original_serve_exit", False),
        ("original_serve_exit", 0.0),
        ("registered_workspaces", 100.0),
        ("original_readiness_deadline_ms", 400.0),
        ("additional_native_or_http_probes", False),
    ],
)
def test_cell_scalar_types_refuse_boolean_or_float_counts(field: str, value: Any) -> None:
    from read_result import admit_observation

    scenario = "first_admission_fault"
    cell = {"passed": False, "failure": {}}
    report = {
        "schema": "hol-guard.workspace-constructor-cell.v1",
        "scenario": scenario,
        "registered_workspaces": 100,
        "original_dispatch_calls": 1,
        "matching_dispatch_calls": 1,
        "original_serve_exit": 0,
        "original_return": "dict",
        "original_result_flags": {
            "registered_workspaces": True,
            "scenario_matches": True,
            "passed": False,
            "status_completed": True,
            "publisher_contained": True,
            "recovered_request_present": False,
            "failure_present": True,
        },
        "setup_failed": False,
        "hooks_restored": True,
        "dispatch_patch_restored": True,
        "observation": capture().freeze(),
        "original_readiness_deadline_ms": 400,
        "original_result_or_exception_preserved": True,
        "additional_native_or_http_probes": 0,
        "headline_timing_eligible": False,
        "qualification_complete": False,
    }
    assert admit_observation(report, scenario, cell)["replacement_calls"] == 0
    report[field] = value
    with pytest.raises(ValueError, match="constructor_scalar_types"):
        admit_observation(report, scenario, cell)
