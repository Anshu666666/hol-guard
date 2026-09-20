"""Pure finite reader controls, without a native workload or generated authority."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from read_result import admit_observation


def good() -> tuple[dict[str, Any], dict[str, Any]]:
    cell = {"passed": False, "failure": {"code": "preserved_original"}}
    row = {
        "id": 0,
        "stage": "await_ack",
        "site": "fixed_source:42",
        "parent": None,
        "await": 1,
        "outcome": "exception",
        "returned": {"exception": "RuntimeError"},
        "entry_seconds": 0.1,
        "exit_seconds": 0.2,
    }
    report = {
        "schema": "hol-guard.workspace-predicate-cell.v1",
        "scenario": "first_admission_fault",
        "registered_workspaces": 100,
        "original_dispatch_calls": 1,
        "matching_dispatch_calls": 1,
        "original_serve_exit": 0,
        "original_return": "dict",
        "setup_failed": False,
        "hooks_restored": True,
        "dispatch_patch_restored": True,
        "original_result_flags": {
            "scenario_matches": True,
            "registered_workspaces": True,
            "passed": False,
            "failure_present": True,
            "publisher_contained": True,
        },
        "observation": {
            "schema": "hol-guard.workspace-predicates.v3",
            "observation_complete": True,
            "lost": False,
            "overflow": False,
            "active_calls": 0,
            "await_calls": 1,
            "factory_handoffs": 0,
            "worker_handoffs": 0,
            "publisher_instances": 1,
            "rows": [row],
        },
    }
    return report, cell


def test_complete_diagnostic_keeps_original_failed_verdict() -> None:
    report, cell = good()
    before = copy.deepcopy((report, cell))
    result = admit_observation(report, "first_admission_fault", cell)
    assert result["diagnostic_complete"] is True and result["original_cell_passed"] is False
    assert result["historical_cause_proven"] is False
    assert (report, cell) == before


@pytest.mark.parametrize(
    "change",
    ["lost", "overflow", "active", "unknown", "parent", "original", "count", "missing", "restore", "containment"],
)
def test_incomplete_or_changed_observation_is_refused(change: str) -> None:
    report, cell = good()
    observation = report["observation"]
    if change in {"lost", "overflow"}:
        observation[change] = True
    elif change == "active":
        observation["active_calls"] = 1
    elif change == "unknown":
        observation["rows"][0]["site"] = "unknown"
    elif change == "parent":
        observation["rows"][0]["parent"] = 0
    elif change == "original":
        report["original_result_flags"]["passed"] = True
    elif change == "count":
        report["matching_dispatch_calls"] = 2
    elif change == "containment":
        report["original_result_flags"]["publisher_contained"] = False
    elif change == "missing":
        observation["rows"] = []
    else:
        report["hooks_restored"] = False
    with pytest.raises(ValueError):
        admit_observation(report, "first_admission_fault", cell)
