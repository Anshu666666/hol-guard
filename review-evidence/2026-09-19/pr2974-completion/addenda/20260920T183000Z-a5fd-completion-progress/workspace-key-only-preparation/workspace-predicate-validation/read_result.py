"""Admit exact original outputs separately from diagnostic observation completeness."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, cast

from admission import MAX_LEDGER, decode, reconstruct, require
from common import digest, write
from predicate.child import SCENARIOS

STAGES = {
    "await_ack",
    "prepare",
    "wait_ready",
    "record_error",
    "request_publish",
    "policy_input_changed",
    "database_policy_marker",
    "configuration_changed",
    "compiled_policy",
    "publish_once",
    "publisher_close",
    "register_workspace",
    "current_snapshot",
    "current_snapshot_binding",
    "last_error",
    "authenticated_readback",
    "readback_matches",
    "public_binding",
    "original_clock",
}


def admit_observation(value: dict[str, Any], scenario: str, cell: dict[str, Any]) -> dict[str, Any]:
    require(value.get("schema") == "hol-guard.workspace-predicate-cell.v1", "predicate_schema")
    require(value.get("scenario") == scenario and value.get("registered_workspaces") == 100, "predicate_cell")
    require(value.get("original_dispatch_calls") == value.get("matching_dispatch_calls") == 1, "dispatch_count")
    require(value.get("original_serve_exit") == 0 and value.get("original_return") == "dict", "serve_result")
    require(
        value.get("setup_failed") is False
        and value.get("hooks_restored") is True
        and value.get("dispatch_patch_restored") is True,
        "predicate_restore",
    )
    flags = value["original_result_flags"]
    require(flags["scenario_matches"] is True and flags["registered_workspaces"] is True, "result_identity")
    require(flags["publisher_contained"] is True, "original_publisher_not_contained")
    require(
        flags["passed"] == cell["passed"] and flags["failure_present"] == ("failure" in cell), "original_result_join"
    )
    observation = value["observation"]
    require(observation.get("schema") == "hol-guard.workspace-predicates.v2", "observation_schema")
    require(
        observation.get("observation_complete") is True
        and observation.get("lost") is False
        and observation.get("overflow") is False
        and observation.get("active_calls") == 0,
        "observation_incomplete",
    )
    rows = observation["rows"]
    require(type(rows) is list and 0 < len(rows) <= 1024, "row_bound")
    require(all(type(row) is dict for row in rows), "row_shape")
    rows = cast(list[dict[str, Any]], rows)
    for index, row in enumerate(rows):
        require(row["id"] == index and row["stage"] in STAGES and row["site"] != "unknown", "row_identity")
        parent = row["parent"]
        require(parent is None or (type(parent) is int and 0 <= parent < index), "parent_order")
        if row["stage"] != "original_clock":
            require(
                row["outcome"] in {"return", "exception"} and row["returned"] is not None, "original_call_incomplete"
            )
            require(row["exit_seconds"] >= row["entry_seconds"] >= 0, "interval_order")
    awaits = [row for row in rows if row["stage"] == "await_ack"]
    require(1 <= len(awaits) <= 2 and observation["await_calls"] == len(awaits), "await_roster")
    require([row["await"] for row in awaits] == list(range(1, len(awaits) + 1)), "await_order")
    return {
        "scenario": scenario,
        "original_cell_passed": cell["passed"],
        "await_calls": len(awaits),
        "observed_rows": len(rows),
        "diagnostic_complete": True,
        "exact_internal_commit_time_proven": False,
        "historical_cause_proven": False,
    }


def admit(
    report: dict[str, Any],
    cells: list[dict[str, Any]],
    invocation: dict[str, Any],
    observations: list[dict[str, Any]],
    *,
    returncode: int,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    require(
        returncode == 1
        and invocation["original_main_calls"] == 1
        and invocation["original_main_return"] == 1
        and invocation["original_main_raised"] is False,
        "original_invocation",
    )
    require(
        invocation["forwarding"]["declared_fixture_roster_complete"] is True
        and invocation["forwarding"]["patches_restored"] is True,
        "parent_forwarding",
    )
    require(
        report["schema"] == "hol-guard.native-workspace-lifecycle.v1"
        and report["counts"] == [100]
        and report["scenarios"] == list(SCENARIOS)
        and report["declared_cells_visited"] is True,
        "original_roster",
    )
    for flag in (
        "complete_lifecycle_matrix_visited",
        "implemented_checks_passed",
        "headline_timing_eligible",
        "full_rsp_128_129_qualification",
    ):
        require(report[flag] is False, "original_scope")
    for key in ("build_sha", "rule_digest", "runtime_sha256"):
        require(report["runtime"][key] == runtime[key], "runtime_identity")
    require(
        report["runtime"]["mode"] == "auto" and report["runtime"]["package_origin"] == "installed", "installed_default"
    )
    require(len(cells) == len(observations) == len(SCENARIOS), "terminal_count")
    summaries = []
    for index, scenario in enumerate(SCENARIOS):
        cell = cells[index]
        require(
            cell["scenario"] == scenario
            and cell["registered_workspaces"] == 100
            and cell["status"] == "completed"
            and type(cell["passed"]) is bool,
            "cell_identity",
        )
        require(cell.get("readiness_deadline_ms") == 400, "original_deadline")
        summaries.append(admit_observation(observations[index], scenario, cell))
    return {
        "schema": "hol-guard.workspace-predicate-admission.v1",
        "diagnostic_complete": True,
        "original_cells": summaries,
        "original_complete_matrix_passed": False,
        "original_all_selected_passed": all(cell["passed"] for cell in cells),
        "headline_timing_eligible": False,
        "qualification_complete": False,
        "scope": "actual_original_calls_with_added_observation_no_extra_probe",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--returncode", type=int, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    sys.path.insert(0, str(source))
    report_path, ledger_path = output / "workspace-lifecycle.json", output / "workspace-lifecycle.jsonl"
    digest(report_path, MAX_LEDGER)
    digest(ledger_path, MAX_LEDGER)
    report = decode(report_path.read_bytes())
    cells = reconstruct(report, ledger_path.read_bytes())
    write(output / "reconstructed-cells.json", cells)
    observations = []
    for index in range(len(SCENARIOS)):
        path = output / "predicates" / f"{index:02d}.json"
        digest(path, 1024 * 1024)
        observations.append(decode(path.read_bytes()))
    invocation = decode((output / "original-invocation.json").read_bytes())
    installed = decode((output / "installed-before.json").read_bytes())["runtime"]
    runtime = {
        "build_sha": installed["source_sha"],
        "rule_digest": installed["rule_digest"],
        "runtime_sha256": installed["runtime_sha256"],
    }
    result = admit(report, cells, invocation, observations, returncode=args.returncode, runtime=runtime)
    write(output / "predicate-admission.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
