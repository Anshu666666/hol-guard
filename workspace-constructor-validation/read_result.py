"""Admit exact original outputs separately from diagnostic observation completeness."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, cast

from admission import MAX_LEDGER, decode, reconstruct, require
from common import digest, write
from constructor.child import SCENARIOS
from constructor.reader import admit_phases


def admit_observation(value: dict[str, Any], scenario: str, cell: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema",
        "scenario",
        "registered_workspaces",
        "original_dispatch_calls",
        "original_return",
        "original_result_flags",
        "setup_failed",
        "hooks_restored",
        "observation",
        "original_readiness_deadline_ms",
        "original_result_or_exception_preserved",
        "additional_native_or_http_probes",
        "headline_timing_eligible",
        "qualification_complete",
        "matching_dispatch_calls",
        "original_serve_exit",
        "dispatch_patch_restored",
    }
    require(type(value) is dict and set(value) == expected, "constructor_cell_fields")
    require(
        all(
            type(value[name]) is int
            for name in (
                "registered_workspaces",
                "original_dispatch_calls",
                "matching_dispatch_calls",
                "original_serve_exit",
                "original_readiness_deadline_ms",
                "additional_native_or_http_probes",
            )
        ),
        "constructor_scalar_types",
    )
    require(value["schema"] == "hol-guard.workspace-constructor-cell.v1", "constructor_schema")
    require(value["scenario"] == scenario and value["registered_workspaces"] == 100, "constructor_cell")
    require(value["original_dispatch_calls"] == value["matching_dispatch_calls"] == 1, "dispatch_count")
    require(value["original_serve_exit"] == 0 and value["original_return"] == "dict", "serve_result")
    require(
        value["setup_failed"] is False and value["hooks_restored"] is True and value["dispatch_patch_restored"] is True,
        "restore",
    )
    require(value["original_readiness_deadline_ms"] == 400 and value["additional_native_or_http_probes"] == 0, "budget")
    require(
        value["original_result_or_exception_preserved"] is True
        and value["headline_timing_eligible"] is False
        and value["qualification_complete"] is False,
        "scope",
    )
    flags = value["original_result_flags"]
    require(
        type(flags) is dict
        and set(flags)
        == {
            "registered_workspaces",
            "scenario_matches",
            "passed",
            "status_completed",
            "publisher_contained",
            "recovered_request_present",
            "failure_present",
        }
        and all(type(item) is bool for item in flags.values()),
        "flags",
    )
    flags = cast(dict[str, bool], flags)
    require(
        flags["scenario_matches"]
        and flags["registered_workspaces"]
        and flags["status_completed"]
        and flags["publisher_contained"],
        "original_identity_and_containment",
    )
    require(
        flags["passed"] == cell["passed"]
        and flags["failure_present"] == ("failure" in cell)
        and flags["recovered_request_present"] == ("requests" in cell),
        "original_result_join",
    )
    summary = admit_phases(value["observation"])
    if summary["replacement_outcome"] == "return":
        replacement = cell.get("service_replacement")
        require(
            type(replacement) is dict
            and all(
                replacement.get(key) is True
                for key in (
                    "old_publisher_stopped",
                    "old_resident_contained",
                    "old_service_contained",
                    "old_owner_lock_released",
                    "same_owned_home_identity",
                    "fresh_store_and_service",
                    "cold_publisher_without_ack",
                )
            ),
            "original_replacement_identity",
        )
    if cell["passed"]:
        require(
            summary["all_five_returned"] is True
            and type(cell.get("fault")) is dict
            and type(cell.get("requests")) is dict,
            "fault_and_receipt_presence",
        )
        require(
            all(
                cell["fault"].get(key) is True
                for key in (
                    "real_accepted_reply_discarded",
                    "production_ack_error_observed",
                    "first_error_withheld_ack",
                    "subsequent_transport_forwarded",
                )
            ),
            "original_fault_proof",
        )
        require(
            cell["fault"].get("successful_ack_fabricated") is False and cell["requests"].get("passed") is True,
            "original_receipt_proof",
        )
    return {"scenario": scenario, "original_cell_passed": cell["passed"], "diagnostic_complete": True, **summary}


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
        "schema": "hol-guard.workspace-constructor-admission.v1",
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
        path = output / "constructors" / f"{index:02d}.json"
        digest(path, 64 * 1024)
        observations.append(decode(path.read_bytes()))
    invocation = decode((output / "original-invocation.json").read_bytes())
    installed = decode((output / "installed-before.json").read_bytes())["runtime"]
    runtime = {
        "build_sha": installed["source_sha"],
        "rule_digest": installed["rule_digest"],
        "runtime_sha256": installed["runtime_sha256"],
    }
    result = admit(report, cells, invocation, observations, returncode=args.returncode, runtime=runtime)
    write(output / "constructor-admission.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
