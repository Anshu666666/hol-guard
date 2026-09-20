"""Strict data-only admission of fixed workspace diagnostic records."""

from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any, cast

from .capture import DETAIL_KEYS, ERROR_CODES, MAX_COUNTER, MAX_PUBLISHERS, MAX_ROWS, STAGES
from .child import MAX_REPORT_BYTES, SCENARIOS

STATE_KEYS = {"epoch", "acked", "closed", "error", "sample_before_ms", "sample_after_ms"}
ROW_KEYS = {
    "id",
    "parent",
    "stage",
    "publisher",
    "started_ms",
    "finished_ms",
    "call_enter_ms",
    "call_return_ms",
    "before",
    "after",
    "outcome",
    "exception",
    "details",
}
OBSERVATION_KEYS = {
    "schema",
    "origin",
    "state_time_scope",
    "call_time_scope",
    "rows",
    "row_bound",
    "publisher_bound",
    "publishers_observed",
    "calls_in_flight",
    "observation_lost",
    "overflow",
    "observation_complete",
    "original_results_preserved",
    "additional_native_or_http_probes",
    "headline_timing_eligible",
    "qualification_complete",
}
CELL_KEYS = {
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
RESULT_FLAG_KEYS = {
    "registered_workspaces",
    "scenario_matches",
    "passed",
    "status_completed",
    "publisher_contained",
    "recovered_request_present",
    "failure_present",
}


def require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 120000


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "workspace_diagnostic_duplicate_key")
        result[key] = value
    return result


def _constant(_value: str) -> Any:
    raise ValueError("workspace_diagnostic_nonfinite_json")


def read_cell(path: Path, scenario: str) -> dict[str, Any]:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), "workspace_diagnostic_file_type")
    require(0 < metadata.st_size <= MAX_REPORT_BYTES, "workspace_diagnostic_file_bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(
            (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino), "workspace_diagnostic_file_identity"
        )
        raw = stream.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(stream.fileno())
    before_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    require(len(raw) == metadata.st_size and before_identity == after_identity, "workspace_diagnostic_file_size")
    report = json.loads(raw, object_pairs_hook=strict_object, parse_constant=_constant)
    return validate_cell(report, scenario)


def _state(value: Any, low: float, high: float) -> None:
    require(type(value) is dict and set(value) == STATE_KEYS, "workspace_diagnostic_state_shape")
    value = cast(dict[str, Any], value)
    require(type(value["epoch"]) is int and 0 <= value["epoch"] <= MAX_COUNTER, "workspace_diagnostic_epoch")
    require(type(value["acked"]) is bool and type(value["closed"]) is bool, "workspace_diagnostic_state_flags")
    require(
        type(value["error"]) is str and value["error"] in ERROR_CODES | {"none", "other"}, "workspace_diagnostic_error"
    )
    before, after = value["sample_before_ms"], value["sample_after_ms"]
    require(number(before) and number(after) and low <= before <= after <= high, "workspace_diagnostic_state_interval")


def _details(value: Any) -> None:
    require(type(value) is dict and set(value) <= DETAIL_KEYS, "workspace_diagnostic_details")
    value = cast(dict[str, Any], value)
    for key, item in value.items():
        if key == "error":
            valid = type(item) is str and item in ERROR_CODES | {"none", "other"}
        elif key == "executor_kind":
            valid = type(item) is str and item in {"general", "control", "other"}
        elif key == "deadline_from_origin_ms":
            valid = type(item) in {int, float} and math.isfinite(item) and abs(item) < 1000000
        elif key in {"observed_count", "changed_hint_count"}:
            valid = type(item) is int and 0 <= item <= MAX_COUNTER
        else:
            valid = type(item) is bool
        require(valid, "workspace_diagnostic_detail_value")


def validate_cell(report: Any, scenario: str) -> dict[str, Any]:
    require(type(report) is dict and set(report) == CELL_KEYS, "workspace_diagnostic_cell_shape")
    report = cast(dict[str, Any], report)
    require(report["schema"] == "hol-guard.workspace-cause-cell.v1", "workspace_diagnostic_schema")
    require(scenario in SCENARIOS and report["scenario"] == scenario, "workspace_diagnostic_scenario")
    require(
        type(report["registered_workspaces"]) is int and report["registered_workspaces"] == 100,
        "workspace_diagnostic_count",
    )
    for key in ("original_dispatch_calls", "matching_dispatch_calls"):
        require(type(report[key]) is int and report[key] == 1, "workspace_diagnostic_call_count")
    require(
        type(report["original_serve_exit"]) is int and report["original_serve_exit"] == 0, "workspace_diagnostic_serve"
    )
    require(
        type(report["original_readiness_deadline_ms"]) is int and report["original_readiness_deadline_ms"] == 400,
        "workspace_diagnostic_budget",
    )
    require(report["original_return"] == "dict", "workspace_diagnostic_original_return")
    flags = report["original_result_flags"]
    require(
        type(flags) is dict and set(flags) == RESULT_FLAG_KEYS and all(type(v) is bool for v in flags.values()),
        "workspace_diagnostic_result_flags",
    )
    flags = cast(dict[str, bool], flags)
    require(flags["registered_workspaces"] and flags["scenario_matches"], "workspace_diagnostic_original_identity")
    require(flags["status_completed"] and flags["publisher_contained"], "workspace_diagnostic_original_cleanup")
    for key in ("hooks_restored", "dispatch_patch_restored", "original_result_or_exception_preserved"):
        require(report[key] is True, "workspace_diagnostic_restore")
    for key in ("setup_failed", "headline_timing_eligible", "qualification_complete"):
        require(report[key] is False, "workspace_diagnostic_scope")
    require(
        type(report["additional_native_or_http_probes"]) is int and report["additional_native_or_http_probes"] == 0,
        "workspace_diagnostic_probes",
    )
    observation = report["observation"]
    require(
        type(observation) is dict and set(observation) == OBSERVATION_KEYS, "workspace_diagnostic_observation_shape"
    )
    observation = cast(dict[str, Any], observation)
    require(
        observation["schema"] == "hol-guard.workspace-cause-observation.v1", "workspace_diagnostic_observation_schema"
    )
    require(observation["origin"] == "owned_lifecycle_dispatch_entry_monotonic", "workspace_diagnostic_origin")
    require(
        observation["state_time_scope"] == "interval_brackets_direct_lock_read_not_transition_commit",
        "workspace_diagnostic_state_scope",
    )
    require(
        observation["call_time_scope"] == "brackets_original_call_with_diagnostic_overhead_explicit",
        "workspace_diagnostic_call_scope",
    )
    for key, expected in (
        ("row_bound", MAX_ROWS),
        ("publisher_bound", MAX_PUBLISHERS),
        ("calls_in_flight", 0),
        ("additional_native_or_http_probes", 0),
    ):
        require(type(observation[key]) is int and observation[key] == expected, "workspace_diagnostic_bound")
    for key in ("observation_complete", "original_results_preserved"):
        require(observation[key] is True, "workspace_diagnostic_incomplete")
    for key in ("observation_lost", "overflow", "headline_timing_eligible", "qualification_complete"):
        require(observation[key] is False, "workspace_diagnostic_loss")
    publishers = observation["publishers_observed"]
    require(type(publishers) is int and 1 <= publishers <= MAX_PUBLISHERS, "workspace_diagnostic_publishers")
    rows = observation["rows"]
    require(type(rows) is list and 0 < len(rows) <= MAX_ROWS, "workspace_diagnostic_rows")
    rows = cast(list[Any], rows)
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == ROW_KEYS, "workspace_diagnostic_row_shape")
        row = cast(dict[str, Any], row)
        require(
            type(row["id"]) is int and row["id"] == index and row["stage"] in STAGES,
            "workspace_diagnostic_row_identity",
        )
        parent = row["parent"]
        require(parent is None or (type(parent) is int and 0 <= parent < index), "workspace_diagnostic_parent")
        times = [row[name] for name in ("started_ms", "call_enter_ms", "call_return_ms", "finished_ms")]
        require(all(number(v) for v in times) and times == sorted(times), "workspace_diagnostic_call_interval")
        if parent is not None:
            require(
                rows[parent]["call_enter_ms"] <= times[0] and times[-1] <= rows[parent]["call_return_ms"],
                "workspace_diagnostic_nested_interval",
            )
        publisher = row["publisher"]
        if publisher is None:
            require(row["before"] is None and row["after"] is None, "workspace_diagnostic_unowned_state")
        else:
            require(type(publisher) is int and 1 <= publisher <= publishers, "workspace_diagnostic_publisher")
            _state(row["before"], times[0], times[1])
            _state(row["after"], times[2], times[3])
        require(row["outcome"] in {"none", "true", "false", "value", "exception"}, "workspace_diagnostic_outcome")
        require(
            row["exception"]
            in {"none", "NativePolicySnapshotError", "RuntimeError", "OSError", "ValueError", "TimeoutError", "other"},
            "workspace_diagnostic_exception",
        )
        require((row["outcome"] == "exception") == (row["exception"] != "none"), "workspace_diagnostic_exception_pair")
        _details(row["details"])
    return report


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    """Produce observations, not inferred unmeasured rejection/commit instants."""
    rows = report["observation"]["rows"]
    stages: dict[str, int] = {}
    for row in rows:
        stages[row["stage"]] = stages.get(row["stage"], 0) + 1
    awaits = [row for row in rows if row["stage"] == "await_ack"]
    recovered = awaits[1] if len(awaits) == 2 else None
    deadline = recovered["details"].get("deadline_from_origin_ms") if recovered is not None else None
    return {
        "scenario": report["scenario"],
        "original_result_flags": report["original_result_flags"],
        "stage_counts": stages,
        "recovered_await_observed": recovered is not None,
        "recovered_deadline_in_dispatch_origin_ms": deadline,
        "acceptance_in_dispatch_origin_derived_from_original_deadline_ms": deadline - 400
        if deadline is not None
        else None,
        "accepted_origin_derivation": "original source sets deadline=accepted+0.4; no timestamp is changed",
        "fixed_errors": [row["details"]["error"] for row in rows if row["stage"] == "record_error"],
        "resident_confirmation_outcomes": [
            {"row_id": row["id"], "outcome": row["outcome"], "details": row["details"]}
            for row in rows
            if row["stage"] == "resident_confirm"
        ],
        "ack_or_epoch_or_closed_state_changes": [
            row["id"]
            for row in rows
            if row["before"] is not None
            and row["after"] is not None
            and any(row["before"][key] != row["after"][key] for key in ("acked", "epoch", "closed"))
        ],
        "state_transition_instant_or_exact_unwrapped_predicate_inferred": False,
        "original_full_matrix_pass_inferred": False,
    }
