"""Strict finite schema and matched-exit constructor regions."""

from __future__ import annotations

from typing import Any, cast

from .capture import PARENTS, finite
from .hooks import CALLERS
from .tail_reader import admit_tail

FIELDS = {
    "schema",
    "clock_origin",
    "origin_monotonic",
    "accepted_monotonic",
    "acceptance_calls",
    "replacement_calls",
    "replacement_outcome",
    "factory_handoffs",
    "rows",
    "tail_rows",
    "active_tail_calls",
    "active_calls",
    "lost",
    "overflow",
    "observation_complete",
    "publisher_state_sampled",
    "constructor_thread_only",
    "background_publisher_observed_by_this_collector",
    "observer_overhead_included",
}
ROW_FIELDS = {"id", "stage", "site", "parent", "entry_seconds", "exit_seconds", "outcome", "returned", "error"}
ERRORS = {"interrupt", "exit", "timeout", "os_error", "value_error", "runtime_error", "exception", "base_exception"}
REGIONS = (
    ("worker_after_wait", "hook_worker_constructor", "publisher_wait"),
    ("services_after_worker", "request_services", "hook_worker_constructor"),
    ("http_after_services", "http_constructor", "request_services"),
    ("service_after_http", "service_constructor", "http_constructor"),
)


def require(value: Any, reason: str) -> None:
    if value is not True:
        raise ValueError("constructor_" + reason)


def admit_phases(value: Any) -> dict[str, Any]:
    require(type(value) is dict and set(value) == FIELDS, "schema_fields")
    require(value["schema"] == "hol-guard.workspace-constructor-phases.v2", "schema")
    require(value["clock_origin"] == "constructor_dispatch_monotonic", "clock_origin")
    for name in ("observation_complete", "constructor_thread_only", "observer_overhead_included"):
        require(value[name] is True, "incomplete")
    for name in ("lost", "overflow", "publisher_state_sampled", "background_publisher_observed_by_this_collector"):
        require(value[name] is False, "scope")
    require(type(value["active_calls"]) is int and value["active_calls"] == 0, "active")
    require(type(value["active_tail_calls"]) is int and value["active_tail_calls"] == 0, "tail_active")
    for name in ("replacement_calls", "factory_handoffs", "acceptance_calls"):
        require(type(value[name]) is int and value[name] in {0, 1}, "count")
    origin = finite(value["origin_monotonic"])
    accepted = value["accepted_monotonic"]
    if accepted is not None:
        require(
            finite(accepted) >= origin and value["acceptance_calls"] == value["factory_handoffs"] == 1, "acceptance"
        )
    else:
        require(value["acceptance_calls"] == 0, "acceptance_count")
    rows = value["rows"]
    require(type(rows) is list and len(rows) <= 5, "row_count")
    require(all(type(row) is dict for row in cast(list[Any], rows)), "row_objects")
    rows = cast(list[dict[str, Any]], rows)
    stages = list(PARENTS)
    indexed = {}
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == ROW_FIELDS, "row_fields")
        stage = stages[index]
        require(
            type(row["id"]) is int and row["id"] == index and row["stage"] == stage and row["site"] == CALLERS[stage],
            "row_identity",
        )
        parent = row["parent"]
        require(parent is None if index == 0 else type(parent) is int and parent == index - 1, "parent")
        entry, exit_time = finite(row["entry_seconds"]), finite(row["exit_seconds"])
        require(0 <= entry <= exit_time, "interval")
        if index:
            previous = rows[index - 1]
            require(previous["entry_seconds"] <= entry <= exit_time <= previous["exit_seconds"], "nested_interval")
        if row["outcome"] == "return":
            require(row["error"] is None, "return_error")
            require(
                row["returned"] in {"true", "false"} if stage == "publisher_wait" else row["returned"] == "none",
                "returned",
            )
        else:
            require(row["outcome"] == "exception" and row["returned"] is None and row["error"] in ERRORS, "exception")
            require(all(parent["outcome"] == "exception" for parent in rows[:index]), "exception_propagation")
        indexed[stage] = row
    calls, outcome = value["replacement_calls"], value["replacement_outcome"]
    require(outcome in {"not_called", "return", "exception"}, "replacement_result")
    if calls == 0:
        require(
            outcome == "not_called" and not rows and value["factory_handoffs"] == 0 and accepted is None,
            "zero_activation",
        )
    else:
        require(outcome != "not_called", "replacement_incomplete")
    if outcome == "return":
        require(len(rows) == 5 and all(row["outcome"] == "return" for row in rows), "normal_roster")
        require(value["factory_handoffs"] == value["acceptance_calls"] == 1, "owner_join")
    if rows and rows[0]["outcome"] == "exception":
        require(outcome == "exception", "constructor_exception_result")
    if value["factory_handoffs"] == 1:
        require("hook_worker_constructor" in indexed, "factory_parent")
    if accepted is not None:
        require("hook_worker_constructor" in indexed, "acceptance_parent")
        relative = finite(accepted) - origin
        worker = indexed["hook_worker_constructor"]
        require(worker["entry_seconds"] <= relative <= worker["exit_seconds"], "acceptance_interval")
        if "publisher_wait" in indexed:
            require(relative <= indexed["publisher_wait"]["entry_seconds"], "acceptance_wait_order")
    if "publisher_wait" in indexed:
        require(value["factory_handoffs"] == value["acceptance_calls"] == 1, "wait_owner")
    tail = admit_tail(value["tail_rows"], indexed, cast(str, outcome))
    regions = {}
    for name, outer_name, inner_name in REGIONS:
        outer, inner = indexed.get(outer_name), indexed.get(inner_name)
        if outer is not None and inner is not None and outer["outcome"] == inner["outcome"] == "return":
            regions[name] = (outer["exit_seconds"] - inner["exit_seconds"]) * 1000
    returns_from_acceptance = {}
    if accepted is not None:
        accepted_offset = finite(accepted) - origin
        returns_from_acceptance = {
            row["stage"]: (row["exit_seconds"] - accepted_offset) * 1000 for row in rows if row["outcome"] == "return"
        }
    return {
        **tail,
        "replacement_calls": calls,
        "replacement_outcome": outcome,
        "observed_phases": len(rows),
        "all_five_returned": len(rows) == 5 and all(row["outcome"] == "return" for row in rows),
        "matched_exit_regions_ms": regions,
        "acceptance_to_successful_returns_ms": returns_from_acceptance,
        "inclusive_spans_summed": False,
        "leaf_cost_proven": False,
        "observer_overhead_included": True,
        "historical_cause_proven": False,
    }
