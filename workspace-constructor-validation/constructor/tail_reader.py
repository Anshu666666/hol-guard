"""Admit only the three source-bound sequential tail calls, without leaf attribution."""

from __future__ import annotations

from typing import Any, cast

from .capture import TAIL_ARGUMENTS, TAIL_STAGES, finite
from .tail_hooks import TAIL_SITES

TAIL_FIELDS = {
    "id",
    "stage",
    "site",
    "parent",
    "entry_seconds",
    "exit_seconds",
    "outcome",
    "returned",
    "error",
    "workers",
    "queue_limit",
}
ERRORS = {"interrupt", "exit", "timeout", "os_error", "value_error", "runtime_error", "exception", "base_exception"}


def require(value: Any, reason: str) -> None:
    if value is not True:
        raise ValueError("constructor_tail_" + reason)


def admit_tail(value: Any, indexed: dict[str, Any], outcome: str) -> dict[str, Any]:
    require(type(value) is list and len(value) <= 3, "rows")
    require(all(type(row) is dict for row in value), "row_objects")
    value = cast(list[dict[str, Any]], value)
    worker, services = indexed.get("hook_worker_constructor", {}), indexed.get("request_services", {})
    if value:
        require(bool(worker) and bool(services) and worker["outcome"] == "return", "worker_parent")
    previous_exit = worker["exit_seconds"] if worker else 0.0
    previous_outcome = "return"
    for index, row in enumerate(value):
        require(type(row) is dict and set(row) == TAIL_FIELDS, "fields")
        stage = TAIL_STAGES[index]
        require(
            type(row["id"]) is int
            and row["id"] == index
            and row["stage"] == stage
            and row["site"] == TAIL_SITES[stage],
            "identity",
        )
        require(type(row["parent"]) is int and row["parent"] == 2 and services["id"] == 2, "parent")
        workers, queue_limit = row["workers"], row["queue_limit"]
        require(
            all(type(item) is int for item in (workers, queue_limit) if item is not None)
            and (workers, queue_limit) == TAIL_ARGUMENTS[index],
            "arguments",
        )
        entry, exit_time = finite(row["entry_seconds"]), finite(row["exit_seconds"])
        require(
            services["entry_seconds"] <= previous_exit <= entry <= exit_time <= services["exit_seconds"], "interval"
        )
        require(previous_outcome == "return", "after_exception")
        if row["outcome"] == "return":
            require(row["error"] is None and row["returned"] == ("opaque" if index == 0 else "none"), "returned")
        else:
            require(row["outcome"] == "exception" and row["returned"] is None and row["error"] in ERRORS, "exception")
            require(services["outcome"] == "exception" and outcome == "exception", "exception_propagation")
        previous_exit, previous_outcome = exit_time, row["outcome"]
    complete = len(value) == 3 and all(row["outcome"] == "return" for row in value)
    if services and services["outcome"] == "return":
        require(complete, "normal_roster")
    if outcome == "return":
        require(complete, "normal_replacement")
    if outcome == "not_called":
        require(not value, "zero_activation")
    spans = {
        row["stage"]: (row["exit_seconds"] - row["entry_seconds"]) * 1000 for row in value if row["outcome"] == "return"
    }
    gaps = {}
    if value and value[0]["outcome"] == "return":
        gaps["worker_return_to_authority_entry"] = (value[0]["entry_seconds"] - worker["exit_seconds"]) * 1000
    for index, name in ((1, "authority_return_to_general_entry"), (2, "general_return_to_control_entry")):
        if len(value) > index and value[index - 1]["outcome"] == value[index]["outcome"] == "return":
            gaps[name] = (value[index]["entry_seconds"] - value[index - 1]["exit_seconds"]) * 1000
    if complete and services["outcome"] == "return":
        gaps["control_return_to_services_return"] = (services["exit_seconds"] - value[2]["exit_seconds"]) * 1000
    return {
        "observed_tail_phases": len(value),
        "all_three_tail_returned": complete,
        "tail_inclusive_spans_ms": spans,
        "matched_tail_gaps_ms": gaps,
    }
