"""Stdlib-only, closed result reader for one finite process-turnover control."""

from __future__ import annotations

import json
import math
from typing import Any, cast

METRICS = ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
_OPERATIONS = {"create_root", "inventory_before", "inventory_after", "cpu_times", "linux_proc_cpu", *METRICS}
_ROLES = {"root", "descendant", "unknown"}
_REASONS = {
    "invalid_process_data",
    "inventory_changed",
    "process_lookup_failed",
    "permission_denied",
    "process_tree_bound",
    "protected_group_inventory_unavailable",
    "os_error",
    "platform_unsupported",
    "metric_unavailable",
    "process_history_bound",
    "invalid_cumulative_delta",
}
_KEYS = {
    "live_inventory_scope",
    "live_inventory_identity",
    "sampled_memory_scope",
    "instantaneous_peak_proven",
    "scope",
    "collector",
    "samples",
    "unavailable_samples",
    "unavailable_sample_reasons",
    "unavailable_sample_reason_scope",
    "unavailable_sample_operations",
    "unavailable_sample_operation_scope",
    "metric_samples",
    "unavailable_metrics",
    "unavailable_metric_roles",
    "unavailable_metric_role_scope",
    "metric_minimum_met",
    "sample_minimum_met",
    "elapsed_seconds",
    "baseline",
    "peak",
    "rss_growth",
    "cpu_seconds",
    "cpu_ms_per_attempt",
    "cpu_includes_reaped_descendants",
    "short_exited_descendants_cpu_complete",
    "short_exited_descendants_cpu_scope",
    "includes_load_generator",
    "fixture_control_overhead_included",
    "handles",
    *METRICS,
    *_REASONS,
    *_ROLES,
    *(operation + ":" + role for operation in _OPERATIONS for role in _ROLES),
}
_STRINGS = {
    "protected_kernel_group",
    "pid_and_creation_time_before_and_after_each_sample",
    "sum_of_live_members_during_successful_sample_windows",
    "load_generator_process_tree",
    "psutil_with_linux_proc_cpu",
    "psutil_observed_descendants",
    "last_failed_attempt_after_two_attempts",
    "last_permission_denial_per_metric_in_each_returned_sample",
    "current_tree_and_waited_children_only",
    "observed_processes_only",
}
_FACT_KEYS = {
    "planned_children",
    "planned_waves",
    "concurrency",
    "sampler_interval_seconds",
    "offered",
    "returned",
    "exit_codes",
    "waves_completed",
    "locally_reaped",
    "local_cleanup_complete",
    "only_worker_live_after",
    "sampled_resources",
    "lifetime_cpu",
    "failure_stage",
}
_STAGES = {
    None,
    "admission",
    "sampler_start",
    "owned_children",
    "final_snapshot",
    "sampler_stop",
    "sampler_report",
    "boundary_close",
}


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("turnover_duplicate_key")
        result[key] = value
    return result


def _integer(value: Any, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _samples(value: Any) -> None:
    if value is None:
        return
    if type(value) is not dict:
        raise ValueError("turnover_samples_schema")
    pending = [(value, 0)]
    total = 0
    while pending:
        node, depth = pending.pop()
        total += 1
        if total > 4096 or depth > 8:
            raise ValueError("turnover_samples_bound")
        if type(node) is dict:
            if any(type(k) is not str or k not in _KEYS for k in node):
                raise ValueError("turnover_samples_key")
            pending.extend((v, depth + 1) for v in node.values())
        elif type(node) is str:
            if node not in _STRINGS:
                raise ValueError("turnover_samples_value")
        elif node is not None and type(node) is not bool:
            if type(node) not in {int, float}:
                raise ValueError("turnover_samples_number")
            numeric = cast(int | float, cast(object, node))
            if not math.isfinite(numeric) or abs(numeric) > 2**63 - 1:
                raise ValueError("turnover_samples_number")


def admit_facts(facts: Any) -> None:
    if type(facts) is not dict or set(facts) != _FACT_KEYS:
        raise ValueError("turnover_facts_schema")
    if any(
        type(facts[k]) is not int or facts[k] != v
        for k, v in {"planned_children": 256, "planned_waves": 16, "concurrency": 16}.items()
    ):
        raise ValueError("turnover_fixed_population")
    if type(facts["sampler_interval_seconds"]) is not float or facts["sampler_interval_seconds"] != 0.1:
        raise ValueError("turnover_fixed_interval")
    if any(not _integer(facts[k], 256) for k in ("offered", "returned", "locally_reaped")) or not _integer(
        facts["waves_completed"], 16
    ):
        raise ValueError("turnover_observed_count")
    if facts["returned"] > facts["offered"] or facts["locally_reaped"] > facts["offered"]:
        raise ValueError("turnover_count_join")
    exits = facts["exit_codes"]
    if (
        type(exits) is not list
        or len(exits) != facts["returned"]
        or any(type(x) is not int or not -255 <= x <= 255 for x in exits)
    ):
        raise ValueError("turnover_exits")
    if (
        any(type(facts[k]) is not bool for k in ("local_cleanup_complete", "only_worker_live_after"))
        or facts["failure_stage"] not in _STAGES
    ):
        raise ValueError("turnover_flags")
    cpu = facts["lifetime_cpu"]
    if cpu is not None and (
        type(cpu) is not dict
        or set(cpu) != {"usage_seconds", "user_seconds", "system_seconds"}
        or any(type(x) not in {int, float} or not math.isfinite(x) or x < 0 for x in cpu.values())
    ):
        raise ValueError("turnover_cpu")
    _samples(facts["sampled_resources"])


def measurement_complete(facts: dict[str, Any]) -> bool:
    admit_facts(facts)
    sampled = facts["sampled_resources"]
    cpu = facts["lifetime_cpu"]
    if (
        facts["offered"] != 256
        or facts["returned"] != 256
        or facts["locally_reaped"] != 256
        or facts["waves_completed"] != 16
    ):
        return False
    if (
        any(facts["exit_codes"])
        or facts["failure_stage"] is not None
        or not facts["local_cleanup_complete"]
        or not facts["only_worker_live_after"]
    ):
        return False
    if sampled is None or cpu is None or cpu["usage_seconds"] <= 0:
        return False
    baseline, peak = sampled.get("baseline"), sampled.get("peak")
    if type(baseline) is not dict or type(peak) is not dict:
        return False
    for metric in METRICS:
        first, maximum = baseline.get(metric), peak.get(metric)
        if type(first) not in {int, float} or type(maximum) not in {int, float}:
            return False
        first_number = cast(int | float, cast(object, first))
        maximum_number = cast(int | float, cast(object, maximum))
        if (
            not math.isfinite(first_number)
            or not math.isfinite(maximum_number)
            or not 0 <= first_number <= maximum_number <= 2**63 - 1
        ):
            return False
    return (
        sampled.get("live_inventory_scope") == "protected_kernel_group"
        and sampled.get("live_inventory_identity") == "pid_and_creation_time_before_and_after_each_sample"
        and sampled.get("instantaneous_peak_proven") is False
        and _integer(sampled.get("samples"))
        and sampled["samples"] >= 30
        and type(sampled.get("unavailable_samples")) is int
        and sampled["unavailable_samples"] == 0
        and all(
            _integer(sampled.get("metric_samples", {}).get(k))
            and 30 <= sampled["metric_samples"][k] <= sampled["samples"]
            for k in METRICS
        )
        and all(sampled.get("metric_minimum_met", {}).get(k) is True for k in METRICS)
        and not set(sampled.get("unavailable_metrics", {})).intersection(METRICS)
    )


def read_worker_report(body: bytes) -> dict[str, Any]:
    if len(body) > 128 * 1024:
        raise ValueError("turnover_report_bound")
    value = json.loads(body, object_pairs_hook=_pairs)
    if type(value) is not dict or set(value) != {
        "schema",
        "admitted",
        "admission_refusal",
        "passed",
        "original_workload_executed",
        "facts",
    }:
        raise ValueError("turnover_report_schema")
    if (
        value["schema"] != "hol-guard.finite-turnover-resource-control.v1"
        or value["original_workload_executed"] is not False
        or any(type(value[k]) is not bool for k in ("admitted", "passed"))
    ):
        raise ValueError("turnover_report_identity")
    admit_facts(value["facts"])
    if value["admitted"]:
        if value["admission_refusal"] is not None:
            raise ValueError("turnover_admission_join")
    elif value["admission_refusal"] != "admission_unavailable" or value["facts"]["offered"] != 0:
        raise ValueError("turnover_admission_refusal")
    if value["passed"] != (value["admitted"] and measurement_complete(value["facts"])):
        raise ValueError("turnover_result_join")
    return value
