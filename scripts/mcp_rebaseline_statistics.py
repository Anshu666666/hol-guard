"""Run-level MCP estimates; resample paired independent runs, never requests."""

from __future__ import annotations

import math
import statistics
from typing import Any

from scripts.mcp_rebaseline_network import NETWORK_METRICS
from scripts.mcp_rebaseline_trace import TRACES
from scripts.native_slo_qualification import paired_ratio_interval

PAIRED_METRICS = {
    "warm_wall_p50": ("warm_wall_ns", "p50"),
    "warm_wall_p95": ("warm_wall_ns", "p95"),
    "warm_process_cpu_mean": ("warm_process_cpu_ns", "mean"),
    "first_call_wall": ("first_call_wall_ns", "mean"),
    "construction_wall": ("construction_wall_ns", "mean"),
    "session_wall": ("session_wall_ns", "mean"),
}


def summary(values: list[int | float]) -> dict[str, float | int] | None:
    if not values:
        return None
    values = sorted(values)
    return {
        "count": len(values),
        "p50": statistics.median(values),
        "p95": values[math.ceil(len(values) * 0.95) - 1],
        "max": values[-1],
        "sum": sum(values),
    }


def observed_metric(rows: list[dict[str, Any]], key: str) -> dict[str, float | int] | None:
    return summary([row[key] for row in rows if type(row.get(key)) in (int, float)])


def trace_summary(role: str, mode: str, name: str, traces: list[dict[str, Any]], *, eligible: bool) -> dict[str, Any]:
    warm = [r for t in traces for r in t["observations"] if r["method"] == "tools/call" and r["request_id"] != 3]
    cold = [r for t in traces for r in t["observations"] if r["method"] == "tools/call" and r["request_id"] == 3]
    return {
        "role": role,
        "mode": mode,
        "trace": name,
        "independent_runs": len(traces),
        "warm_attempts": len(warm),
        "cold_attempts": len(cold),
        "headline_eligible": eligible and mode == "plain",
        "warm_wall_ns": observed_metric(warm, "wall_ns"),
        "warm_process_cpu_ns": observed_metric(warm, "process_cpu_ns"),
        "first_call_wall_ns": observed_metric(cold, "wall_ns"),
        "session_wall_ns": summary([t["session"]["wall_ns"] for t in traces]),
        "construction_wall_ns": summary([t["construction"]["wall_ns"] for t in traces]),
        "child_service_wall_ns": observed_metric(warm, "child_wall_ns"),
        "child_observed_wire_bytes": observed_metric(warm, "wire_bytes"),
        "synthetic_approval_wall_ns": summary([a["wall_ns"] for t in traces for a in t["approvals"]]),
        **{key: observed_metric(warm, key) for key in NETWORK_METRICS},
    }


def independent_summaries(records: list[dict[str, Any]], *, eligible: bool) -> list[dict[str, Any]]:
    return [
        {
            "block": record["block"],
            **trace_summary(record["role"], record["mode"], t["trace"]["name"], [t], eligible=eligible),
        }
        for record in records
        for t in record.get("result", {}).get("traces", [])
    ]


def paired_comparisons(rows: list[dict[str, Any]], *, runs: int, eligible: bool) -> list[dict[str, Any]]:
    """Compare the same trace in each plain-mode environmental block.

    Missing/duplicate blocks or metrics are retained as incomplete comparisons.
    A globally failed experiment emits no confidence interval, even if some
    pairs happened to complete. Five runs do not qualify the 12-request tails.
    """
    result = []
    for trace in TRACES:
        selected = [r for r in rows if r["mode"] == "plain" and r["trace"] == trace.name]
        keyed = {(r["block"], r["role"]): r for r in selected}
        blocks = [b for b in range(runs) if (b, "baseline") in keyed and (b, "candidate") in keyed]
        valid = eligible and len(keyed) == len(selected) == 2 * runs and blocks == list(range(runs))
        intervals: dict[str, Any] = {}
        for label, (metric, statistic) in PAIRED_METRICS.items():
            arms: dict[str, list[float]] = {"baseline": [], "candidate": []}
            for block in blocks:
                for role, values in arms.items():
                    measured = keyed[block, role].get(metric)
                    if not measured or measured["count"] <= 0:
                        valid = False
                        continue
                    value = measured["sum"] / measured["count"] if statistic == "mean" else measured[statistic]
                    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                        valid = False
                        continue
                    values.append(float(value))
            if valid:
                intervals[label] = paired_ratio_interval(arms["baseline"], arms["candidate"])
        result.append(
            {
                "trace": trace.name,
                "status": "complete" if valid else "incomplete",
                "offered_runs": runs,
                "matched_blocks": blocks,
                "resampling_unit": "independent_run_pair",
                "ratio_direction": "candidate_over_baseline",
                "tail_qualified": False,
                "intervals": intervals if valid else None,
            }
        )
    return result
