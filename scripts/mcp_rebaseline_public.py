"""Reconstruct public evidence from bounded typed metrics and exact identities."""

from __future__ import annotations

from typing import Any

from scripts.mcp_rebaseline_public_records import COMPARISONS, PHASES, RUNS
from scripts.mcp_rebaseline_public_types import SHA1, SHA256, array, choice, fields, integer, pattern, require
from scripts.mcp_rebaseline_trace import TRACES, digest, trace_identity

BASELINE = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
RUN_COUNT = 5
CALLS = 13
EXPECTED_ORDER = [
    {"block": block, "role": role, "mode": mode}
    for block in range(RUN_COUNT)
    for role in (("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"))
    for mode in ("plain", "resources", "diagnostic")
]
WORKERS = len(EXPECTED_ORDER)
TOOL_CALLS = WORKERS * len(TRACES) * CALLS
INTERPRETATION = {
    "phase_rows": "nested wall/thread CPU; inclusive phases overlap and must not be summed",
    "exclusive": "subtracts instrumented same-thread children; residual work is not an isolated phase",
    "memory": "worker/child process tree sampled at 10ms; peaks are lower bounds; RSS includes shared pages",
    "network": "not exercised",
    "human": "synthetic inline callback delay; no actual human latency",
    "boundary": "production run_session plus real child stdio; excludes outer installed CLI ingress/bootstrap",
}
FIELDS = {
    "schema",
    "status",
    "qualification",
    "native_selection",
    "failures",
    "independent_runs_per_revision_and_mode",
    "calls_per_trace",
    "percentile_estimator",
    "comparisons",
    "diagnostic_phases",
    "interpretation",
    "source_and_environment",
    "expected_worker_attempts",
    "observed_worker_attempts",
    "expected_tool_call_attempts",
    "observed_tool_call_outcomes",
    "run_observations",
    "raw_evidence",
}
FAILURES = (
    {
        "paired_run_completeness",
        "alternating_run_order",
        "trace_inventory",
        "quiet_barrier_or_phase_completeness",
        "phase_row_accounting",
        "full_process_memory_unobserved",
    }
    | {
        f"{prefix}:{trace.name}"
        for prefix in (
            "trace_oracle",
            "request_count",
            "request_order",
            "delivered_oracle",
            "catalog_oracle",
            "approval_count",
        )
        for trace in TRACES
    }
    | {f"worker_failure:{row['block']}:{row['role']}:{row['mode']}" for row in EXPECTED_ORDER}
)


def manifest(value: Any, candidate: str) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "created_at_utc",
            "sources",
            "platform",
            "python",
            "executable_sha256",
            "dependencies",
            "harness",
            "child_sha256",
            "traces",
            "order",
            "note",
        }
    )
    source = fields({"commit": SHA1, "production_tree": SHA1, "uv_lock_sha256": SHA256})
    sources = fields({"baseline": source, "candidate": source})(value["sources"])
    require(sources["baseline"]["commit"] == BASELINE and sources["candidate"]["commit"] == candidate)
    require(value["traces"] == [trace_identity(trace, CALLS) for trace in TRACES])
    require(value["order"] == EXPECTED_ORDER)
    require(isinstance(value["harness"], dict) and 1 <= len(value["harness"]) <= 32)
    name = pattern(r"(?:bench_mcp_rebaseline|mcp_rebaseline(?:_[a-z]+)*|native_slo_resources)\.py")
    harness = {name(key): SHA256(item) for key, item in value["harness"].items()}
    # Free-form platform/interpreter/dependency strings remain in the encrypted
    # manifest. Its digest binds their exact content without publishing text.
    return {
        "sources": sources,
        "executable_sha256": SHA256(value["executable_sha256"]),
        "harness": harness,
        "child_sha256": SHA256(value["child_sha256"]),
        "traces": [trace_identity(trace, CALLS) for trace in TRACES],
        "order": [dict(row) for row in EXPECTED_ORDER],
        "private_manifest_sha256": digest(value),
    }


def _counts(report: dict[str, Any]) -> None:
    passed = report["status"] == "passed"
    require(passed == (not report["failures"]))
    evidence = report["raw_evidence"]
    names = {row["file"] for row in evidence}
    require(len(names) == len(evidence) and all(row["bytes"] <= 32 * 1024 * 1024 for row in evidence))
    if passed:
        required_names = {"manifest.json"} | {
            f"{row['block']}-{row['role']}-{row['mode']}.{suffix}"
            for row in EXPECTED_ORDER
            for suffix in (
                "begin.json",
                "observation.json",
                "raw.json",
                "raw.stdout.json",
                "raw.stderr.json",
                "raw.journal.jsonl",
            )
        }
        require(names == required_names)
    runs = report["run_observations"]
    keys = [(row["block"], row["role"], row["mode"]) for row in runs]
    expected = [(row["block"], row["role"], row["mode"]) for row in EXPECTED_ORDER]
    require(len(set(keys)) == len(keys) and all(key in expected for key in keys))
    require(report["observed_worker_attempts"] == len(runs))
    if passed:
        require(keys == expected and report["observed_tool_call_outcomes"] == TOOL_CALLS)
        for row in runs:
            require(row["returncode"] == 0 and row["capture_failure"] is None and row["import"] is not None)
            require("worker_lifecycle_wall_ns" in row)
            if row["mode"] == "resources":
                resource = row.get("resources")
                require(isinstance(resource, dict))
                require(resource["peak"]["processes"] is not None and resource["peak"]["processes"] >= 2)
                require(resource["peak"]["rss_bytes"] is not None and resource["peak"]["rss_bytes"] > 0)
            else:
                require("resources" not in row)
            if row["mode"] == "diagnostic":
                require(
                    row["phase_counts"] is not None
                    and row["phase_counts"].get("quiet_frame_wait") == CALLS * len(TRACES)
                )
            else:
                require(row["phase_counts"] == {})
    groups = report["comparisons"]
    group_keys = [(row["role"], row["mode"], row["trace"]) for row in groups]
    require(len(set(group_keys)) == len(groups))
    if passed:
        require(len(groups) == 2 * 3 * len(TRACES))
    require(sum(row["cold_attempts"] + row["warm_attempts"] for row in groups) == report["observed_tool_call_outcomes"])
    require(report["observed_tool_call_outcomes"] <= TOOL_CALLS)
    for row in groups:
        require(0 < row["independent_runs"] <= RUN_COUNT)
        require(row["cold_attempts"] <= row["independent_runs"])
        require(row["warm_attempts"] <= row["independent_runs"] * (CALLS - 1))
        require(row["headline_eligible"] is (passed and row["mode"] == "plain"))
        if passed:
            require(row["independent_runs"] == RUN_COUNT and row["cold_attempts"] == RUN_COUNT)
            require(row["warm_attempts"] == RUN_COUNT * (CALLS - 1))
        counts = {
            "warm_wall_ns": row["warm_attempts"],
            "warm_process_cpu_ns": row["warm_attempts"],
            "child_service_wall_ns": row["warm_attempts"],
            "child_observed_wire_bytes": row["warm_attempts"],
            "first_call_wall_ns": row["cold_attempts"],
            "session_wall_ns": row["independent_runs"],
            "construction_wall_ns": row["independent_runs"],
            "synthetic_approval_wall_ns": row["independent_runs"] * CALLS
            if row["trace"] == "inline_approval10ms"
            else 0,
        }
        for key, maximum in counts.items():
            metric_count = 0 if row[key] is None else row[key]["count"]
            require(metric_count <= maximum and (not passed or metric_count == maximum))
    phases = report["diagnostic_phases"]
    require(len({(row["role"], row["trace"], row["phase"]) for row in phases}) == len(phases))
    for row in phases:
        require(row["count"] > 0 and row["failures"] <= row["count"])
        for key in ("inclusive_wall_ns", "exclusive_wall_ns", "exclusive_thread_cpu_ns"):
            require(row[key] is not None and row[key]["count"] == row["count"])
    for role in ("baseline", "candidate"):
        counts: dict[str, int] = {}
        for row in runs:
            if row["role"] == role and row["mode"] == "diagnostic":
                for key, value in (row["phase_counts"] or {}).items():
                    if not key.endswith("_bytes"):
                        counts[key] = counts.get(key, 0) + value
        actual: dict[str, int] = {}
        for row in phases:
            if row["role"] == role:
                actual[row["phase"]] = actual.get(row["phase"], 0) + row["count"]
        if counts != actual:
            require(
                not passed
                and bool(
                    {
                        "phase_row_accounting",
                        "quiet_barrier_or_phase_completeness",
                    }
                    & set(report["failures"])
                )
            )


def project(value: Any, *, candidate: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == FIELDS)
    raw_name = pattern(
        r"(?:manifest\.json|[0-4]-(?:baseline|candidate)-(?:plain|resources|diagnostic)\."
        r"(?:begin\.json|observation\.json|raw\.json|raw\.(?:stdout|stderr)\.json|raw\.journal\.jsonl))"
    )
    report = fields(
        {
            "schema": choice("hol-guard.mcp-rebaseline.v1"),
            "status": choice("passed", "failed"),
            "qualification": choice(False),
            "native_selection": choice("not_selected_by_this_component_report"),
            "failures": array(choice(*sorted(FAILURES)), 10000),
            "independent_runs_per_revision_and_mode": choice(RUN_COUNT),
            "calls_per_trace": choice(CALLS),
            "percentile_estimator": choice("nearest-rank"),
            "comparisons": COMPARISONS,
            "diagnostic_phases": PHASES,
            "interpretation": lambda item: fields({key: choice(text) for key, text in INTERPRETATION.items()})(item),
            "source_and_environment": lambda item: manifest(item, candidate),
            "expected_worker_attempts": choice(WORKERS),
            "observed_worker_attempts": integer,
            "expected_tool_call_attempts": choice(TOOL_CALLS),
            "observed_tool_call_outcomes": integer,
            "run_observations": RUNS,
            "raw_evidence": array(fields({"file": raw_name, "bytes": integer, "sha256": SHA256}), 256),
        }
    )(value)
    _counts(report)
    return report
