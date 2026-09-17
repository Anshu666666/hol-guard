"""Strict aggregation of paired source-proxy observations, never an SLO gate."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scripts.mcp_rebaseline_network import NETWORK_METRICS, NETWORK_TRACE, validate_network
from scripts.mcp_rebaseline_resources import _complete as warm_resource_complete
from scripts.mcp_rebaseline_statistics import independent_summaries, paired_comparisons, summary, trace_summary
from scripts.mcp_rebaseline_trace import TRACES, calls_for_mode, catalog_result, digest, messages, trace_identity


def aggregate(records: list[dict[str, Any]], *, runs: int, calls: int) -> dict[str, Any]:
    expected = {
        (block, role, mode)
        for block in range(runs)
        for role in ("baseline", "candidate")
        for mode in ("plain", "resources", "diagnostic")
    }
    actual = {(r["block"], r["role"], r["mode"]) for r in records}
    failures: list[str] = []
    if actual != expected or len(records) != len(expected):
        failures.append("paired_run_completeness")
    expected_order = [
        (block, role, mode)
        for block in range(runs)
        for role in (("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"))
        for mode in ("plain", "resources", "diagnostic")
    ]
    if [(r["block"], r["role"], r["mode"]) for r in records] != expected_order:
        failures.append("alternating_run_order")
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        mode_calls = calls_for_mode(record["mode"], calls)
        payload = record.get("result", {})
        if record.get("returncode") != 0 or payload.get("status") != "passed" or record.get("capture_failure"):
            failures.append(f"worker_failure:{record['block']}:{record['role']}:{record['mode']}")
        traces = payload.get("traces", [])
        if [t.get("trace", {}).get("name") for t in traces] != [trace.name for trace in TRACES]:
            failures.append("trace_inventory")
        for trace, data in zip(TRACES, traces, strict=False):
            identity = trace_identity(trace, mode_calls)
            if data.get("sha256") != identity["sha256"] or data.get("status") != "passed":
                failures.append(f"trace_oracle:{trace.name}")
            observed = data.get("observations", [])
            expected_messages = messages(trace, mode_calls)
            if len(observed) != len(expected_messages):
                failures.append(f"request_count:{trace.name}")
            generation = 0
            for message, row in zip(expected_messages, observed, strict=False):
                if row.get("request_id") != message["id"] or row.get("method") != message["method"]:
                    failures.append(f"request_order:{trace.name}")
                if message["method"] == "tools/call":
                    expected_action = "allow" if trace.approval_delay_ms else "warn"
                    expected_decision = "inline-approved" if trace.approval_delay_ms else "policy-warn"
                    if (
                        row.get("request_sha256") != digest(message)
                        or row.get("policy_action") != expected_action
                        or row.get("decision") != expected_decision
                    ):
                        failures.append(f"delivered_oracle:{trace.name}")
                    try:
                        network = {key: row[key] for key in NETWORK_METRICS if key in row}
                        validate_network(
                            {
                                "child_wall_ns": row.get("child_wall_ns"),
                                "network": {**network, "requests": 1, "loopback": True} if network else None,
                            },
                            expected=trace.name == NETWORK_TRACE,
                        )
                    except (TypeError, ValueError):
                        failures.append(f"network_oracle:{trace.name}")
                elif message["method"] == "tools/list":
                    generation += 1
                    if row.get("catalog_result_sha256") != digest(catalog_result(trace, generation)):
                        failures.append(f"catalog_oracle:{trace.name}")
            if len(data.get("approvals", [])) != (mode_calls if trace.approval_delay_ms else 0):
                failures.append(f"approval_count:{trace.name}")
            grouped[record["role"], record["mode"], trace.name].append(data)
        if record["mode"] == "diagnostic":
            counts = payload.get("phase_counts", {})
            if payload.get("phase_rows_dropped") or counts.get("quiet_frame_wait", 0) != calls * len(TRACES):
                failures.append("quiet_barrier_or_phase_completeness")
            observed_counts = Counter(row.get("phase") for row in payload.get("phases", []))
            required = {
                "catalog_fingerprint",
                "classification_categories",
                "policy_evaluation_composite",
                "policy_store_lookup",
                "final_quiet_barrier",
                "quiet_frame_wait",
                "child_response_wait",
                "receipt_and_inventory_composite",
            }
            if any(not observed_counts[name] for name in required) or any(
                observed_counts[name] != count for name, count in counts.items() if not name.endswith("_bytes")
            ):
                failures.append("phase_row_accounting")
        if record["mode"] == "resources":
            resource = record.get("resources", {})
            if resource.get("peak", {}).get("processes", 0) < 2 or not resource.get("peak", {}).get("rss_bytes"):
                failures.append("full_process_memory_unobserved")
            warm = record.get("warm_resources", [])
            if (
                record.get("warm_resource_failure") is not None
                or len(warm) != len(TRACES)
                or any(
                    row.get("trace_index") != index
                    or row.get("status") != "complete"
                    or row.get("identity_verified") is not True
                    or row.get("warm_attempts") != mode_calls - 1
                    or row.get("expected_warm_attempts") != mode_calls - 1
                    or row.get("failure") is not None
                    or not isinstance(row.get("resources"), dict)
                    or not warm_resource_complete(row["resources"])
                    for index, row in enumerate(warm)
                )
            ):
                failures.append("warm_resources_incomplete")
    comparisons = [
        trace_summary(role, mode, name, traces, eligible=not failures)
        for (role, mode, name), traces in sorted(grouped.items())
    ]
    run_traces = independent_summaries(records, eligible=not failures)
    phases = []
    for role in ("baseline", "candidate"):
        rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            if record["role"] == role and record["mode"] == "diagnostic":
                for row in record["result"].get("phases", []):
                    rows[row["scope"].split("/", 1)[0], row["phase"]].append(row)
        for (trace, phase), values in sorted(rows.items()):
            phases.append(
                {
                    "role": role,
                    "trace": trace,
                    "phase": phase,
                    "count": len(values),
                    "inclusive_wall_ns": summary([r["wall_ns"] for r in values]),
                    "exclusive_wall_ns": summary([r["exclusive_wall_ns"] for r in values]),
                    "exclusive_thread_cpu_ns": summary([r["exclusive_thread_cpu_ns"] for r in values]),
                    "failures": sum(r["failed"] for r in values),
                }
            )
    return {
        "schema": "hol-guard.mcp-rebaseline.v2",
        "status": "passed" if not failures else "failed",
        "qualification": False,
        "native_selection": "not_selected_by_this_component_report",
        "failures": failures,
        "independent_runs_per_revision_and_mode": runs,
        "calls_per_trace": calls,
        "calls_per_trace_by_mode": {mode: calls_for_mode(mode, calls) for mode in ("plain", "resources", "diagnostic")},
        "expected_worker_attempts": len(expected),
        "observed_worker_attempts": len(records),
        "expected_tool_call_attempts": sum(calls_for_mode(mode, calls) * len(TRACES) for _, _, mode in expected),
        "observed_tool_call_outcomes": sum(
            len([r for r in t.get("observations", []) if r.get("method") == "tools/call"])
            for record in records
            for t in record.get("result", {}).get("traces", [])
        ),
        "percentile_estimator": "nearest-rank",
        "comparisons": comparisons,
        "run_trace_summaries": run_traces,
        "paired_comparisons": paired_comparisons(run_traces, runs=runs, eligible=not failures),
        "diagnostic_phases": phases,
        "interpretation": {
            "phase_rows": "nested wall/thread CPU; inclusive phases overlap and must not be summed",
            "exclusive": "subtracts instrumented same-thread children; residual work is not an isolated phase",
            "memory": (
                "separate startup-inclusive lifecycle and fixed warm worker/child windows sampled at 10ms; "
                "incomplete reads retained; peaks lower bounds and RSS includes shared pages"
            ),
            "network": (
                "actual child-owned loopback TCP round trip; separately observed synthetic 10ms service; "
                "no external remote transport"
            ),
            "human": "synthetic inline callback delay; no actual human latency",
            "boundary": "production run_session plus real child stdio; excludes outer installed CLI ingress/bootstrap",
        },
    }


def raw_reference(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_private(path: Path, value: object, *, limit: int = 16 * 1024 * 1024) -> None:
    import os

    data = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    if len(data) > limit:
        raise ValueError("evidence exceeds byte bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
