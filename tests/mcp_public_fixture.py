"""Synthetic complete controller records for publication contract tests only."""

from scripts.mcp_rebaseline_network import NETWORK_TRACE
from scripts.mcp_rebaseline_public import BASELINE, CALLS, EXPECTED_ORDER
from scripts.mcp_rebaseline_report import aggregate
from scripts.mcp_rebaseline_trace import (
    RESOURCE_CALLS,
    TRACES,
    calls_for_mode,
    catalog_result,
    digest,
    messages,
    trace_identity,
)

CANDIDATE = "a" * 40


def resource_fixture():
    metrics = {"rss_bytes", "private_bytes", "cpu_seconds", "processes", "threads", "descriptors", "handles"}
    memory = {key: None if key == "handles" else 2 for key in metrics - {"cpu_seconds"}}
    return {
        "scope": "mcp_proxy_worker_and_descendants",
        "collector": "psutil_with_linux_proc_cpu",
        "samples": 30,
        "unavailable_samples": 0,
        "metric_samples": {key: 30 for key in metrics},
        "unavailable_metrics": {"handles": {"platform_unsupported": 30}},
        "metric_minimum_met": {key: True for key in metrics - {"handles"}},
        "sample_minimum_met": True,
        "elapsed_seconds": 1,
        "baseline": dict(memory),
        "peak": dict(memory),
        "rss_growth": 0,
        "cpu_seconds": 1,
        "cpu_ms_per_attempt": 1,
        "cpu_includes_reaped_descendants": True,
        "short_exited_descendants_cpu_complete": True,
        "cpu_accounting_scope": "observed_process_tree",
        "cpu_unavailable_samples": 0,
        "includes_load_generator": False,
        "fixture_control_overhead_included": True,
    }


def complete_report():
    records = []
    for identity in EXPECTED_ORDER:
        calls = calls_for_mode(identity["mode"], CALLS)
        traces = []
        for trace in TRACES:
            rows = []
            generation = 0
            for message in messages(trace, calls):
                row = {
                    "request_id": message["id"],
                    "method": message["method"],
                    "request_sha256": digest(message),
                    "wall_ns": 12,
                    "process_cpu_ns": 4,
                    "child_wall_ns": 3,
                    "child_cpu_ns": 2,
                    "wire_bytes": 100,
                    "decision": "inline-approved" if trace.approval_delay_ms else "policy-warn",
                    "policy_action": "allow" if trace.approval_delay_ms else "warn",
                }
                if trace.name == NETWORK_TRACE:
                    row.update(
                        network_roundtrip_wall_ns=20_000_000,
                        network_client_thread_cpu_ns=20,
                        network_service_wall_ns=10_000_000,
                        network_service_thread_cpu_ns=10,
                        network_request_bytes=65,
                        network_response_bytes=180,
                        child_wall_ns=30_000_000,
                    )
                if message["method"] == "tools/list":
                    generation += 1
                    row["catalog_result_sha256"] = digest(catalog_result(trace, generation))
                rows.append(row)
            traces.append(
                {
                    **trace_identity(trace, calls),
                    "status": "passed",
                    "observations": rows,
                    "session": {"wall_ns": 100},
                    "construction": {"wall_ns": 10},
                    "approvals": [{"wall_ns": 10}] * (calls if trace.approval_delay_ms else 0),
                }
            )
        phases = []
        if identity["mode"] == "diagnostic":
            for trace in TRACES:
                for name in (
                    "catalog_fingerprint",
                    "classification_categories",
                    "policy_evaluation_composite",
                    "policy_store_lookup",
                    "final_quiet_barrier",
                    "child_response_wait",
                    "receipt_and_inventory_composite",
                    *("quiet_frame_wait",) * CALLS,
                ):
                    phases.append(
                        {
                            "scope": f"{trace.name}/3",
                            "phase": name,
                            "wall_ns": 1,
                            "thread_cpu_ns": 1,
                            "exclusive_wall_ns": 1,
                            "exclusive_thread_cpu_ns": 1,
                            "failed": False,
                        }
                    )
        counts = {name: sum(row["phase"] == name for row in phases) for name in {row["phase"] for row in phases}}
        record = {
            **identity,
            "returncode": 0,
            "capture_failure": None,
            "worker_lifecycle_wall_ns": 1000,
            "result": {
                "status": "passed",
                "traces": traces,
                "phases": phases,
                "phase_counts": counts,
                "phase_rows_dropped": 0,
                "import": {"wall_ns": 10, "process_cpu_ns": 10},
                "self_cpu_seconds": 1,
                "waited_child_cpu_seconds": 1,
                "self_peak_rss_bytes": 100,
                "largest_waited_child_peak_rss_bytes": 10,
            },
        }
        if identity["mode"] == "resources":
            record["resources"] = resource_fixture()
            record["warm_resource_failure"] = None
            record["warm_resources"] = [
                {
                    "trace_index": index,
                    "status": "complete",
                    "failure": None,
                    "identity_verified": True,
                    "expected_warm_attempts": calls - 1,
                    "warm_attempts": calls - 1,
                    "resources": resource_fixture(),
                }
                for index in range(len(TRACES))
            ]
        records.append(record)
    report = aggregate(records, runs=5, calls=CALLS)
    assert report["status"] == "passed"
    report["source_and_environment"] = {
        "created_at_utc": "2026-09-17T00:00:00+00:00",
        "platform": "fixture",
        "python": "fixture",
        "dependencies": ["fixture==1"],
        "note": "fixture",
        "sources": {
            role: {"commit": commit, "production_tree": "b" * 40, "uv_lock_sha256": "c" * 64}
            for role, commit in (("baseline", BASELINE), ("candidate", CANDIDATE))
        },
        "executable_sha256": "d" * 64,
        "child_sha256": "e" * 64,
        "harness": {"bench_mcp_rebaseline.py": "f" * 64},
        "traces": [trace_identity(trace, CALLS) for trace in TRACES],
        "resource_traces": [trace_identity(trace, RESOURCE_CALLS) for trace in TRACES],
        "order": EXPECTED_ORDER,
    }
    report["run_observations"] = [
        {key: value for key, value in record.items() if key != "result"}
        | {
            key: record["result"][key]
            for key in (
                "import",
                "phase_counts",
                "self_cpu_seconds",
                "waited_child_cpu_seconds",
                "self_peak_rss_bytes",
                "largest_waited_child_peak_rss_bytes",
            )
        }
        for record in records
    ]
    names = ["manifest.json"] + [
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
    ]
    report["raw_evidence"] = [{"file": name, "bytes": 10, "sha256": "1" * 64} for name in names]
    return report
