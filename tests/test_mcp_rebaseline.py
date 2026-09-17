from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS.parent))
trace_module = importlib.import_module("scripts.mcp_rebaseline_trace")
report_module = importlib.import_module("scripts.mcp_rebaseline_report")
phase_module = importlib.import_module("scripts.mcp_rebaseline_phases")
driver_module = importlib.import_module("scripts.bench_mcp_rebaseline")


def _row(message, trace):
    return {
        "request_id": message["id"],
        "method": message["method"],
        "request_sha256": trace_module.digest(message),
        "wall_ns": 12,
        "process_cpu_ns": 4,
        "child_wall_ns": 3,
        "child_cpu_ns": 2,
        "wire_bytes": 100,
        "decision": "inline-approved" if trace.approval_delay_ms else "policy-warn",
        "policy_action": "allow" if trace.approval_delay_ms else "warn",
    }


def _records():
    records = []
    for role in ("baseline", "candidate"):
        for mode in ("plain", "resources", "diagnostic"):
            traces = []
            for trace in trace_module.TRACES:
                rows = []
                generation = 0
                for message in trace_module.messages(trace, 2):
                    row = _row(message, trace)
                    if message["method"] == "tools/list":
                        generation += 1
                        row["catalog_result_sha256"] = trace_module.digest(
                            trace_module.catalog_result(trace, generation)
                        )
                    rows.append(row)
                traces.append(
                    {
                        **trace_module.trace_identity(trace, 2),
                        "status": "passed",
                        "observations": rows,
                        "session": {"wall_ns": 100},
                        "construction": {"wall_ns": 10},
                        "approvals": [{"wall_ns": 10}] * (2 if trace.approval_delay_ms else 0),
                    }
                )
            phases = [
                {
                    "scope": "catalog10/3",
                    "phase": name,
                    "wall_ns": 1,
                    "thread_cpu_ns": 1,
                    "exclusive_wall_ns": 1,
                    "exclusive_thread_cpu_ns": 1,
                    "failed": False,
                }
                for name in (
                    "catalog_fingerprint",
                    "classification_categories",
                    "policy_evaluation_composite",
                    "policy_store_lookup",
                    "final_quiet_barrier",
                    "child_response_wait",
                    "receipt_and_inventory_composite",
                )
            ]
            phases.extend([{**phases[0], "phase": "quiet_frame_wait"}] * 14)
            counts = {name: sum(row["phase"] == name for row in phases) for name in {row["phase"] for row in phases}}
            records.append(
                {
                    "block": 0,
                    "role": role,
                    "mode": mode,
                    "returncode": 0,
                    "capture_failure": None,
                    "resources": {"peak": {"processes": 2, "rss_bytes": 10}},
                    "result": {
                        "status": "passed",
                        "traces": traces,
                        "phases": phases,
                        "phase_counts": counts,
                        "phase_rows_dropped": 0,
                    },
                }
            )
    return records


def test_identical_trace_is_deterministic_and_refresh_changes_catalog_identity():
    for trace in trace_module.TRACES:
        assert trace_module.trace_identity(trace, 2) == trace_module.trace_identity(trace, 2)
        assert trace_module.digest(trace_module.catalog_result(trace, 1)) != trace_module.digest(
            trace_module.catalog_result(trace, 2)
        )
    assert trace_module.messages(trace_module.TRACES[3], 2)[-1]["params"]["arguments"]["text"].isascii()


def test_oracle_accepts_exact_actual_default_warn_and_inline_allow():
    for trace in (trace_module.TRACES[0], trace_module.TRACES[-1]):
        message = trace_module.messages(trace, 2)[-1]
        response = {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "_fixture": {
                    "request_sha256": trace_module.digest(message),
                    "child_wall_ns": 3,
                    "child_cpu_ns": 2,
                    "wire_bytes": 100,
                },
            },
        }
        assert trace_module.validate_tool_response(message, response, _row(message, trace), trace)["request_id"] == 4
        response["result"]["_fixture"]["request_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="different request"):
            trace_module.validate_tool_response(message, response, _row(message, trace), trace)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_run",
        "reordered_runs",
        "duplicate_run",
        "worker_error",
        "missing_call",
        "wrong_action",
        "stale_catalog",
        "missing_approval",
        "dropped_phase",
        "fake_phase_count",
        "no_child_memory",
    ),
)
def test_aggregate_rejects_omitted_or_falsely_passing_observations(mutation):
    records = _records()
    assert report_module.aggregate(records, runs=1, calls=2)["status"] == "passed"
    if mutation == "missing_run":
        records.pop()
    elif mutation == "reordered_runs":
        records.reverse()
    elif mutation == "duplicate_run":
        records.append(copy.deepcopy(records[0]))
    elif mutation == "worker_error":
        records[0]["returncode"] = 1
    elif mutation == "missing_call":
        records[0]["result"]["traces"][0]["observations"].pop()
    elif mutation == "wrong_action":
        records[0]["result"]["traces"][0]["observations"][-1]["policy_action"] = "allow"
    elif mutation == "stale_catalog":
        records[0]["result"]["traces"][0]["observations"][1]["catalog_result_sha256"] = "0" * 64
    elif mutation == "missing_approval":
        records[0]["result"]["traces"][-1]["approvals"].pop()
    elif mutation == "dropped_phase":
        records[2]["result"]["phase_rows_dropped"] = 1
    elif mutation == "fake_phase_count":
        records[2]["result"]["phase_counts"]["catalog_fingerprint"] += 1
    elif mutation == "no_child_memory":
        records[1]["resources"]["peak"]["processes"] = 1
    assert report_module.aggregate(records, runs=1, calls=2)["status"] == "failed"


def test_nested_phase_failure_and_row_bound_are_observable(monkeypatch):
    phases = phase_module.Phases()
    with phases.span("outer"), pytest.raises(ValueError), phases.span("inner"):
        raise ValueError("fixture")
    inner, outer = phases.rows
    assert inner["failed"] is True and outer["failed"] is False
    assert outer["wall_ns"] >= inner["wall_ns"]
    assert outer["exclusive_wall_ns"] == outer["wall_ns"] - inner["wall_ns"]
    monkeypatch.setattr(phase_module, "MAX_ROWS", 2)
    with phases.span("overflow"):
        pass
    assert phases.dropped == 1 and phases.counts["overflow"] == 1


def test_phase_install_restores_exact_production_bindings_after_failure():
    from codex_plugin_scanner.guard import mcp_tool_calls
    from codex_plugin_scanner.guard.proxy import runtime_mcp
    from codex_plugin_scanner.guard.store import GuardStore

    original = runtime_mcp._tool_catalog_fingerprint
    original_json = runtime_mcp.json
    with pytest.raises(ValueError), phase_module.Phases().install(runtime_mcp, mcp_tool_calls, GuardStore):
        assert runtime_mcp._tool_catalog_fingerprint is not original
        assert json.dumps({"outside": "unchanged"}) == '{"outside": "unchanged"}'
        raise ValueError("fixture")
    assert runtime_mcp._tool_catalog_fingerprint is original and runtime_mcp.json is original_json


def test_private_evidence_is_bounded_exclusive_and_owner_only(tmp_path):
    path = tmp_path / "record.json"
    report_module.write_private(path, {"safe": "value"})
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        report_module.write_private(path, {})
    with pytest.raises(ValueError, match="byte bound"):
        report_module.write_private(tmp_path / "large.json", "x" * 100, limit=10)


def test_failed_request_retains_attempt_denominator_and_missing_metric():
    records = _records()
    row = records[0]["result"]["traces"][0]["observations"][-1]
    row.pop("child_wall_ns")
    row.pop("request_sha256")
    report = report_module.aggregate(records, runs=1, calls=2)
    assert report["status"] == "failed"
    comparison = next(
        r
        for r in report["comparisons"]
        if r["role"] == "baseline" and r["mode"] == "plain" and r["trace"] == "catalog10"
    )
    assert comparison["warm_attempts"] == 1
    assert comparison["child_service_wall_ns"] is None


def test_controller_bounds_capture_and_preserves_worker_failure(tmp_path, monkeypatch):
    worker = tmp_path / "fixture_worker.py"
    worker.write_text(
        "import json, pathlib, sys\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
        "output.write_text(json.dumps({'status': 'failed', 'failure_type': 'fixture'}))\n"
        "print('x' * 70000)\n"
    )
    monkeypatch.setattr(driver_module, "WORKER", worker)
    path = tmp_path / "result.json"
    result = driver_module._worker(tmp_path, path, calls=2, diagnostic=False)
    assert result["capture_failure"] == "capture_byte_bound"
    assert result["result"]["failure_type"] == "fixture"
    capture = json.loads(path.with_suffix(".stdout.json").read_text())
    assert capture["total_bytes"] == 70001 and capture["retained_bytes"] == driver_module.MAX_CAPTURE


def test_controller_quarantines_owned_worker_if_resource_observer_fails(tmp_path, monkeypatch):
    worker = tmp_path / "fixture_worker.py"
    worker.write_text("import time\ntime.sleep(10)\n")
    monkeypatch.setattr(driver_module, "WORKER", worker)

    def unavailable(**kwargs):
        raise RuntimeError("fixture observer unavailable")

    monkeypatch.setattr(driver_module, "ResourceSampler", unavailable)
    result = driver_module._worker(tmp_path, tmp_path / "result.json", calls=2, diagnostic=False, resources=True)
    assert result["capture_failure"] == "worker_observer_failure:RuntimeError"
    assert result["returncode"] != 0 and result["result"]["status"] == "failed"
