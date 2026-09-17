from __future__ import annotations

import copy
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from tests.mcp_public_fixture import resource_fixture

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS.parent))
trace_module = importlib.import_module("scripts.mcp_rebaseline_trace")
report_module = importlib.import_module("scripts.mcp_rebaseline_report")
phase_module = importlib.import_module("scripts.mcp_rebaseline_phases")
driver_module = importlib.import_module("scripts.bench_mcp_rebaseline")


def _row(message, trace):
    result = {
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
    if trace.name == "loopback_tcp10ms":
        result.update(
            network_roundtrip_wall_ns=20_000_000,
            network_client_thread_cpu_ns=20,
            network_service_wall_ns=10_000_000,
            network_service_thread_cpu_ns=10,
            network_request_bytes=65,
            network_response_bytes=180,
            child_wall_ns=30_000_000,
        )
    return result


def _records():
    records = []
    for role in ("baseline", "candidate"):
        for mode in ("plain", "resources", "diagnostic"):
            calls = trace_module.calls_for_mode(mode, 2)
            traces = []
            for trace in trace_module.TRACES:
                rows = []
                generation = 0
                for message in trace_module.messages(trace, calls):
                    row = _row(message, trace)
                    if message["method"] == "tools/list":
                        generation += 1
                        row["catalog_result_sha256"] = trace_module.digest(
                            trace_module.catalog_result(trace, generation)
                        )
                    rows.append(row)
                traces.append(
                    {
                        **trace_module.trace_identity(trace, calls),
                        "status": "passed",
                        "observations": rows,
                        "session": {"wall_ns": 100},
                        "construction": {"wall_ns": 10},
                        "approvals": [{"wall_ns": 10}] * (calls if trace.approval_delay_ms else 0),
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
            phases.extend([{**phases[0], "phase": "quiet_frame_wait"}] * (2 * len(trace_module.TRACES)))
            counts = {name: sum(row["phase"] == name for row in phases) for name in {row["phase"] for row in phases}}
            records.append(
                {
                    "block": 0,
                    "role": role,
                    "mode": mode,
                    "returncode": 0,
                    "capture_failure": None,
                    "resources": {"peak": {"processes": 2, "rss_bytes": 10}},
                    "warm_resource_failure": None,
                    "warm_resources": [
                        {
                            "trace_index": index,
                            "status": "complete",
                            "failure": None,
                            "identity_verified": True,
                            "expected_warm_attempts": calls - 1,
                            "warm_attempts": calls - 1,
                            "resources": resource_fixture(),
                        }
                        for index in range(len(trace_module.TRACES))
                    ],
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
    ordinary = ("ad28eaa46adc48c915861f08d0612952845c35e6289e4337d272f7d24c08e62a", 604)
    expected_wire_identity = {
        "catalog10": ordinary,
        "catalog100": ordinary,
        "catalog1000": ordinary,
        "payload16k": ("e70eb6acd6622bdf42097ca57f5216afa44216e9399af40f2f48cc9c6e40a92c", 33116),
        "catalog_refresh": ("637204e928056fe5152f2e8d0c9c58ce4fffb51e4e5eef5e029af84cb9583ce8", 671),
        "child_delay10ms": ordinary,
        "inline_approval10ms": ("771f3ba7be56f05af2cac04987495e048d32d109f5197b287d75e91902a735b0", 688),
        "loopback_tcp10ms": ordinary,
    }
    assert {trace.name for trace in trace_module.TRACES} == set(expected_wire_identity)
    for trace in trace_module.TRACES:
        original = trace_module.trace_identity(trace, 2)
        assert (original["sha256"], original["canonical_bytes"]) == expected_wire_identity[trace.name]
        assert trace_module.trace_identity(trace, 3)["sha256"] != original["sha256"]
        equivalent = copy.deepcopy(trace)
        assert equivalent is not trace
        assert trace_module.trace_identity(equivalent, 2) == original
        assert trace_module.digest(trace_module.catalog_result(trace, 1)) != trace_module.digest(
            trace_module.catalog_result(trace, 2)
        )
    assert trace_module.messages(trace_module.TRACES[3], 2)[-1]["params"]["arguments"]["text"].isascii()


def test_oracle_accepts_exact_actual_default_warn_and_inline_allow():
    for trace in (trace_module.TRACES[0], next(t for t in trace_module.TRACES if t.approval_delay_ms)):
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
        next(t for t in records[0]["result"]["traces"] if t["trace"]["approval_delay_ms"])["approvals"].pop()
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


def test_controller_spawn_failure_closes_all_resource_pipe_ends(tmp_path, monkeypatch):
    pipes = driver_module.ResourcePipes.create()
    descriptors = (pipes.parent_request_fd, pipes.parent_ack_fd, *pipes.worker_fds)
    monkeypatch.setattr(driver_module.ResourcePipes, "create", lambda: pipes)

    def fail_spawn(*args, **kwargs):
        raise OSError("synthetic spawn failure")

    monkeypatch.setattr(driver_module.subprocess, "Popen", fail_spawn)
    with pytest.raises(OSError, match="spawn failure"):
        driver_module._worker(tmp_path, tmp_path / "result.json", calls=100, diagnostic=False, resources=True)
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
