from __future__ import annotations

import copy
import json

import pytest

from scripts import bench_mcp_rebaseline as driver
from scripts import mcp_rebaseline_ci as ci
from scripts.mcp_rebaseline_public import TOOL_CALLS, project
from scripts.mcp_rebaseline_statistics import paired_comparisons
from scripts.mcp_rebaseline_trace import digest
from tests.mcp_public_fixture import CANDIDATE, complete_report

SENTINEL = "PRIVATE_FIXTURE_SENTINEL"


@pytest.fixture(scope="module")
def frozen_report():
    return complete_report()


@pytest.mark.parametrize(
    "case",
    [
        "comparison_text",
        "run_text",
        "phase_text",
        "resource_text",
        "unknown_nested",
        "failure_text",
        "boolean_number",
        "nan",
        "infinity",
        "empty_pass",
        "missing_worker",
        "wrong_total",
        "wrong_warm",
        "missing_phase",
        "duplicate_group",
        "missing_metric",
        "passing_failure",
        "missing_raw",
        "duplicate_worker",
        "wrong_expected",
        "wrong_mode",
    ],
)
def test_public_projection_rejects_nested_data_and_inconsistent_pass(tmp_path, frozen_report, case):
    report = copy.deepcopy(frozen_report)
    if case == "comparison_text":
        report["comparisons"][0]["warm_wall_ns"]["p50"] = SENTINEL
    elif case == "run_text":
        report["run_observations"][0]["import"]["wall_ns"] = SENTINEL
    elif case == "phase_text":
        report["diagnostic_phases"][0]["phase"] = SENTINEL
    elif case == "resource_text":
        report["run_observations"][1]["resources"]["unavailable_metrics"]["rss_bytes"] = {SENTINEL: 1}
    elif case == "unknown_nested":
        report["comparisons"][0]["raw"] = SENTINEL
    elif case == "failure_text":
        report["failures"] = [SENTINEL]
    elif case == "boolean_number":
        report["observed_worker_attempts"] = True
    elif case in {"nan", "infinity"}:
        report["comparisons"][0]["warm_wall_ns"]["sum"] = float("nan" if case == "nan" else "inf")
    elif case == "empty_pass":
        report["comparisons"] = []
        report["run_observations"] = []
        report["observed_worker_attempts"] = 0
        report["observed_tool_call_outcomes"] = 0
    elif case == "missing_worker":
        report["run_observations"].pop()
        report["observed_worker_attempts"] -= 1
    elif case == "wrong_total":
        report["observed_tool_call_outcomes"] -= 1
    elif case == "wrong_warm":
        report["comparisons"][0]["warm_attempts"] -= 1
    elif case == "missing_phase":
        report["diagnostic_phases"].pop()
    elif case == "duplicate_group":
        report["comparisons"][-1] = copy.deepcopy(report["comparisons"][0])
    elif case == "missing_metric":
        report["comparisons"][0]["warm_wall_ns"] = None
    elif case == "passing_failure":
        report["failures"] = ["trace_inventory"]
    elif case == "missing_raw":
        report["raw_evidence"].pop()
    elif case == "duplicate_worker":
        report["run_observations"][-1] = copy.deepcopy(report["run_observations"][0])
    elif case == "wrong_expected":
        report["expected_tool_call_attempts"] = 2700
    elif case == "wrong_mode":
        report["run_observations"][0]["phase_counts"] = {"quiet_frame_wait": 91}
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "aggregate.json"
    # Exercise invalid JSON numbers too; the production writer rejects these.
    path.write_text(json.dumps(report))
    path.chmod(0o600)
    output = tmp_path / "public.json"
    observed = ci.publish(private, output, candidate=CANDIDATE, outcome="success")
    assert observed["status"] == "incomplete" and observed["measurements"] is None
    assert observed["expected_worker_attempts"] == 30 and observed["expected_tool_call_attempts"] == TOOL_CALLS
    assert SENTINEL not in output.read_text()


def test_environment_text_stays_private_and_projection_does_not_alias(frozen_report):
    report = copy.deepcopy(frozen_report)
    report["source_and_environment"]["python"] = SENTINEL
    report["source_and_environment"]["dependencies"] = [SENTINEL]
    public = project(report, candidate=CANDIDATE)
    assert public["status"] == "passed" and SENTINEL not in json.dumps(public)
    assert public["source_and_environment"]["private_manifest_sha256"] == digest(report["source_and_environment"])
    report["comparisons"][0]["warm_wall_ns"]["p50"] = SENTINEL
    assert SENTINEL not in json.dumps(public)


def test_failed_partial_report_keeps_actual_counts_and_unknown_metrics(frozen_report):
    report = copy.deepcopy(frozen_report)
    report.update(status="failed", failures=["worker_failure:0:baseline:plain", "trace_inventory"])
    report["observed_tool_call_outcomes"] -= 104
    run = report["run_observations"][0]
    run.update(returncode=None, capture_failure="controller_worker_failure")
    for key in (
        "import",
        "phase_counts",
        "self_cpu_seconds",
        "waited_child_cpu_seconds",
        "self_peak_rss_bytes",
        "largest_waited_child_peak_rss_bytes",
    ):
        run[key] = None
    run.pop("worker_lifecycle_wall_ns")
    for row in report["comparisons"]:
        row["headline_eligible"] = False
        if row["role"] == "baseline" and row["mode"] == "plain":
            row.update(independent_runs=4, warm_attempts=48, cold_attempts=4)
            for value in row.values():
                if isinstance(value, dict) and "count" in value:
                    value["count"] = value["count"] * 4 // 5
                    value["sum"] = value["sum"] * 4 // 5
    report["run_trace_summaries"] = [
        r
        for r in report["run_trace_summaries"]
        if not (r["block"] == 0 and r["role"] == "baseline" and r["mode"] == "plain")
    ]
    for row in report["run_trace_summaries"]:
        row["headline_eligible"] = False
    report["paired_comparisons"] = paired_comparisons(report["run_trace_summaries"], runs=5, eligible=False)
    report["raw_evidence"] = [
        row for row in report["raw_evidence"] if not row["file"].startswith("0-baseline-plain.raw")
    ]
    public = project(report, candidate=CANDIDATE)
    assert public["status"] == "failed"
    assert public["observed_worker_attempts"] == 30 and public["observed_tool_call_outcomes"] == TOOL_CALLS - 104
    assert public["run_observations"][0]["self_cpu_seconds"] is None
    assert all(not row["headline_eligible"] for row in public["comparisons"])


@pytest.mark.parametrize("retained_exceeds_count", [False, True])
def test_failed_phase_accounting_preserves_actual_denominators(frozen_report, retained_exceeds_count):
    report = copy.deepcopy(frozen_report)
    report.update(status="failed", failures=["phase_row_accounting"])
    for comparison in report["comparisons"]:
        comparison["headline_eligible"] = False
    for row in report["run_trace_summaries"]:
        row["headline_eligible"] = False
    report["paired_comparisons"] = paired_comparisons(report["run_trace_summaries"], runs=5, eligible=False)
    if retained_exceeds_count:
        report["run_observations"][2]["phase_counts"]["catalog_fingerprint"] -= 1
    else:
        report["diagnostic_phases"].pop()
    public = project(report, candidate=CANDIDATE)
    assert public["status"] == "failed" and public["failures"] == ["phase_row_accounting"]
    assert public["observed_worker_attempts"] == 30 and public["observed_tool_call_outcomes"] == TOOL_CALLS
    assert public["diagnostic_phases"] == report["diagnostic_phases"]
    assert public["run_observations"] == report["run_observations"]


@pytest.mark.parametrize("name,expected", [("OSError", "OSError"), (SENTINEL * 100, "NonStandardException")])
def test_controller_exception_class_is_bounded_private_and_preserves_attempts(tmp_path, monkeypatch, name, expected):
    error_type = type(name, (Exception,), {})

    def fail(*args, **kwargs):
        raise error_type(SENTINEL)

    monkeypatch.setattr(driver, "_worker", fail)
    monkeypatch.setattr(
        driver,
        "source_identity",
        lambda path: {
            "commit": ci.BASELINE if path.name == "baseline" else CANDIDATE,
            "production_tree": "b" * 40,
            "uv_lock_sha256": "c" * 64,
        },
    )
    output = tmp_path / "private"
    report = driver.run(tmp_path / "baseline", tmp_path / "candidate", output, runs=5, calls=13, lock=tmp_path / "lock")
    assert report["status"] == "failed" and report["observed_worker_attempts"] == 30
    assert report["observed_tool_call_outcomes"] == 0
    observations = list(output.glob("*.observation.json"))
    assert len(observations) == 30
    for path in observations:
        observed = json.loads(path.read_text())
        assert observed["controller_exception_class"] == expected
        assert SENTINEL not in path.read_text() and path.stat().st_mode & 0o777 == 0o600
    assert "controller_exception_class" not in json.dumps(report)
    public = project(report, candidate=CANDIDATE)
    assert public["status"] == "failed" and public["observed_worker_attempts"] == 30


def test_controller_stops_offering_workers_when_cleanup_cannot_be_proved(tmp_path, monkeypatch):
    monkeypatch.setattr(
        driver,
        "_worker",
        lambda *args, **kwargs: {
            "returncode": -9,
            "capture_failure": "resource_observer_cleanup_incomplete",
            "result": {"status": "failed"},
        },
    )
    monkeypatch.setattr(
        driver,
        "source_identity",
        lambda path: {
            "commit": ci.BASELINE if path.name == "baseline" else CANDIDATE,
            "production_tree": "b" * 40,
            "uv_lock_sha256": "c" * 64,
        },
    )
    output = tmp_path / "private"
    report = driver.run(tmp_path / "baseline", tmp_path / "candidate", output, runs=5, calls=13, lock=tmp_path / "lock")
    assert report["status"] == "failed" and report["observed_worker_attempts"] == 1
    assert len(list(output.glob("*.begin.json"))) == 1
    assert report["observed_tool_call_outcomes"] == 0
    public = project(report, candidate=CANDIDATE)
    assert public["observed_worker_attempts"] == 1
    assert all(row["intervals"] is None for row in public["paired_comparisons"])
