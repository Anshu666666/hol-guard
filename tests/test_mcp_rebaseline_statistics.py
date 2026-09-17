"""Independent-run estimation and strict public interval provenance."""

from __future__ import annotations

import copy

import pytest

from scripts.mcp_rebaseline_public import project
from scripts.mcp_rebaseline_statistics import paired_comparisons
from scripts.native_slo_qualification import paired_ratio_interval
from tests.mcp_public_fixture import CANDIDATE, complete_report


@pytest.fixture(scope="module")
def report():
    return complete_report()


def test_intervals_resample_five_run_ratios_instead_of_sixty_requests(report):
    rows = copy.deepcopy(report["run_trace_summaries"])
    baseline = [1000, 1, 1, 1, 1]
    candidate = [500, 2, 2, 2, 2]
    for row in rows:
        if row["trace"] == "catalog10" and row["mode"] == "plain":
            value = (baseline if row["role"] == "baseline" else candidate)[row["block"]]
            row["warm_wall_ns"].update(p50=value, p95=value, max=value, sum=value * 12)
    observed = paired_comparisons(rows, runs=5, eligible=True)[0]
    expected = paired_ratio_interval(baseline, candidate)
    assert observed["intervals"]["warm_wall_p95"] == expected
    assert expected["runs"] == 5 and expected["median_ratio"] == 2
    assert expected["ci95_low"] == 0.5 and expected["ci95_high"] == 2
    assert observed["tail_qualified"] is False
    assert observed == paired_comparisons(rows, runs=5, eligible=True)[0]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "zero", "failed_experiment"])
def test_incomplete_pairs_never_emit_an_interval(report, mutation):
    rows = copy.deepcopy(report["run_trace_summaries"])
    target = next(row for row in rows if row["trace"] == "catalog10" and row["mode"] == "plain")
    if mutation == "missing":
        rows.remove(target)
    elif mutation == "duplicate":
        rows.append(copy.deepcopy(target))
    elif mutation == "zero":
        target["warm_process_cpu_ns"]["sum"] = 0
    observed = paired_comparisons(rows, runs=5, eligible=mutation != "failed_experiment")[0]
    assert observed["status"] == "incomplete" and observed["intervals"] is None


@pytest.mark.parametrize("mutation", ["interval", "unpaired", "unknown", "counts", "warm_missing"])
def test_public_recomputes_intervals_and_admits_only_exact_complete_run_summaries(report, mutation):
    value = copy.deepcopy(report)
    if mutation == "interval":
        value["paired_comparisons"][0]["intervals"]["warm_wall_p95"]["ci95_high"] = 0.1
    elif mutation == "unpaired":
        value["run_trace_summaries"][0]["block"] = 1
    elif mutation == "unknown":
        value["run_trace_summaries"][0]["command"] = "PRIVATE_SENTINEL"
    elif mutation == "counts":
        value["run_trace_summaries"][0]["warm_wall_ns"]["count"] = 11
    elif mutation == "warm_missing":
        resource = value["run_observations"][1]["warm_resources"][0]["resources"]
        resource["unavailable_samples"] = 1
    with pytest.raises(ValueError, match="public component"):
        project(value, candidate=CANDIDATE)
