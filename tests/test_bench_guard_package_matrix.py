"""Benchmark qualification must observe full results and deterministic samples."""

from __future__ import annotations

from copy import deepcopy
from itertools import pairwise

import pytest

from scripts.bench_guard_package_matrix import compare_results


def _arm():
    return {
        "status": "complete",
        "measurement": {
            "corpus_sha256": "corpus",
            "semantic_sha256": ["partial"],
            "complete_result_sha256": ["full"],
            "persisted_evidence_sha256": ["evidence"],
            "wall_median_ms": 100,
            "cpu_median_ms": 90,
        },
    }


@pytest.mark.parametrize("field", ["corpus_sha256", "complete_result_sha256", "persisted_evidence_sha256"])
def test_matrix_rejects_full_result_or_evidence_difference_with_same_decision_subset(field: str) -> None:
    baseline = _arm()
    candidate = deepcopy(baseline)
    candidate["measurement"][field] = "different" if field == "corpus_sha256" else ["different"]
    assert compare_results(baseline, candidate)["status"] == "mismatch"


def test_matrix_rejects_identically_nondeterministic_sample_sets() -> None:
    baseline = _arm()
    baseline["measurement"]["complete_result_sha256"] = ["full", "changed"]
    assert compare_results(baseline, deepcopy(baseline))["status"] == "mismatch"


def test_matrix_never_treats_censored_timeout_as_latency() -> None:
    censored = {"status": "censored_whole_process_timeout", "whole_process_timeout_seconds": 20}
    assert compare_results(censored, _arm()) == {"status": "not_comparable"}


def test_matrix_compares_deterministic_different_sample_counts() -> None:
    baseline = _arm()
    candidate = deepcopy(baseline)
    for field in ("semantic_sha256", "complete_result_sha256", "persisted_evidence_sha256"):
        candidate["measurement"][field] *= 3
    candidate["measurement"]["cpu_median_ms"] = 45
    comparison = compare_results(baseline, candidate)
    assert comparison["status"] == "equal"
    assert comparison["median_cpu_improvement_percent"] == 50


def test_matrix_rejects_unequal_timed_sample_counts(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import sys

    from scripts import bench_guard_package_matrix as runner

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "matrix",
            "--baseline-root",
            str(tmp_path),
            "--candidate-root",
            str(tmp_path),
            "--measurement-lock",
            str(tmp_path / "lock"),
            "--output",
            str(tmp_path / "report.json"),
            "--baseline-samples",
            "1",
            "--candidate-samples",
            "3",
        ],
    )
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2


def test_matrix_order_changes_within_each_match_mode(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import os
    import sys

    from scripts import bench_guard_package_matrix as runner

    if os.name != "posix":
        pytest.skip("The diagnostic runner requires POSIX advisory locking")
    observations = []

    def fake_arm(_args, **kwargs):
        observations.append((kwargs["mode"], kwargs["candidate"]))
        return _arm()

    monkeypatch.setattr(runner, "run_arm", fake_arm)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "matrix",
            "--baseline-root",
            str(tmp_path),
            "--candidate-root",
            str(tmp_path),
            "--measurement-lock",
            str(tmp_path / "lock"),
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    assert runner.main() == 0
    first_arms = observations[::2]
    for mode in ("absent", "exact", "unversioned", "deny"):
        arm_orders = [candidate for observed_mode, candidate in first_arms if observed_mode == mode]
        assert len(arm_orders) == 9
        assert all(a != b for a, b in pairwise(arm_orders))
