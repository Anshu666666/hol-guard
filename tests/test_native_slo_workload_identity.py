from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import native_slo_workload_identity as identity
from scripts import qualify_guard_native
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_qualification import sampling_plan
from scripts.native_slo_qualification_run import workload_matrix
from scripts.native_slo_source_capability import SOURCE_HANDLE_READ_FEATURE
from scripts.native_slo_workloads import build_cases, platform_scope_summary

_ROUTES = (("pi", "PostToolUse"),)
_Report = dict[str, Any]


def _common(
    *,
    routes: Sequence[tuple[str, str]] = _ROUTES,
    plan: Mapping[str, int] | None = None,
    manifest_digest: str = "a" * 64,
    oracle_digest: str = "b" * 64,
) -> str:
    return identity.common_workload_digest(
        routes=routes,
        plan=plan if plan is not None else sampling_plan(runs=5, qualification=True),
        manifest_digest=manifest_digest,
        oracle_digest=oracle_digest,
    )


@pytest.fixture(scope="module")
def platform_reports(tmp_path_factory: pytest.TempPathFactory) -> tuple[_Report, _Report]:
    workspace = tmp_path_factory.mktemp("common-workload")
    result: list[_Report] = []
    for features in ((), (SOURCE_HANDLE_READ_FEATURE,)):
        cases = build_cases(workspace, system="Windows", features=features)
        validated = [case.case_id for case in cases]
        corpus = {
            "coverage": {},
            "declared_cases": len(cases),
            "validated_cases": len(cases),
            "remaining_setups": [],
            "complete": True,
            "implemented_scope_passed": True,
            "validated_digest": hashlib.sha256(json.dumps(validated).encode()).hexdigest(),
            "platform_scope": platform_scope_summary(cases, validated),
        }
        launcher = {"validated_digest": "c" * 64, "implemented_scope_passed": True}
        matrix = workload_matrix(_ROUTES, corpus, launcher)
        result.append(
            {
                "corpus_digest": _common(),
                "common_workload_digest": _common(),
                "semantic_scope_digest": identity.semantic_scope_digest(matrix, corpus, launcher),
                "matrix": matrix,
                "contract_corpus": corpus,
                "registered_launcher_contract_corpus": launcher,
            }
        )
    return result[0], result[1]


def test_real_platform_case_inventory_has_common_inputs_and_distinct_observed_scopes(
    platform_reports: tuple[_Report, _Report],
) -> None:
    baseline, candidate = platform_reports
    assert baseline["common_workload_digest"] == candidate["common_workload_digest"]
    assert baseline["semantic_scope_digest"] != candidate["semantic_scope_digest"]
    old = baseline["contract_corpus"]["platform_scope"]
    new = candidate["contract_corpus"]["platform_scope"]
    assert old["platform_denial_validated_cases"] == 55
    assert old["reference_review_qualified"] is False
    assert new["platform_denial_validated_cases"] == 0
    assert new["reference_review_qualified"] is True
    comparison = cast(_Report, identity.reference_comparability([baseline], [candidate]))
    assert comparison["semantic_comparison_available"] is False
    assert comparison["timing_comparison_available"] is False
    assert comparison["arms"]["baseline"]["denial_contracts_passed"] is True
    assert comparison["arms"]["candidate"]["full_review_contracts_passed"] is True
    assert assert_privacy_safe(comparison) == comparison


@pytest.mark.parametrize(
    "changed",
    [
        {"manifest_digest": "d" * 64},
        {"oracle_digest": "d" * 64},
        {"routes": (("claude-code", "PostToolUse"),)},
        {"plan": sampling_plan(runs=6, qualification=True)},
    ],
)
def test_common_identity_rejects_changed_frozen_inputs_or_sampling(changed: _Report) -> None:
    assert _common() != _common(**changed)


def test_common_identity_binds_actual_timed_fixture_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    before = _common()
    original = identity.workload_payload

    def changed(event: str, size: str) -> dict[str, object]:
        request = original(event, size)
        request["tool_response"] = [{"type": "text", "text": "different timed bytes"}]
        return request

    monkeypatch.setattr(identity, "workload_payload", changed)
    assert _common() != before


def test_reference_comparability_requires_every_arm_and_block(platform_reports: tuple[_Report, _Report]) -> None:
    baseline, candidate = platform_reports
    assert identity.reference_comparability([candidate], [candidate])["semantic_comparison_available"] is True
    for left, right in (
        ([], [candidate]),
        ([candidate], []),
        ([candidate, baseline], [candidate]),
        ([{}], [candidate]),
    ):
        comparison = identity.reference_comparability(left, right)
        assert comparison["semantic_comparison_available"] is False
        assert comparison["timing_comparison_available"] is False


def _paired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reports: tuple[_Report, _Report],
    *,
    mutation: str = "none",
) -> _Report:
    args = argparse.Namespace(
        baseline_python=tmp_path / "baseline-python",
        candidate_python=tmp_path / "candidate-python",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=2,
        mode="smoke",
        output_dir=tmp_path / "evidence",
        block_timeout_seconds=10,
    )
    calls = {"baseline": 0, "candidate": 0}

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        arm = "baseline" if argv[0] == str(args.baseline_python) else "candidate"
        report = deepcopy(reports[0 if arm == "baseline" else 1])
        report.update(
            schema="hol-guard.native-qualification-block.v1",
            runtime={"runtime_sha256": arm, "package_record_sha256": arm, "python_version": "3.12.14"},
            hardware={"platform": "windows-x64", "cpu_model": "same-cpu"},
            resources={"sample_minimum_met": False, "short_exited_descendants_cpu_complete": False},
            measurements={"DAEMON_INGRESS.pi.PostToolUse": {"count": 2, "p95_ms": 10, "p99_ms": 11}},
        )
        if arm == "candidate":
            if mutation == "common":
                report["common_workload_digest"] = report["corpus_digest"] = "d" * 64
            elif mutation == "alias":
                report["corpus_digest"] = "d" * 64
            elif mutation == "missing":
                del report["common_workload_digest"]
            elif mutation == "scope" and calls[arm]:
                report["semantic_scope_digest"] = "d" * 64
        if mutation == "reference_series":
            # Even identical series names on both arms cannot turn an old
            # source refusal into an apparent faster full-content review.
            report["measurements"]["DAEMON_INGRESS.pi.PostToolUse.reference"] = {
                "count": 2000,
                "p95_ms": 0.1 if arm == "baseline" else 20,
                "p99_ms": 21,
            }
        calls[arm] += 1
        Path(argv[argv.index("--raw-file") + 1]).write_text("{}")
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=json.dumps(report),
        )

    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", run)
    return cast(_Report, qualify_guard_native._run_pair(args))


def test_controller_compares_common_inline_work_and_retains_incomparable_reference_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform_reports: tuple[_Report, _Report]
) -> None:
    result = _paired(tmp_path, monkeypatch, platform_reports)
    assert set(result["comparisons"]) == {"DAEMON_INGRESS.pi.PostToolUse"}
    evidence = result["reference_comparability"]
    assert evidence["semantic_comparison_available"] is False
    assert evidence["arms"]["baseline"]["denial_contracts_passed"] is True
    assert evidence["arms"]["candidate"]["full_review_contracts_passed"] is True
    scopes = result["acceptance"]["scopes"]
    assert scopes["reference_full_review"]["qualified"] is False
    assert scopes["daemon_resources.cpu_ms_per_attempt"]["qualified"] is False
    assert result["acceptance"]["migration_benefit_go"] is False
    assert result["qualification_complete"] is False
    assert result["program_qualification_complete"] is False
    saved = json.loads((tmp_path / "evidence/aggregate/00-baseline.json").read_text())
    assert saved["contract_corpus"]["platform_scope"]["platform_denial_validated_cases"] == 55


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("common", "different common workload"),
        ("alias", "inconsistent common workload"),
        ("missing", "identifier invalid"),
        ("scope", "semantic scope changed"),
        ("reference_series", "outside the common workload"),
    ],
)
def test_controller_rejects_input_drift_scope_drift_and_incomparable_timers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_reports: tuple[_Report, _Report],
    mutation: str,
    error: str,
) -> None:
    with pytest.raises(RuntimeError, match=error):
        _paired(tmp_path, monkeypatch, platform_reports, mutation=mutation)
    assert not (tmp_path / "evidence/aggregate/comparison.json").exists()
    assert len(tuple((tmp_path / "evidence/aggregate").glob("0*-*.json"))) == 4
