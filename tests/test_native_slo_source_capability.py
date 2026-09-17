"""A verified artifact capability selects strict source semantics, never a response."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_source_capability as capability
from scripts import native_slo_workloads as workloads
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_qualification_run import workload_matrix
from scripts.native_slo_session import AdapterSession


def _status(runtime: Path, features: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=SimpleNamespace(path=runtime),
        capabilities=SimpleNamespace(features=features),
    )


@pytest.mark.parametrize("features", [(), ("post-tool-source-read-v1",), ("native-source-handle-read-v2",)])
def test_windows_old_or_unknown_capability_retains_unsupported_baseline(features: tuple[str, ...]) -> None:
    assert not workloads.source_reference_supported(system="Windows", features=features)
    assert workloads.source_reference_supported(system="Linux", features=features)
    assert workloads.source_reference_supported(system="Darwin", features=features)


def test_selected_runtime_overrides_untrusted_caller_feature_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    status = _status(runtime, ("post-tool-source-read-v1",))
    monkeypatch.setattr(capability, "native_runtime_status", lambda: status)
    assert not workloads.source_reference_supported(
        system="Windows",
        runtime=runtime,
        features=(capability.SOURCE_HANDLE_READ_FEATURE,),
    )
    status.capabilities.features = (capability.SOURCE_HANDLE_READ_FEATURE,)
    assert workloads.source_reference_supported(system="Windows", runtime=runtime)


@pytest.mark.parametrize("mutation", ["mode", "available", "compatible", "reason", "identity", "capabilities", "path"])
def test_unverified_runtime_is_a_failure_not_an_unsupported_platform_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    runtime = tmp_path / "runtime"
    status = _status(runtime, (capability.SOURCE_HANDLE_READ_FEATURE,))
    if mutation == "path":
        status.identity.path = tmp_path / "other-runtime"
    else:
        setattr(status, mutation, {"mode": "force", "reason": "not_ready"}.get(mutation))
    monkeypatch.setattr(capability, "native_runtime_status", lambda: status)
    with pytest.raises(RuntimeError, match="source_capability_runtime_"):
        workloads.source_reference_supported(system="Windows", runtime=runtime)


def test_capable_windows_candidate_keeps_original_content_digest_and_watch_oracles(tmp_path: Path) -> None:
    candidate = workloads.build_cases(tmp_path, system="Windows", features=(capability.SOURCE_HANDLE_READ_FEATURE,))
    unix = workloads.build_cases(tmp_path, system="Linux")
    baseline = workloads.build_cases(tmp_path, system="Windows")
    assert candidate == unix
    source = [case for case in candidate if case.payload_kind == "source_file_ref"]
    assert source and all(case.validation_scope == "full_semantics" for case in source)
    assert any(case.setup == "watch" for case in source)
    assert any("source-digest-mismatch" in case.case_id for case in source)
    for case in source:
        assert case.native_expected is not None
        if case.native_expected.reason_code == "no_output_to_review":
            continue  # A declared digest mismatch remains a real refusal.
        changed = dict(case.native_expected.fields)
        changed["reason_code"] = "no_output_to_review"
        with pytest.raises(AssertionError):
            workloads.validate_native_result(case, changed)
    baseline_scope = workloads.platform_scope_summary(baseline, [case.case_id for case in baseline])
    assert baseline_scope["reference_review_qualified"] is False
    assert baseline_scope["platform_denial_timing_eligible"] is False
    scope = workloads.platform_scope_summary(candidate, [case.case_id for case in candidate])
    assert scope["reference_review_supported"] is True
    assert scope["reference_review_qualified"] is True
    assert scope["missing_scopes"] == []
    corpus = {
        "coverage": {},
        "platform_scope": scope,
        "declared_cases": len(candidate),
        "validated_cases": len(candidate),
        "remaining_setups": [],
        "complete": True,
    }
    matrix = workload_matrix((("pi", "PostToolUse"),), corpus)
    assert matrix["reference_review_qualified"] is True
    assert matrix["missing_reference_scopes"] == []


def test_capability_without_observed_source_coverage_cannot_qualify() -> None:
    corpus = {
        "coverage": {},
        "platform_scope": {"reference_review_supported": True},
        "declared_cases": 0,
        "validated_cases": 0,
        "remaining_setups": [],
        "complete": True,
    }
    matrix = workload_matrix((), corpus)
    assert matrix["reference_review_supported"] is True
    assert matrix["reference_review_qualified"] is False
    assert matrix["daemon_contract_complete"] is False


def test_capability_identity_label_survives_aggregate_privacy_filter() -> None:
    evidence = {"runtime": {"reference_reader_capability": capability.SOURCE_HANDLE_READ_FEATURE}}
    assert assert_privacy_safe(evidence) == evidence


def test_capable_installed_sizes_use_full_review_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import bench_guard_native_installed_slo as installed
    from scripts.native_slo_adapter import Observation

    runtime = tmp_path / "runtime"
    monkeypatch.setattr(
        capability, "native_runtime_status", lambda: _status(runtime, (capability.SOURCE_HANDLE_READ_FEATURE,))
    )
    monkeypatch.setattr(workloads.platform, "system", lambda: "Windows")
    observed: list[str] = []

    def observe(harness: str, event: str, size: str, payload: object) -> Observation:
        observed.append(size)
        return Observation(harness, event, size, 1, "native_resident", True)

    session = SimpleNamespace(
        runtime=runtime,
        workspace=tmp_path,
        observe=observe,
        probe_source_reference_denial=lambda *_args: pytest.fail("candidate downgraded to baseline refusal"),
    )
    samples = installed._run_sizes(cast(AdapterSession, cast(object, session)), (("pi", "PostToolUse"),))
    assert observed == ["250k", "1m", "5m"]
    assert len(samples) == 3
