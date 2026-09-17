"""Shared paired-run comparison; collection layout does not change estimators."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from scripts.native_slo_acceptance import scoped_acceptance
from scripts.native_slo_adapter import route_matrix
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_qualification import compare_routes, sampling_gates, sampling_plan
from scripts.native_slo_workload_identity import reference_comparability, timing_series


def _object_field(report: Mapping[str, object], field: str) -> Mapping[str, object]:
    value = report.get(field)
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RuntimeError("paired block evidence object invalid: " + field)
    return cast(Mapping[str, object], value)


def _text_field(report: Mapping[str, object], field: str) -> str:
    value = report.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError("paired block evidence identifier invalid: " + field)
    return value


def compare_blocks(
    reports: Mapping[str, Sequence[Mapping[str, object]]],
    *,
    mode: str,
    runs: int,
    artifact_digests: Mapping[str, str],
) -> dict[str, object]:
    plan = sampling_plan(runs=runs, qualification=mode == "qualification")
    if set(reports) != {"baseline", "candidate"} or any(len(arm) != runs for arm in reports.values()):
        raise RuntimeError("paired comparison requires every declared block")
    combined = [*reports["baseline"], *reports["candidate"]]
    if any(
        _text_field(report, "corpus_digest") != _text_field(report, "common_workload_digest") for report in combined
    ):
        raise RuntimeError("paired block has an inconsistent common workload identity")
    if len({_text_field(report, "common_workload_digest") for report in combined}) != 1:
        raise RuntimeError("paired artifacts used different common workload definitions")
    allowed_series = timing_series(route_matrix())
    if any(set(_object_field(report, "measurements")) - allowed_series for report in combined):
        raise RuntimeError("paired block contains a timing series outside the common workload")
    identities = [_object_field(report, "hardware") for report in combined]
    stable_fields = (
        "platform",
        "cpu_model",
        "cpu_count",
        "effective_cpu_count",
        "ram_bytes",
        "os_release",
        "runner_image",
        "runner_image_os",
    )
    if any(any(item.get(field) != identities[0].get(field) for field in stable_fields) for item in identities[1:]):
        raise RuntimeError("paired hardware identity changed between blocks")
    if len({_text_field(_object_field(report, "runtime"), "python_version") for report in combined}) != 1:
        raise RuntimeError("paired interpreter version changed between artifacts")
    # Keep artifact identity stable within each arm, not equal across arms.
    for arm in reports.values():
        if len({_text_field(report, "semantic_scope_digest") for report in arm}) != 1:
            raise RuntimeError("semantic scope changed within a paired arm")
        if (
            len(
                {
                    tuple(
                        _text_field(_object_field(report, "runtime"), key)
                        for key in ("runtime_sha256", "package_record_sha256")
                    )
                    for report in arm
                }
            )
            != 1
        ):
            raise RuntimeError("artifact changed within a paired arm")
    comparison = compare_routes(
        [_object_field(report, "measurements") for report in reports["baseline"]],
        [_object_field(report, "measurements") for report in reports["candidate"]],
    )
    gates = sampling_gates(comparison, runs=runs)
    gates["steady_state_resources"] = all(
        _object_field(report, "resources").get("sample_minimum_met") is True for report in combined
    )
    acceptance = scoped_acceptance(reports["baseline"], reports["candidate"], comparison, gates)
    result = assert_privacy_safe(
        {
            "schema": "hol-guard.native-paired-performance.v1",
            "collection_complete": True,
            "evidence_class": "qualification_sampling" if mode == "qualification" else "smoke",
            "plan": plan,
            "order": "alternating_baseline_candidate_blocks",
            "corpus_digest": combined[0]["corpus_digest"],
            "common_workload_digest": combined[0]["common_workload_digest"],
            "semantic_scope_digests": {arm: items[0]["semantic_scope_digest"] for arm, items in reports.items()},
            "reference_comparability": reference_comparability(reports["baseline"], reports["candidate"]),
            "baseline": reports["baseline"][0]["runtime"],
            "candidate": reports["candidate"][0]["runtime"],
            "artifact_digests": artifact_digests,
            "hardware": identities[0],
            "comparisons": comparison,
            "sampling_gates": gates,
            "sampling_passed": all(gates.values()),
            "acceptance": acceptance,
            "qualification_complete": mode == "qualification"
            and all(scope["qualified"] for scope in acceptance["scopes"].values()),
            "qualification_scope": "observed_platform_implemented_hook_boundaries",
            "program_qualification_complete": False,
        }
    )
    return result
