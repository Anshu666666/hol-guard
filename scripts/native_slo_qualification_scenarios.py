"""Retain additional installed contracts independently of headline timers.

A baseline contract failure remains failed evidence. It must not discard
already measured priority routes or become a passing candidate contract. These
instrumented scenarios never supply an installed launcher latency sample.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_identity_cold_run import measure_cold_identity
from scripts.native_slo_identity_run import measure_evaluated_identity
from scripts.native_slo_launcher_corpus import run_registered_approval_corpus
from scripts.native_slo_launcher_input import run_registered_input_corpus
from scripts.native_slo_launcher_utf8 import run_registered_utf8_observation
from scripts.native_slo_mixed import run_mixed_scenario
from scripts.native_slo_phase_run import measure_installed_phases
from scripts.native_slo_registered_surfaces_run import SurfaceSession, run_registered_surface_corpus

_BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
_ATTRIBUTION_SCHEMA = "hol-guard.installed-attribution-scenarios.v1"
_ATTRIBUTION_SCOPES = {
    "python_phases": ("hol-guard.installed-phase-run.v1", "diagnostic_instrumented_run"),
    "runtime_identity": ("hol-guard.evaluated-hook-identity-run.v1", "prepared_resident_first_hook_and_warm"),
    "runtime_identity_cold": ("hol-guard.cold-hook-identity-run.v1", "fresh_process_preparation_first_hook_and_warm"),
}


def validate_receipt_profile(profile: str, runtime_identity: Mapping[str, object]) -> None:
    if profile not in {"candidate", "baseline_2e672d2"}:
        raise ValueError("unsupported qualification receipt profile")
    if profile == "baseline_2e672d2" and runtime_identity.get("build_sha") != _BASELINE_SHA:
        raise ValueError("legacy receipt profile requires the exact audited native build")


def _retained_scenario(
    operation: Callable[[], dict[str, object]], *, evidence_file: Path, scope: str
) -> dict[str, object]:
    try:
        report = operation()
    except Exception as error:
        report = {"scope": scope, "passed": False, "failure": failure_evidence(error)}
    safe = assert_privacy_safe(report)
    evidence_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with evidence_file.open("x", encoding="utf-8") as stream:
        evidence_file.chmod(0o600)
        stream.write(json.dumps(safe, separators=(",", ":")) + "\n")
    return safe


def run_attribution_scenarios(
    runtime: Path,
    *,
    raw_file: Path,
    receipt_profile: str,
    runtime_identity: Mapping[str, object],
    phase_count: int = 2,
) -> dict[str, object]:
    validate_receipt_profile(receipt_profile, runtime_identity)

    def phases() -> dict[str, object]:
        with DaemonFixture(runtime, setup="normal") as session:
            report = measure_installed_phases(
                session, phase_count, raw_file.with_name(raw_file.stem + "-phase-cases.jsonl")
            )
        report["passed"] = report.get("validated") == 4 * phase_count
        return report

    def identity() -> dict[str, object]:
        with DaemonFixture(runtime, setup="normal") as session:
            return measure_evaluated_identity(session, raw_file.with_name(raw_file.stem + "-identity-cases.jsonl"))

    def cold_identity() -> dict[str, object]:
        return measure_cold_identity(
            runtime,
            raw_file.with_name(raw_file.stem + "-identity-cold-cases.jsonl"),
            raw_file.with_name(raw_file.stem + "-identity-cold-observer.jsonl"),
            {key: runtime_identity.get(key) for key in ("build_sha", "runtime_sha256", "installed_package_sha256")},
        )

    return {
        "schema": _ATTRIBUTION_SCHEMA,
        "receipt_profile": receipt_profile,
        "headline_timing_eligible": False,
        "python_phases": _retained_scenario(
            phases,
            evidence_file=raw_file.with_name(raw_file.stem + "-phase-summary.json"),
            scope="diagnostic_instrumented_run",
        ),
        "runtime_identity": _retained_scenario(
            identity,
            evidence_file=raw_file.with_name(raw_file.stem + "-identity-summary.json"),
            scope="prepared_resident_first_hook_and_warm",
        ),
        "runtime_identity_cold": _retained_scenario(
            cold_identity,
            evidence_file=raw_file.with_name(raw_file.stem + "-identity-cold-summary.json"),
            scope="fresh_process_preparation_first_hook_and_warm",
        ),
    }


def _validate_attribution(attribution: Mapping[str, object], *, receipt_profile: str) -> None:
    """Reject missing or substituted summaries before any remaining offers."""
    if (
        not isinstance(attribution, Mapping)
        or set(attribution) != {"schema", "receipt_profile", "headline_timing_eligible", *_ATTRIBUTION_SCOPES}
        or attribution.get("schema") != _ATTRIBUTION_SCHEMA
        or attribution.get("receipt_profile") != receipt_profile
        or attribution.get("headline_timing_eligible") is not False
    ):
        raise ValueError("qualification attribution envelope invalid")
    for key, (schema, scope) in _ATTRIBUTION_SCOPES.items():
        report = attribution[key]
        if not isinstance(report, Mapping) or report.get("scope") != scope or type(report.get("passed")) is not bool:
            raise ValueError("qualification attribution report invalid")
        if set(report) == {"scope", "passed", "failure"}:
            failure = report["failure"]
            if (
                report["passed"] is not False
                or not isinstance(failure, Mapping)
                or type(failure.get("reason")) is not str
            ):
                raise ValueError("qualification attribution failure invalid")
            continue
        if report.get("schema") != schema or report.get("headline_timing_eligible") is not False:
            raise ValueError("qualification attribution report schema invalid")
        if report["passed"] is True:
            if key == "python_phases":
                count = report.get("count_per_case")
                groups = report.get("groups")
                if (
                    type(count) is not int
                    or not 1 <= count <= 100
                    or any(
                        type(report.get(field)) is not int or report[field] != 4 * count
                        for field in ("attempted", "validated")
                    )
                    or not isinstance(groups, Mapping)
                    or set(groups) != {"small_inline", "maximum_supported_inline"}
                    or any(
                        not isinstance(group, Mapping)
                        or any(
                            type(group.get(field)) is not int or group[field] != 2 * count
                            for field in ("attempted", "validated")
                        )
                        for group in groups.values()
                    )
                ):
                    raise ValueError("qualification attribution phase counts invalid")
            else:
                expected = {
                    "planned": 3,
                    "offered": 3,
                    "request_started": 3,
                    "validated": 3,
                    "request_not_started": 0,
                    "request_start_unknown": 0,
                    "unoffered": 0,
                }
                observer = report.get("observer")
                observer_schema = (
                    "hol-guard.evaluated-hook-identity.v1"
                    if key == "runtime_identity"
                    else "hol-guard.cold-identity-observation.v1"
                )
                if any(
                    type(report.get(field)) is not int or report[field] != value for field, value in expected.items()
                ) or (
                    not isinstance(observer, Mapping)
                    or observer.get("schema") != observer_schema
                    or observer.get("complete") is not True
                ):
                    raise ValueError("qualification attribution identity counts invalid")
    assert_privacy_safe(dict(attribution))


def run_additional_scenarios(
    runtime: Path,
    *,
    raw_file: Path,
    receipt_profile: str,
    runtime_identity: Mapping[str, object],
    precollected_attribution: Mapping[str, object],
) -> dict[str, object]:
    validate_receipt_profile(receipt_profile, runtime_identity)
    _validate_attribution(precollected_attribution, receipt_profile=receipt_profile)

    def registered() -> dict[str, object]:
        with DaemonFixture(runtime, setup="normal") as session:
            report = run_registered_surface_corpus(
                cast(SurfaceSession, cast(object, session)),
                evidence_file=raw_file.with_name(raw_file.stem + "-registered-cases.jsonl"),
            )
        count = report.get("validated_cases")
        report["passed"] = report.get("passed") is not False and type(count) is int and count > 0
        return report

    def mixed() -> dict[str, object]:
        with DaemonFixture(runtime, policy="normal") as session:
            return run_mixed_scenario(
                session,
                raw_file=raw_file.with_name(raw_file.stem + "-mixed.jsonl"),
                receipt_profile=receipt_profile,
            )

    def approvals() -> dict[str, object]:
        report = run_registered_approval_corpus(
            runtime, evidence_file=raw_file.with_name(raw_file.stem + "-approval-cases.jsonl")
        )
        report["passed"] = report.get("implemented_scope_passed") is True
        return report

    def inputs() -> dict[str, object]:
        with DaemonFixture(runtime, setup="normal") as session:
            report = run_registered_input_corpus(
                session, evidence_file=raw_file.with_name(raw_file.stem + "-input-cases.jsonl")
            )
        report["passed"] = report.get("implemented_scope_passed") is True
        return report

    def raw_utf8() -> dict[str, object]:
        with DaemonFixture(runtime, setup="normal") as session:
            return run_registered_utf8_observation(
                session, evidence_file=raw_file.with_name(raw_file.stem + "-utf8-cases.jsonl")
            )

    return {
        "schema": "hol-guard.additional-installed-scenarios.v1",
        "receipt_profile": receipt_profile,
        "headline_timing_eligible": False,
        "registered_surfaces": _retained_scenario(
            registered,
            evidence_file=raw_file.with_name(raw_file.stem + "-registered-summary.json"),
            scope="nonpriority_registered_delivery",
        ),
        "mixed_contention": _retained_scenario(
            mixed,
            evidence_file=raw_file.with_name(raw_file.stem + "-mixed-summary.json"),
            scope="installed_daemon_mixed_contention",
        ),
        "priority_approval": _retained_scenario(
            approvals,
            evidence_file=raw_file.with_name(raw_file.stem + "-approval-summary.json"),
            scope="priority_approval",
        ),
        **{key: precollected_attribution[key] for key in _ATTRIBUTION_SCOPES},
        "priority_input": _retained_scenario(
            inputs,
            evidence_file=raw_file.with_name(raw_file.stem + "-input-summary.json"),
            scope="priority_input",
        ),
        "priority_utf8": _retained_scenario(
            raw_utf8,
            evidence_file=raw_file.with_name(raw_file.stem + "-utf8-summary.json"),
            scope="priority_utf8_observation",
        ),
    }
