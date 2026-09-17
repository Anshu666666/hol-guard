#!/usr/bin/env python3
"""One installed interpreter, one real registration, serial nonpriority tails."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary  # noqa: E402
from scripts.native_probe_receipts import wait_for_route_corpus  # noqa: E402
from scripts.native_slo_adapter import route_counts  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe  # noqa: E402
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route  # noqa: E402
from scripts.native_slo_dependency_identity import dependency_versions_digest  # noqa: E402
from scripts.native_slo_evidence_files import atomic_exclusive  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_numeric_journal import NumericJournal  # noqa: E402
from scripts.native_slo_pair_io import canonical, require  # noqa: E402
from scripts.native_slo_qualification import confidence_summary  # noqa: E402
from scripts.native_slo_qualification_run import hardware_summary  # noqa: E402
from scripts.native_slo_registered_surfaces import (  # noqa: E402
    RegisteredSurface,
    SurfaceUnavailableError,
    install_registered_surface,
)
from scripts.native_slo_registered_surfaces_evidence import SurfaceAttempt, SurfaceEvidence  # noqa: E402
from scripts.native_slo_registered_surfaces_run import (  # noqa: E402
    SurfaceSession,
    _context,
    delivery_expectation,
    observe_registered_surface,
    surface_cases,
)
from scripts.native_slo_surface_tail_contract import (  # noqa: E402
    UNAVAILABLE_CODES,
    TailRoute,
    plan,
    route_for,
    workload_digest,
)
from scripts.native_slo_workloads import (  # noqa: E402
    QualificationCase,
    build_cases,
    validate_native_result,
    validate_setup,
)


def observe(
    session: SurfaceSession, surface: RegisteredSurface, case: QualificationCase, evidence: SurfaceEvidence
) -> float:
    """Readback/native/delivery witnesses are mandatory; only child I/O is timed."""
    attempt = SurfaceAttempt()
    evidence.offer(f"{surface.scope}/{case.case_id}", surface.registration_sha256)
    try:
        session.control("case_before")
        metrics = session.daemon._server.hook_worker.metrics
        before = route_counts(metrics.snapshot())
        _response, elapsed = observe_registered_surface(session, surface, case, attempt=attempt)
        attempt.stage = "route"
        after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
        attempt.route = witnessed_route(before, after)
        require(attempt.route == case.expected_route == "native_resident", "surface_tail_native_route_mismatch")
        attempt.stage = "witness"
        result = session.control("case_result")
        validate_setup(case, cast(Mapping[str, object], result["setup"]))
        validate_native_result(case, cast(Mapping[str, object] | None, result["native_result"]))
        attempt.stage = "complete"
    except BaseException:
        evidence.finish("failed", attempt)
        raise
    evidence.finish("completed", attempt)
    return elapsed


def collect(session: SurfaceSession, *, route: TailRoute, mode: str, raw_file: Path) -> dict[str, object]:
    surfaces = install_registered_surface(_context(session), route.harness)
    selected = [surface for surface in surfaces if (surface.event, surface.scope) == (route.event, route.scope)]
    require(len(selected) == 1, "surface_tail_registration_missing")
    surface = selected[0]
    cases = surface_cases(build_cases(session.workspace), surface)
    require(bool(cases), "surface_tail_preflight_missing")
    # Freeze a single ordinary vector; intrinsic file/MCP review stays review.
    ordinary = [case for case in cases if case.case_id.split("/")[2] in {"benign", "normal"}]
    require(len(ordinary) == 1, "surface_tail_ordinary_case_ambiguous")
    case = ordinary[0]
    require(case.case_id == route.case_id and len(cases) == route.preflight_count, "surface_tail_frozen_case_mismatch")
    expected, exit_code = delivery_expectation(case)
    raw: dict[str, list[float]] = {route.series: []}
    with SurfaceEvidence(raw_file.with_name(raw_file.stem + "-cases.jsonl")) as evidence:
        for vector in cases:
            observe(session, surface, vector, evidence)
        # Offer numeric work only after every strict semantic preflight succeeds.
        with NumericJournal(raw_file.with_name(raw_file.stem + "-numeric.jsonl")) as journal:
            with journal.batch(route.series, plan(mode)["samples_per_arm"]) as batch:
                for _ in range(plan(mode)["samples_per_arm"]):
                    elapsed = observe(session, surface, case, evidence)
                    batch.record([elapsed])
                    raw[route.series].append(elapsed)
            journal.finish(raw)
    atomic_exclusive(raw_file, canonical(raw))
    return {
        "schema": "hol-guard.nonpriority-tail-block.v1",
        "route": route.identifier,
        "boundary": "INSTALLED_LAUNCHER",
        "sample_class": "remaining_installed_route",
        "result_profile": "intrinsic_review" if "/normal/" in route.case_id else "benign",
        "native_decision": case.native_expected.fields["decision"] if case.native_expected else None,
        "native_policy_action": case.native_expected.fields["policy_action"] if case.native_expected else None,
        "mode": mode,
        "plan": plan(mode),
        "common_workload_digest": workload_digest(route, mode),
        "measurements": {route.series: confidence_summary(raw[route.series])},
        "preflight_cases": len(cases),
        "validated_cases": len(cases) + len(raw[route.series]),
        "errors": 0,
        "native_route": "native_resident",
        "case_id": case.case_id.replace("/", "."),
        "delivery": expected.decision,
        "model_action": expected.model_action,
        "exit_code": exit_code,
        "size_class": case.size_class,
        "registration_sha256": surface.registration_sha256,
        "registration_artifacts": dict(surface.artifact_sha256),
        "matchers_read_back": len(surface.matchers),
        "matched_tool": "Bash" if surface.matchers else "event_slot",
        "process_startup_included": True,
        "stdout_exit_checked": True,
        "full_host_activation": False,
        "resident_cold_measured": False,
        "concurrency": 1,
        "qualification_complete": False,
        "program_qualification_complete": False,
    }


def run(*, route: TailRoute, mode: str, raw_file: Path) -> dict[str, object]:
    _clear_proof_overrides()
    status = native_runtime_status()
    require(status.identity is not None, "surface_tail_runtime_unavailable")
    assert status.identity is not None
    runtime = _runtime_summary(status.identity.path)
    runtime["dependency_versions_sha256"] = dependency_versions_digest()
    with DaemonFixture(status.identity.path, setup="normal") as session:
        report = collect(cast(SurfaceSession, cast(object, session)), route=route, mode=mode, raw_file=raw_file)
    report["runtime"] = runtime
    hardware = hardware_summary()
    hardware["runner_image"] = os.environ.get("ImageVersion", "unavailable")  # noqa: SIM112
    hardware["runner_image_os"] = os.environ.get("ImageOS", "unavailable")  # noqa: SIM112
    report["hardware"] = hardware
    require(assert_privacy_safe(report) == report, "surface_tail_public_projection_invalid")
    return report


def failure_report(error: Exception) -> dict[str, object]:
    result = failure_evidence(error)
    if isinstance(error, SurfaceUnavailableError) and str(error) in UNAVAILABLE_CODES:
        result["availability_code"] = str(error)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route", required=True)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    parser.add_argument("--raw-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(route=route_for(args.route), mode=args.mode, raw_file=args.raw_file)
    except Exception as error:
        print(json.dumps(failure_report(error), sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
