"""Explicit diagnostic-wheel client attribution; never production selection."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from scripts.native_client_profile_observer import ClientObserver  # noqa: E402
from scripts.native_client_profile_records import PHASES, Journal, require  # noqa: E402
from scripts.native_client_profile_report import validate_report  # noqa: E402
from scripts.native_client_profile_resident import require_evaluated, summarize_resident_profiles  # noqa: E402
from scripts.native_slo_artifact import (  # noqa: E402
    assert_installed_import_origin,
    installed_package_digest,
    wheel_package_digest,
)
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment, summarize  # noqa: E402
from scripts.native_slo_evidence_files import _new_directory, atomic_exclusive  # noqa: E402
from scripts.native_slo_pair_io import digest_file, write_public  # noqa: E402


def installed_identity(wheel: Path, source_sha: str) -> tuple[Path, dict[str, Any]]:
    from codex_plugin_scanner.guard import native_runtime

    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None)
    require(not Path(sys.prefix).resolve().is_relative_to(ROOT))
    distribution = importlib.metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    expected = wheel_package_digest(wheel)
    require(installed_package_digest(distribution) == expected)
    status = native_runtime._inspect_native_runtime_status(allow_attestation=False)
    require(status.mode == "auto" and status.available and status.compatible)
    identity, capabilities = status.identity, status.capabilities
    require(identity is not None and capabilities is not None)
    assert identity is not None and capabilities is not None
    require(capabilities.build_sha == source_sha and list(capabilities.features).count("native-client-profile-v1") == 1)
    require(list(capabilities.features).count("native-resident-profile-v1") == 1)
    require(identity.path == native_runtime._bundled_runtime_candidate().resolve(strict=True))
    return identity.path, {
        "build_sha": source_sha,
        "wheel_sha256": digest_file(wheel, 256 * 1024 * 1024),
        "runtime_sha256": identity.sha256,
        "target": capabilities.target,
        "rule_digest": capabilities.rule_digest,
        "installed_package_sha256": expected,
        "artifact_scope": "explicit_diagnostic_feature_wheel",
        "production_selected": False,
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "observer_sha256": hashlib.sha256(
            (ROOT / "scripts/native_client_profile_observer.py").read_bytes()
        ).hexdigest(),
        "records_sha256": hashlib.sha256((ROOT / "scripts/native_client_profile_records.py").read_bytes()).hexdigest(),
        "report_sha256": hashlib.sha256((ROOT / "scripts/native_client_profile_report.py").read_bytes()).hexdigest(),
        "resident_profile_sha256": hashlib.sha256(
            (ROOT / "scripts/native_client_profile_resident.py").read_bytes()
        ).hexdigest(),
        "lock_sha256": hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
    }


def summarize_profiles(records: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for case in ("benign", "secret"):
        selected = [item["profile"] for item in records if item["case"] == case]
        result["benign" if case == "benign" else "credential_fixture"] = {
            "count": len(selected),
            "socket_opened": sum(item["socket_opened"] for item in selected),
            "socket_accounting_complete": bool(selected) and all(item["socket_count_complete"] for item in selected),
            "phases": {
                phase: {
                    "calls": sum(item["phases"][phase]["calls"] for item in selected),
                    "succeeded": sum(item["phases"][phase]["succeeded"] for item in selected),
                    "duration_ms": summarize(
                        [
                            item["phases"][phase]["nanoseconds"] / 1e6
                            for item in selected
                            if item["phases"][phase]["nanoseconds"] is not None
                        ]
                    )
                    if any(item["phases"][phase]["nanoseconds"] is not None for item in selected)
                    else None,
                }
                for phase in PHASES
            },
        }
    return result


def worker(*, wheel: Path, source_sha: str, private: Path, count: int) -> dict[str, Any]:
    from codex_plugin_scanner.guard import native_hook_edge
    from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, reset_native_hook_route
    from scripts.native_benchmark_oracle import synthetic_payload, validate_semantic_response
    from scripts.native_slo_session import AdapterSession
    from scripts.native_slo_workloads import configuration_text

    report: dict[str, Any] = {
        "schema": "hol-guard.native-client-profile-collection.v2",
        "collection_complete": False,
        "qualification_complete": False,
        "production_selected": False,
        "headline_timing_eligible": False,
        "planned": 2 * count,
        "completed": 0,
        "failed": 0,
        "stage": "identity",
        "span_semantics": "inclusive_do_not_sum",
        "evaluation_isolated": False,
        "evaluation_scope": "resident_edge_snapshot_fence_evaluate_receipt_encode",
        "resource_comparison_measured": False,
        "normal_release_runtime_measured": False,
        "resident_capture_complete": False,
        "request_cases": ["claude_code_post_benign", "claude_code_post_credential_fixture"],
        "socket_count_scope": "helper_to_resident_successful_opens_failed_connects_incomplete",
    }
    completed: list[dict[str, Any]] = []
    try:
        runtime, identity = installed_identity(wheel, source_sha)
        report["identity"] = identity
        with Journal(private / "native-profiles.jsonl") as profiles, Journal(private / "attempts.jsonl") as attempts:
            with ClientObserver(runtime, profiles) as observer:
                report["stage"] = "fixture_start"
                with AdapterSession(runtime, configuration=configuration_text("normal")) as session:
                    require(session.daemon._server.hook_worker.test_oracle is None)
                    report["readiness_ms"] = session.readiness_ms
                    for case in ("benign", "secret"):
                        for sample in range(count):
                            entry: dict[str, Any] = {"case": case, "sample": sample, "status": "offered"}
                            attempts.append(entry)
                            try:
                                report["stage"] = "policy_readiness"
                                snapshot = session.daemon._server.hook_worker.prepare_workspace_policy(
                                    session.workspace, deadline=time.monotonic() + 0.4
                                )
                                require(snapshot is not None)
                                report["stage"] = "native_request"
                                before = len(observer.requests)
                                reset_native_hook_route()
                                edge = native_hook_edge.review_raw_hook_native(
                                    payload=synthetic_payload(sample, case=case),
                                    harness="claude-code",
                                    event="PostToolUse",
                                    guard_home=session.guard_home,
                                    home_dir=session.root,
                                    cwd=session.workspace,
                                    source_ref_external_allowed=False,
                                    observe_mode=False,
                                    deadline=time.monotonic() + 5,
                                    policy_snapshot=snapshot,
                                )
                                require(isinstance(edge, dict) and edge.get("authority") == "rust")
                                assert isinstance(edge, dict)
                                validate_semantic_response(
                                    edge.get("result"),
                                    route=native_hook_route(),
                                    expected_route="native_resident",
                                    case=case,
                                )
                                report["stage"] = "profile_match"
                                matched = observer.request_profile(before)
                                profile = matched["profile"]
                                require(not profile["overflow"] and profile["socket_count_complete"])
                                require(profile["helper_request_nanoseconds"] is not None)
                                require(
                                    all(
                                        0 < profile["phases"][p]["calls"] == profile["phases"][p]["succeeded"]
                                        for p in ("connect", "authentication", "request_write", "response_read")
                                    )
                                )
                                resident = observer.resident_profile(profile["request_sha256"])
                                require_evaluated(resident["resident_profile"])
                                completed.append(
                                    {"case": case, "profile": profile, "resident_profile": resident["resident_profile"]}
                                )
                                entry.update(
                                    status="completed",
                                    helper=matched["helper"],
                                    sequence=profile["sequence"],
                                    request_sha256=profile["request_sha256"],
                                    native_semantics_validated=True,
                                    route=native_hook_route(),
                                    edge_sha256=hashlib.sha256(
                                        json.dumps(edge, sort_keys=True, separators=(",", ":")).encode()
                                    ).hexdigest(),
                                    resident_process_id=resident["resident_profile"]["process_id"],
                                    resident_generation=resident["resident_profile"]["generation"],
                                    resident_sequence=resident["resident_profile"]["sequence"],
                                    resident_helper=resident["helper"],
                                )
                                report["completed"] += 1
                            except BaseException:
                                entry.update(status="failed", stage=report["stage"])
                                report["failed"] += 1
                                raise
                            finally:
                                attempts.append(entry)
                report["stage"] = "fixture_closed"
                cleanup = session.last_stop_diagnostic.get("status")
                report["cleanup_status"] = (
                    cleanup
                    if cleanup in {"contained", "already-stopped", "failed", "contained_client_cleanup_failed"}
                    else "unverified"
                )
                require(cleanup in {"contained", "already-stopped"})
            report["helpers"] = observer.spawns
            report["native_records"] = len(observer.records)
            report["resident_records"] = len(observer.resident_records)
            observer.validate_resident_capture()
            report["resident_capture_complete"] = True
            require(not observer.failure)
        _, after = installed_identity(wheel, source_sha)
        require(after == identity)
        report["collection_complete"] = len(completed) == 2 * count
        report["evaluation_isolated"] = report["collection_complete"]
        report["stage"] = "complete"
    except Exception:
        report["failure"] = "diagnostic_collection_incomplete"
    report["uncompleted"] = report["planned"] - report["completed"]
    report["profiles"] = summarize_profiles(completed)
    report["resident_profiles"] = summarize_resident_profiles(completed)
    return report


def run(*, wheel: Path, source_sha: str, private: Path, output: Path, count: int) -> dict[str, Any]:
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

    require(1 <= count <= 100)
    output.mkdir(parents=True, exist_ok=False)
    private.parent.mkdir(parents=True, exist_ok=True)
    _new_directory(private)
    plan = {
        "schema": "hol-guard.native-client-profile-plan.v1",
        "source_sha": source_sha,
        "count_per_case": count,
        "planned": 2 * count,
        "qualification_complete": False,
    }
    atomic_exclusive(private / "plan.json", json.dumps(plan, sort_keys=True).encode())
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    report: dict[str, Any] = {
        "schema": "hol-guard.native-client-profile-collection.v2",
        "collection_complete": False,
        "qualification_complete": False,
        "production_selected": False,
        "planned": 2 * count,
        "completed": None,
        "worker_summary_available": False,
        "stage": "worker_start",
    }
    try:
        result = run_isolated_hook_process(
            [
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--worker",
                "--wheel",
                str(wheel),
                "--source-sha",
                source_sha,
                "--private",
                str(private),
                "--output",
                str(output),
                "--count",
                str(count),
            ],
            input_text="",
            cwd=private.parent,
            environment=environment,
            timeout_seconds=180,
            output_limit=256 * 1024,
        )
        captures = {}
        for name, text in (("stdout", result.stdout), ("stderr", result.stderr)):
            encoded = text.encode("utf-8")
            captures[name] = {
                "scope": "decoded_utf8_reencoded_capture",
                "length": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "prefix_base64": base64.b64encode(encoded[: 256 * 1024]).decode("ascii"),
                "truncated": len(encoded) > 256 * 1024,
            }
        atomic_exclusive(private / "worker-capture.json", json.dumps(captures, sort_keys=True).encode())
        flags = {
            "worker_returncode": result.returncode,
            "worker_timed_out": result.timed_out,
            "worker_containment_failed": result.containment_failed,
            "worker_capture_limit": result.output_limit_exceeded,
        }
        report.update(flags)
        value = validate_report(json.loads(result.stdout), 2 * count, source_sha)
        report = {**value, **flags, "worker_summary_available": True}
        if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
            report["collection_complete"] = False
            report["evaluation_isolated"] = False
            report["resident_capture_complete"] = False
    except Exception:
        report["failure"] = "diagnostic_worker_incomplete"
    require(assert_privacy_safe(report) == report)
    write_public(output / "summary.json", report, limit=128 * 1024)
    atomic_exclusive(private / "summary.json", json.dumps(report, sort_keys=True).encode())
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, choices=range(1, 101), default=20)
    args = parser.parse_args()
    try:
        if args.worker:
            clear_proof_environment()
            report = worker(wheel=args.wheel, source_sha=args.source_sha, private=args.private, count=args.count)
        else:
            report = run(
                wheel=args.wheel.resolve(strict=True),
                source_sha=args.source_sha,
                private=args.private.resolve(),
                output=args.output.resolve(),
                count=args.count,
            )
    except Exception:
        # Fixed failure shape only; filesystem and environment errors may carry
        # private paths. Existing partial files remain for the always-run seal.
        report = {
            "schema": "hol-guard.native-client-profile-collection.v2",
            "collection_complete": False,
            "qualification_complete": False,
            "production_selected": False,
            "planned": 2 * args.count,
            "completed": None,
            "worker_summary_available": False,
            "stage": "preparation",
            "failure": "diagnostic_preparation_incomplete",
        }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["collection_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
