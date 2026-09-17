"""One installed-artifact block in a paired performance experiment."""

from __future__ import annotations

import json
import math
import os
import platform
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.daemon.hook_process_capacity import effective_cpu_count, physical_memory_bytes
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from scripts.bench_guard_native_installed_slo import _run_cold, _run_recovery
from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary
from scripts.native_slo_adapter import route_matrix
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_corpus_run import run_contract_corpus
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_evidence_files import atomic_exclusive
from scripts.native_slo_launcher_corpus import run_registered_contract_corpus
from scripts.native_slo_load_profiles import measure_load_profiles
from scripts.native_slo_numeric_journal import NumericJournal
from scripts.native_slo_priority_launchers import LauncherSession, measure_priority_launchers
from scripts.native_slo_qualification import confidence_summary
from scripts.native_slo_qualification_scenarios import run_additional_scenarios, validate_receipt_profile
from scripts.native_slo_resources import ResourceSampler
from scripts.native_slo_workload_identity import common_workload_digest, semantic_scope_digest

_PLATFORMS = ("linux-x64", "macos-x64", "macos-arm64", "windows-x64")
_REQUIRED_CASES = (
    "allow",
    "block",
    "review",
    "watch",
    "unavailable",
    "malformed",
    "expired_policy",
    "integrity_failure",
    "empty",
    "output_reference",
    "oversized",
)


def platform_label() -> str:
    system = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "unsupported")
    architecture = {"x86_64": "x64", "AMD64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine(), "unsupported"
    )
    return f"{system}-{architecture}"


def hardware_summary() -> dict[str, object]:
    cpu = platform.processor()
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    cpu = line.partition(":")[2].strip()
                    break
        except OSError:
            pass
    try:
        load = list(os.getloadavg())
    except (AttributeError, OSError):
        load = None
    return {
        "platform": platform_label(),
        "cpu_model": re.sub(r"[^A-Za-z0-9_.:-]", "_", cpu)[:96] or "unknown",
        "cpu_count": os.cpu_count(),
        "effective_cpu_count": effective_cpu_count(),
        "ram_bytes": physical_memory_bytes(),
        "os_release": re.sub(r"[^A-Za-z0-9_.:-]", "_", platform.release())[:96],
        "load_average": load,
        "power_mode": "unrecorded",
        "rust_toolchain": "record_in_build_artifact",
        "build_flags": "record_in_build_artifact",
    }


def workload_matrix(
    routes: tuple[tuple[str, str], ...],
    corpus: Mapping[str, object],
    launcher_corpus: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Declare coverage and remaining obligations without inferring missing routes."""
    platform_scope = corpus.get("platform_scope", {})
    source_supported = isinstance(platform_scope, Mapping) and platform_scope.get("reference_review_supported") is True
    source_qualified = isinstance(platform_scope, Mapping) and platform_scope.get("reference_review_qualified") is True
    missing_source = (
        []
        if source_supported and source_qualified
        else ["source_reference_full_content_review", "source_reference_identity_verification"]
    )
    return {
        "required_platforms": list(_PLATFORMS),
        "observed_platform": platform_label(),
        "required_sizes": ["1k", "16k", "256k", "1m", "maximum_supported"],
        "required_cases": list(_REQUIRED_CASES),
        "concurrency": [1, 4, 16, 64],
        "daemon_routes": [f"{harness}.{event}" for harness, event in routes],
        "daemon_coverage": corpus["coverage"],
        "daemon_platform_scope": platform_scope,
        "daemon_semantic_coverage": platform_scope.get("semantic_coverage", {})
        if isinstance(platform_scope, Mapping)
        else {},
        "reference_review_supported": source_supported,
        "reference_review_qualified": source_supported and source_qualified,
        "missing_reference_scopes": missing_source,
        "platform_denial_timing_eligible": False,
        "declared_cases": corpus["declared_cases"],
        "validated_cases": corpus["validated_cases"],
        "launcher_routes": [
            f"{harness}.{event}" for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
        ],
        "launcher_contract_coverage": launcher_corpus.get("coverage", {}) if launcher_corpus else {},
        "launcher_contract_validated_cases": launcher_corpus.get("validated_cases", 0) if launcher_corpus else 0,
        "remaining_setups": corpus["remaining_setups"],
        "daemon_contract_complete": corpus["complete"] is True and not missing_source,
        "complete": False,
    }


def _native_sample_values(measured: Mapping[str, object], expected: int) -> list[float]:
    values = measured.get("values")
    if (
        measured.get("benign_and_block_validated") is not True
        or not isinstance(values, list)
        or len(values) != expected
        or not 1 <= expected <= 100
        or any(
            not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0
            for value in values
        )
    ):
        raise RuntimeError("native sample preflight or bounded values were not validated")
    return [float(value) for value in values]


def run_block(*, plan: Mapping[str, int], raw_file: Path, receipt_profile: str = "candidate") -> dict[str, object]:
    """Measure one block using this interpreter's installed default native wheel."""
    with NumericJournal(raw_file.with_name(raw_file.stem + "-numeric.jsonl")) as journal:
        return _run_block(plan=plan, raw_file=raw_file, receipt_profile=receipt_profile, journal=journal)


def _run_block(
    *, plan: Mapping[str, int], raw_file: Path, receipt_profile: str, journal: NumericJournal
) -> dict[str, object]:
    _clear_proof_overrides()
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("qualification native runtime unavailable")
    runtime = status.identity.path
    identity = _runtime_summary(runtime)
    validate_receipt_profile(receipt_profile, identity)
    routes = route_matrix()
    contract_corpus = run_contract_corpus(
        runtime, evidence_file=raw_file.with_name(raw_file.stem + "-daemon-contract.jsonl")
    )
    launcher_corpus = run_registered_contract_corpus(
        runtime, evidence_file=raw_file.with_name(raw_file.stem + "-launcher-contract.jsonl")
    )
    raw: dict[str, list[float]] = {}
    with DaemonFixture(runtime, policy="normal") as session:
        startup_ms = session.startup_ms
        journal.record("DAEMON_PROCESS.startup", [startup_ms])
        journal.record("NATIVE_CLIENT.policy_readiness", [session.readiness_ms])
        for harness, event in routes:
            observation = session.observe(harness, event, "1k")
            if not observation.allowed or observation.route != "native_resident":
                raise RuntimeError("qualification warmup changed semantic route")
        attempts = 0
        with ResourceSampler(pid=session.pid, cpu_reader=session.cpu_accounting_reader()) as resources:
            for harness, event in routes:
                count = plan["priority_per_run"] if harness in {"claude-code", "codex"} else plan["other_per_run"]
                values: list[float] = []
                name = f"DAEMON_INGRESS.{harness}.{event}"
                with journal.batch(name, count) as batch:
                    for _ in range(count):
                        observation = session.observe(harness, event, "1k")
                        attempts += 1
                        batch.record([observation.latency_ms])
                        if not observation.allowed or observation.route != "native_resident":
                            raise RuntimeError("qualification warm sample changed semantic route")
                        values.append(observation.latency_ms)
                raw[name] = values
            # Ensure a small smoke run still records its requested resource count.
            resource_deadline = time.monotonic() + 10.0
            while resources.samples < plan["resource_samples_per_run"] and time.monotonic() < resource_deadline:
                time.sleep(0.05)
        resource_report = resources.report(attempted=attempts)
        resource_report["boundary"] = "DAEMON_INGRESS"
        direct_samples: list[float] = []
        while len(direct_samples) < plan["priority_per_run"]:
            count = min(100, plan["priority_per_run"] - len(direct_samples))
            with journal.batch("NATIVE_CLIENT.claude-code.PostToolUse", count) as batch:
                measured = session.control("native_samples", count=count)
                numbers = _native_sample_values(measured, count)
                batch.record(numbers)
                direct_samples.extend(numbers)
        raw["NATIVE_CLIENT.claude-code.PostToolUse"] = direct_samples
        launcher, launcher_series = measure_priority_launchers(
            cast(LauncherSession, cast(object, session)), plan, journal=journal
        )
        raw.update(launcher_series)
        concurrent, offered, capacity_resources = measure_load_profiles(session, routes)
        native_readiness_ms = session.readiness_ms
    with DaemonFixture(runtime, policy="normal") as cold_session:
        journal.record("DAEMON_PROCESS.startup", [cold_session.startup_ms])
        journal.record("NATIVE_CLIENT.policy_readiness", [cold_session.readiness_ms])
        cold = _run_cold(runtime, cold_session, plan["cold_per_run"], journal=journal)
    recovery: list[float] = []
    readiness = [native_readiness_ms, cold_session.readiness_ms]
    startups = [startup_ms, cold_session.startup_ms]
    # Independent fixtures keep repeated fault trials separate from the resident's
    # production restart-circuit window. Never reset production circuit state.
    for _ in range(plan["recovery_per_run"]):
        with DaemonFixture(runtime, policy="normal") as recovery_session:
            journal.record("DAEMON_PROCESS.startup", [recovery_session.startup_ms])
            journal.record("NATIVE_CLIENT.policy_readiness", [recovery_session.readiness_ms])
            recovery.extend(_run_recovery(recovery_session, 1, journal=journal))
            readiness.append(recovery_session.readiness_ms)
            startups.append(recovery_session.startup_ms)
    raw["NATIVE_CLIENT.cold_oneshot"] = cold
    raw["DAEMON_INGRESS.recovery"] = recovery
    raw["NATIVE_CLIENT.policy_readiness"] = readiness
    raw["DAEMON_PROCESS.startup"] = startups
    journal.finish(raw)
    atomic_exclusive(raw_file, (json.dumps(raw, separators=(",", ":")) + "\n").encode("utf-8"))
    additional = run_additional_scenarios(
        runtime,
        raw_file=raw_file,
        receipt_profile=receipt_profile,
        runtime_identity=identity,
        phase_count=min(100, plan["priority_per_run"]),
    )
    matrix = workload_matrix(routes, contract_corpus, launcher_corpus)
    workload_digest = common_workload_digest(
        routes=routes,
        plan=plan,
        manifest_digest=cast(str, contract_corpus["manifest_digest"]),
        oracle_digest=cast(str, contract_corpus["oracle_digest"]),
    )
    return assert_privacy_safe(
        {
            "schema": "hol-guard.native-qualification-block.v1",
            "runtime": identity,
            "hardware": hardware_summary(),
            # Retain the field name for consumers, with explicit new semantics.
            "corpus_digest": workload_digest,
            "common_workload_digest": workload_digest,
            "semantic_scope_digest": semantic_scope_digest(matrix, contract_corpus, launcher_corpus),
            "matrix": matrix,
            "contract_corpus": contract_corpus,
            "registered_launcher_contract_corpus": launcher_corpus,
            "additional_scenarios": additional,
            "measurements": {key: confidence_summary(values) for key, values in raw.items()},
            "daemon_process_start_to_policy_ready_ms": startup_ms,
            "native_readiness_ms": native_readiness_ms,
            "launcher": launcher,
            "resources": resource_report,
            "capacity_resources": capacity_resources,
            "closed_loop": concurrent,
            "offered_load": offered,
            "phases": additional["python_phases"],
            "qualification_complete": False,
            "remaining": [
                "nonpriority_registered_launchers",
                "browser_approval_continuation",
                "malformed_launcher_input",
                "native_phase_attribution",
                "all_platforms",
                *cast(list[str], matrix["missing_reference_scopes"]),
            ],
        }
    )
