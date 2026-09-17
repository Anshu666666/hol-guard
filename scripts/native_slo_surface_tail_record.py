"""Exact offer, numeric and workload commitments for one companion pair."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from scripts.native_slo_evidence_files import atomic_exclusive, read_file
from scripts.native_slo_pair_io import MANIFEST_LIMIT, canonical, decode, digest_file, require, write_public
from scripts.native_slo_pair_record import validate_context, validate_runtime
from scripts.native_slo_qualification import confidence_summary, paired_order
from scripts.native_slo_surface_tail_contract import NUMERIC_LIMIT, SCHEMA, TailRoute, plan, workload

_REPORT_FIELDS = frozenset(
    {
        "schema",
        "route",
        "boundary",
        "sample_class",
        "result_profile",
        "native_decision",
        "native_policy_action",
        "mode",
        "plan",
        "common_workload_digest",
        "measurements",
        "preflight_cases",
        "validated_cases",
        "errors",
        "native_route",
        "case_id",
        "delivery",
        "model_action",
        "exit_code",
        "size_class",
        "registration_sha256",
        "registration_artifacts",
        "matchers_read_back",
        "matched_tool",
        "process_startup_included",
        "stdout_exit_checked",
        "full_host_activation",
        "resident_cold_measured",
        "concurrency",
        "qualification_complete",
        "program_qualification_complete",
        "runtime",
        "hardware",
        "artifact_sha256",
    }
)
_RUNTIME_FIELDS = frozenset(
    {
        "mode",
        "target",
        "runtime_version",
        "protocol_version",
        "package_origin",
        "package_version",
        "package_record_sha256",
        "installed_package_sha256",
        "python_version",
        "architecture",
        "system",
        "runtime_sha256",
        "rule_digest",
        "build_sha",
        "reference_reader_capability",
        "dependency_versions_sha256",
    }
)
_HARDWARE_FIELDS = frozenset(
    {
        "platform",
        "cpu_model",
        "cpu_count",
        "effective_cpu_count",
        "ram_bytes",
        "os_release",
        "load_average",
        "power_mode",
        "rust_toolchain",
        "build_flags",
        "runner_image",
        "runner_image_os",
    }
)


def _finite(value: object) -> bool:
    return isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def _label(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", value) is not None


def _identity_leaves(runtime: Mapping[str, Any], hardware: Mapping[str, Any]) -> None:
    for key in _RUNTIME_FIELDS - {"protocol_version"}:
        require(_label(runtime[key]), "surface_tail_runtime_leaf_invalid")
    require(
        type(runtime["protocol_version"]) is int and 0 < runtime["protocol_version"] < 100,
        "surface_tail_runtime_protocol_invalid",
    )
    for key in ("package_record_sha256", "rule_digest"):
        require(re.fullmatch(r"[0-9a-f]{64}", runtime[key]) is not None, "surface_tail_runtime_digest_invalid")
    require(
        runtime["architecture"] in {"AMD64", "x86_64", "arm64", "aarch64"}
        and runtime["system"] in {"Linux", "Darwin", "Windows"}
        and runtime["reference_reader_capability"] in {"absent", "native-source-handle-read-v1"},
        "surface_tail_runtime_platform_invalid",
    )
    require(
        re.fullmatch(r"[0-9][0-9A-Za-z_.+-]{0,95}", runtime["runtime_version"]) is not None,
        "surface_tail_runtime_version_invalid",
    )
    for key in ("cpu_count", "effective_cpu_count", "ram_bytes"):
        require(type(hardware[key]) is int and 0 < hardware[key] < 2**63, "surface_tail_hardware_count_invalid")
    for key in _HARDWARE_FIELDS - {"cpu_count", "effective_cpu_count", "ram_bytes", "load_average"}:
        require(_label(hardware[key]), "surface_tail_hardware_leaf_invalid")
    require(
        hardware["platform"] in {"linux-x64", "macos-x64", "macos-arm64", "windows-x64"}
        and hardware["power_mode"] == "unrecorded"
        and hardware["rust_toolchain"] == hardware["build_flags"] == "record_in_build_artifact",
        "surface_tail_hardware_profile_invalid",
    )
    load = hardware["load_average"]
    require(
        load is None or (isinstance(load, list) and len(load) == 3 and all(_finite(value) for value in load)),
        "surface_tail_hardware_load_invalid",
    )


def check_report(
    report: Mapping[str, Any], *, route: TailRoute, mode: str, bundle: Mapping[str, Any], arm: str
) -> None:
    require(
        set(report) == _REPORT_FIELDS
        and isinstance(report.get("runtime"), dict)
        and set(report["runtime"]) == _RUNTIME_FIELDS
        and isinstance(report.get("hardware"), dict)
        and set(report["hardware"]) == _HARDWARE_FIELDS,
        "surface_tail_report_fields_invalid",
    )
    _identity_leaves(report["runtime"], report["hardware"])
    require(report.get("schema") == "hol-guard.nonpriority-tail-block.v1", "surface_tail_report_schema")
    for key, value in workload(route, mode).items():
        require(report.get(key) == value, "surface_tail_workload_mismatch")
    require(
        report.get("boundary") == "INSTALLED_LAUNCHER" and report.get("mode") == mode, "surface_tail_boundary_mismatch"
    )
    require(
        report.get("preflight_cases") == route.preflight_count
        and type(report.get("preflight_cases")) is int
        and type(report.get("validated_cases")) is int
        and type(report.get("concurrency")) is int
        and report.get("validated_cases") == route.preflight_count + plan(mode)["samples_per_arm"]
        and type(report.get("errors")) is int
        and report["errors"] == 0,
        "surface_tail_semantic_conservation",
    )
    require(
        report.get("native_route") == "native_resident"
        and report.get("process_startup_included") is True
        and report.get("stdout_exit_checked") is True
        and report.get("full_host_activation") is False
        and report.get("resident_cold_measured") is False
        and report.get("qualification_complete") is False
        and report.get("program_qualification_complete") is False,
        "surface_tail_scope_invalid",
    )
    validate_runtime(report, bundle["arms"][arm], target=bundle["target"])
    measurements = report.get("measurements")
    require(isinstance(measurements, dict) and set(measurements) == {route.series}, "surface_tail_series_mismatch")
    summary = cast(dict[str, Any], measurements)[route.series]
    require(
        isinstance(summary, dict)
        and set(summary)
        == {"count", "p50_ms", "p95_ms", "p99_ms", "max_ms", "p95_ci95_ms", "p99_ci95_ms", "interval_method"},
        "surface_tail_summary_fields_invalid",
    )
    require(
        isinstance(summary, dict)
        and type(summary.get("count")) is int
        and summary["count"] == plan(mode)["samples_per_arm"],
        "surface_tail_count_mismatch",
    )
    for field in ("p50_ms", "p95_ms", "p99_ms", "max_ms"):
        value: Any = summary.get(field)
        require(type(value) in {float, int} and math.isfinite(value) and value >= 0, "surface_tail_summary_invalid")
    require(
        summary["interval_method"] == "empirical_percentile_bootstrap_nearest_rank_2000",
        "surface_tail_interval_method_invalid",
    )
    for field in ("p95_ci95_ms", "p99_ci95_ms"):
        interval = summary[field]
        require(
            isinstance(interval, list)
            and len(interval) == 2
            and all(_finite(value) for value in interval)
            and interval[0] <= interval[1],
            "surface_tail_interval_invalid",
        )
    require(
        report["delivery"] in {"allow", "ask", "deny", "observation_only"}
        and report["model_action"] in {"not_applicable", "allow_original", "unreviewed_original", "block"}
        and type(report["exit_code"]) is int
        and report["exit_code"] in {0, 2}
        and type(report["matchers_read_back"]) is int
        and report["matchers_read_back"] in {0, 18}
        and report["matched_tool"] in {"Bash", "event_slot"},
        "surface_tail_semantic_fields_invalid",
    )
    registration = report["registration_sha256"]
    require(
        isinstance(registration, str) and len(registration) == 64 and set(registration) <= set("0123456789abcdef"),
        "surface_tail_registration_digest_invalid",
    )
    artifacts = report["registration_artifacts"]
    require(
        isinstance(artifacts, dict)
        and set(artifacts) <= {"cursor_worker", "paths", "workers"}
        and all(
            isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef")
            for value in artifacts.values()
        ),
        "surface_tail_registration_artifacts_invalid",
    )


def numeric_commitment(path: Path, report: Mapping[str, Any], route: TailRoute, mode: str) -> dict[str, object]:
    encoded = read_file(path, NUMERIC_LIMIT, private=True)
    raw = decode(encoded)
    require(set(raw) == {route.series}, "surface_tail_numeric_series")
    values = raw[route.series]
    require(
        isinstance(values, list)
        and len(values) == plan(mode)["samples_per_arm"]
        and all(type(value) in {float, int} and math.isfinite(value) and value >= 0 for value in values),
        "surface_tail_numeric_count",
    )
    require(report["measurements"][route.series] == confidence_summary(values), "surface_tail_numeric_summary")
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "series_counts": {route.series: len(values)},
    }


class TailRecorder:
    def __init__(self, *, root: Path, context: dict[str, Any], route: TailRoute, bundle: dict[str, Any]) -> None:
        validate_context(context)
        self.root, self.context, self.route, self.bundle = root, context, route, bundle
        self.public, self.private = root / "aggregate", root / "private_samples"
        self.offered: list[str] = []
        self.states: dict[str, dict[str, object]] = {
            arm: {"status": "unattempted"} for arm in ("baseline", "candidate")
        }
        self.report: dict[str, Any] | None = None

    def offer(self, arm: str) -> None:
        order = paired_order(self.context["pair_index"])
        require(len(self.offered) < 2 and arm == order[len(self.offered)], "surface_tail_order_invalid")
        write_public(
            self.public / f"{self.context['pair_index']:02d}-{arm}-offer.json",
            {
                "schema": "hol-guard.nonpriority-tail-offer.v1",
                "context": self.context,
                "workload": workload(self.route, self.context["mode"]),
                "arm": arm,
                "ordinal": len(self.offered) + 1,
            },
            MANIFEST_LIMIT,
        )
        self.offered.append(arm)
        self.states[arm] = {"status": "failed", "reason": "pair_controller_interrupted"}

    def failed(self, arm: str) -> None:
        require(
            arm in self.offered and self.states[arm] == {"status": "failed", "reason": "pair_controller_interrupted"},
            "surface_tail_failure_without_offer",
        )
        self.states[arm] = {
            "status": "failed",
            "failure_sha256": digest_file(
                self.public / f"{self.context['pair_index']:02d}-{arm}-failure.json", 256 * 1024
            ),
        }

    def completed(self, arm: str, report: dict[str, Any], raw_file: Path) -> None:
        require(
            arm in self.offered and self.states[arm] == {"status": "failed", "reason": "pair_controller_interrupted"},
            "surface_tail_completion_without_offer",
        )
        check_report(report, route=self.route, mode=self.context["mode"], bundle=self.bundle, arm=arm)
        numeric = numeric_commitment(raw_file, report, self.route, self.context["mode"])
        write_public(self.public / f"{self.context['pair_index']:02d}-{arm}.json", report)
        self.states[arm] = {
            "status": "completed",
            "numeric": numeric,
            "report_sha256": hashlib.sha256(canonical(report) + b"\n").hexdigest(),
        }

    def finish(self) -> dict[str, Any]:
        self.report = {
            "schema": SCHEMA,
            "context": self.context,
            "workload": workload(self.route, self.context["mode"]),
            "expected_order": list(paired_order(self.context["pair_index"])),
            "offered_order": self.offered,
            "arms": self.states,
            "collection_complete": all(state["status"] == "completed" for state in self.states.values()),
            "qualification_complete": False,
            "program_qualification_complete": False,
        }
        write_public(self.public / "pair-manifest.json", self.report, MANIFEST_LIMIT)
        atomic_exclusive(self.private / "pair-manifest.json", canonical(self.report) + b"\n")
        return self.report
