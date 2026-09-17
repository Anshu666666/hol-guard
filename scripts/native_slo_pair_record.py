"""Conserve both expected arms and exact numeric commitments for one pair."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Any, cast

from scripts.native_slo_adapter import route_matrix
from scripts.native_slo_evidence_files import atomic_exclusive, read_file
from scripts.native_slo_pair_io import (
    MANIFEST_LIMIT,
    REPORT_LIMIT,
    canonical,
    decode,
    digest_file,
    require,
    write_public,
)
from scripts.native_slo_qualification import confidence_summary, paired_order, sampling_plan
from scripts.native_slo_qualification_bundle import TARGETS
from scripts.native_slo_workload_identity import timing_series

PAIR_SCHEMA = "hol-guard.qualification-pair.v1"
NUMERIC_LIMIT = 4 * 1024 * 1024
CONTEXT_KEYS = {"build_sha", "target", "run_id", "run_attempt", "pair_index", "runs", "mode", "bundle_sha256"}


def validate_context(value: Mapping[str, Any]) -> None:
    require(set(value) == CONTEXT_KEYS, "pair_context_fields_invalid")
    require(
        isinstance(value["build_sha"], str) and re.fullmatch(r"[0-9a-f]{40}", value["build_sha"]) is not None,
        "pair_build_identity_invalid",
    )
    require(value["target"] in TARGETS, "pair_target_invalid")
    require(
        isinstance(value["bundle_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["bundle_sha256"]) is not None,
        "pair_bundle_identity_invalid",
    )
    for key in ("run_id", "run_attempt"):
        require(type(value[key]) is int and 1 <= value[key] < 2**63, "pair_execution_identity_invalid")
    require(value["mode"] in {"smoke", "qualification"}, "pair_mode_invalid")
    require(
        type(value["runs"]) is int and value["runs"] == (5 if value["mode"] == "qualification" else 1),
        "pair_run_count_invalid",
    )
    require(type(value["pair_index"]) is int and 0 <= value["pair_index"] < value["runs"], "pair_index_invalid")


def expected_counts(plan: Mapping[str, int]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in timing_series(route_matrix()):
        if key in {"NATIVE_CLIENT.policy_readiness", "DAEMON_PROCESS.startup"}:
            count = plan["recovery_per_run"] + 2
        elif key == "DAEMON_INGRESS.recovery":
            count = plan["recovery_per_run"]
        elif key == "NATIVE_CLIENT.cold_oneshot" or key.startswith("INSTALLED_LAUNCHER.cold."):
            count = plan["cold_per_run"]
        elif key.startswith("INSTALLED_LAUNCHER.c16."):
            count = math.ceil(plan["priority_per_run"] / 16) * 16
        elif key.startswith("INSTALLED_LAUNCHER.") or ".claude-code." in key or ".codex." in key:
            count = plan["priority_per_run"]
        else:
            count = plan["other_per_run"]
        result[key] = count
    return dict(sorted(result.items()))


def numeric_commitment(path: Path, report: Mapping[str, Any], plan: Mapping[str, int]) -> dict[str, object]:
    encoded = read_file(path, NUMERIC_LIMIT)
    raw = decode(encoded)
    expected = expected_counts(plan)
    require(set(raw) == set(expected), "pair_numeric_series_incomplete")
    summaries = report.get("measurements")
    require(isinstance(summaries, Mapping) and set(summaries) == set(expected), "pair_summary_series_incomplete")
    summaries = cast(Mapping[str, Any], summaries)
    for key, count in expected.items():
        values = raw[key]
        require(isinstance(values, list) and len(values) == count, "pair_numeric_count_mismatch")
        require(
            all(type(item) in {int, float} and math.isfinite(item) and item >= 0 for item in values),
            "pair_numeric_value_invalid",
        )
        require(confidence_summary(values) == summaries[key], "pair_numeric_summary_mismatch")
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded), "series_counts": expected}


def validate_runtime(report: Mapping[str, Any], expected: Mapping[str, Any], *, target: str) -> None:
    runtime = report.get("runtime")
    require(isinstance(runtime, Mapping), "pair_runtime_identity_missing")
    runtime = cast(Mapping[str, Any], runtime)
    require(
        runtime.get("target") == target
        and runtime.get("package_origin") == "installed"
        and runtime.get("mode") == "auto",
        "pair_installed_runtime_context_invalid",
    )
    for report_key, expected_key in (
        ("build_sha", "build_sha"),
        ("runtime_sha256", "runtime_sha256"),
        ("installed_package_sha256", "package_sha256"),
        ("package_version", "package_version"),
        ("python_version", "python_version"),
        ("dependency_versions_sha256", "dependency_versions_sha256"),
    ):
        require(runtime.get(report_key) == expected[expected_key], "pair_runtime_identity_mismatch")
    require(report.get("artifact_sha256") == expected["wheel_sha256"], "pair_wheel_identity_mismatch")
    hardware = report.get("hardware")
    require(isinstance(hardware, Mapping), "pair_runner_cohort_missing")
    hardware = cast(Mapping[str, Any], hardware)
    for field in ("runner_image", "runner_image_os"):
        value = hardware.get(field)
        require(
            isinstance(value, str)
            and value not in {"unavailable", "redacted", "truncated", "unknown"}
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value) is not None,
            "pair_runner_cohort_missing",
        )


class PairRecorder:
    def __init__(self, *, public: Path, private: Path, context: Mapping[str, Any], bundle: Mapping[str, Any]) -> None:
        validate_context(context)
        self.context = dict(context)
        self.bundle = bundle
        self.public, self.private = public, private
        self.plan = sampling_plan(runs=context["runs"], qualification=context["mode"] == "qualification")
        self.states: dict[str, dict[str, object]] = {
            arm: {"status": "unattempted"} for arm in ("baseline", "candidate")
        }
        self.offered: list[str] = []
        self.report: dict[str, object] | None = None

    def __enter__(self) -> PairRecorder:
        return self

    def offer(self, arm: str) -> None:
        order = paired_order(self.context["pair_index"])
        require(len(self.offered) < 2 and arm == order[len(self.offered)], "pair_offer_order_invalid")
        require(self.states[arm]["status"] == "unattempted", "pair_duplicate_offer")
        self.offered.append(arm)
        self.states[arm] = {"status": "in_progress"}
        write_public(
            self.public / f"{self.context['pair_index']:02d}-{arm}-offer.json",
            {
                "schema": "hol-guard.qualification-offer.v1",
                "context": self.context,
                "arm": arm,
                "ordinal": len(self.offered),
            },
            MANIFEST_LIMIT,
        )

    def failed(self, arm: str) -> None:
        require(self.states[arm]["status"] == "in_progress", "pair_failure_without_offer")
        path = self.public / f"{self.context['pair_index']:02d}-{arm}-failure.json"
        self.states[arm] = {"status": "failed", "failure_sha256": digest_file(path, REPORT_LIMIT)}

    def completed(self, arm: str, report: Mapping[str, Any], numeric: Path) -> None:
        require(self.states[arm]["status"] == "in_progress", "pair_completion_without_offer")
        validate_runtime(report, self.bundle["arms"][arm], target=self.bundle["target"])
        commitment = numeric_commitment(numeric, report, self.plan)
        path = self.public / f"{self.context['pair_index']:02d}-{arm}.json"
        self.states[arm] = {
            "status": "completed",
            "report_sha256": digest_file(path, REPORT_LIMIT),
            "numeric": commitment,
        }

    def __exit__(
        self, error_type: type[BaseException] | None, _error: BaseException | None, _tb: TracebackType | None
    ) -> None:
        for arm, state in tuple(self.states.items()):
            if state["status"] == "in_progress":
                self.states[arm] = {"status": "failed", "reason": "pair_controller_failed"}
        complete = error_type is None and all(state["status"] == "completed" for state in self.states.values())
        self.report = {
            "schema": PAIR_SCHEMA,
            "context": self.context,
            "plan": self.plan,
            "expected_order": list(paired_order(self.context["pair_index"])),
            "offered_order": self.offered,
            "arms": self.states,
            "collection_complete": complete,
            "sampling_passed": False,
            "qualification_complete": False,
            "program_qualification_complete": False,
            "comparison_available": False,
        }
        # Copy the exact public manifest into the encrypted recovery inventory.
        # This binds the raw files and interrupted journals to their offered pair.
        encoded = canonical(self.report) + b"\n"
        require(len(encoded) <= MANIFEST_LIMIT, "pair_manifest_bound")
        write_public(self.public / "pair-manifest.json", self.report, MANIFEST_LIMIT)
        atomic_exclusive(self.private / "pair-manifest.json", encoded)
