"""Closed public projection of the separately instrumented client experiment."""

from __future__ import annotations

import math
import re
from typing import Any

from scripts.native_client_profile_records import PHASES, count, require
from scripts.native_slo_contract import assert_privacy_safe

STAGES = {
    "identity",
    "fixture_start",
    "policy_readiness",
    "native_request",
    "profile_match",
    "fixture_closed",
    "complete",
}
FIXED = {
    "schema": "hol-guard.native-client-profile-collection.v1",
    "qualification_complete": False,
    "production_selected": False,
    "headline_timing_eligible": False,
    "span_semantics": "inclusive_do_not_sum",
    "evaluation_isolated": False,
    "resource_comparison_measured": False,
    "normal_release_runtime_measured": False,
    "request_cases": ["claude_code_post_benign", "claude_code_post_credential_fixture"],
    "socket_count_scope": "helper_to_resident_successful_opens_failed_connects_incomplete",
}
IDENTITY_HASHES = {
    "wheel_sha256",
    "runtime_sha256",
    "rule_digest",
    "installed_package_sha256",
    "collector_sha256",
    "observer_sha256",
    "records_sha256",
    "report_sha256",
    "lock_sha256",
}


def validate_report(value: Any, planned: int, source_sha: str) -> dict[str, Any]:
    require(isinstance(value, dict))
    mandatory = set(FIXED) | {
        "collection_complete",
        "planned",
        "completed",
        "failed",
        "stage",
        "uncompleted",
        "profiles",
    }
    require(
        mandatory
        <= set(value)
        <= mandatory | {"identity", "readiness_ms", "helpers", "native_records", "failure", "cleanup_status"}
    )
    require(all(type(value[key]) is type(expected) and value[key] == expected for key, expected in FIXED.items()))
    require(count(value["planned"], 200) == planned)
    completed, failed = count(value["completed"], planned), count(value["failed"], 1)
    require(count(value["uncompleted"], planned) == planned - completed and completed + failed <= planned)
    require(type(value["collection_complete"]) is bool and value["stage"] in STAGES)
    if "failure" in value:
        require(value["failure"] == "diagnostic_collection_incomplete" and not value["collection_complete"])
    if "identity" in value:
        identity = value["identity"]
        require(
            isinstance(identity, dict)
            and set(identity) == IDENTITY_HASHES | {"build_sha", "target", "artifact_scope", "production_selected"}
        )
        require(identity["build_sha"] == source_sha and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None)
        require(
            all(
                isinstance(identity[key], str) and re.fullmatch(r"[0-9a-f]{64}", identity[key]) is not None
                for key in IDENTITY_HASHES
            )
        )
        require(identity["target"] in {"x86_64-linux", "x86_64-macos", "aarch64-macos", "x86_64-windows"})
        require(
            identity["artifact_scope"] == "explicit_diagnostic_feature_wheel"
            and identity["production_selected"] is False
        )
    if "cleanup_status" in value:
        require(
            value["cleanup_status"]
            in {"contained", "already-stopped", "failed", "contained_client_cleanup_failed", "unverified"}
        )
    if "readiness_ms" in value:
        _number(value["readiness_ms"])
    for key in ("helpers", "native_records"):
        if key in value:
            count(value[key], 32 if key == "helpers" else 1024)
    profiles = value["profiles"]
    require(isinstance(profiles, dict) and set(profiles) == {"benign", "credential_fixture"})
    total = 0
    for case in profiles.values():
        require(
            isinstance(case, dict) and set(case) == {"count", "socket_opened", "socket_accounting_complete", "phases"}
        )
        n = count(case["count"], planned // 2)
        total += n
        count(case["socket_opened"])
        require(case["socket_accounting_complete"] is bool(n))
        require(isinstance(case["phases"], dict) and set(case["phases"]) == set(PHASES))
        for span in case["phases"].values():
            require(isinstance(span, dict) and set(span) == {"calls", "succeeded", "duration_ms"})
            calls, succeeded = count(span["calls"]), count(span["succeeded"])
            require(succeeded <= calls)
            statistics = span["duration_ms"]
            require((statistics is None) == (calls == 0))
            if statistics is not None:
                require(
                    isinstance(statistics, dict)
                    and set(statistics) == {"count", "p50_ms", "p95_ms", "p99_ms", "max_ms"}
                )
                require(0 < count(statistics["count"], n) <= calls)
                for key in ("p50_ms", "p95_ms", "p99_ms", "max_ms"):
                    _number(statistics[key])
    require(total == completed)
    if value["collection_complete"]:
        require(completed == planned and failed == 0 and value["stage"] == "complete")
        require({"identity", "readiness_ms", "helpers", "native_records"} <= set(value))
        require(value.get("cleanup_status") in {"contained", "already-stopped"})
        require(value["helpers"] > 0 and value["native_records"] >= completed)
    require(assert_privacy_safe(value) == value)
    return value


def _number(value: Any) -> None:
    require(type(value) in {int, float} and math.isfinite(value) and value >= 0)
