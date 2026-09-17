"""Strict public worker projection and descriptive, nonqualifying paired summaries."""

from __future__ import annotations

import math
import re
import statistics
from collections.abc import Mapping, Sequence
from typing import cast

from scripts.package_benchmark_corpus import Case, matrix, supplemental_cases
from scripts.package_benchmark_phases import validate_phases
from scripts.package_benchmark_registry import validate_registry

_HASH = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_FIELDS = (
    "case_id",
    "source",
    "fixture_sha256",
    "signed_response_sha256",
    "environment",
    "harness_sha256",
    "measurement",
)
_COMMON = {
    "schema",
    *IDENTITY_FIELDS,
    "status",
    "installed_artifact",
    "cpu_scope",
    "native_activation_authorized",
    "worker_address_space_limit",
    "worker_file_size_limit",
    "bundle_admission_verified_before_route",
    "semantic_sha256",
    "complete",
}
_OPTIONAL = {
    "packages",
    "evidence_rows",
    "decision",
    "evidence_sha256",
    "protect_sha256",
    "parser_version",
    "entry_sha256",
    "input_sha256",
    "input_bytes",
    "entries",
    "lookups",
    "matched",
    "wall_ms",
    "cpu_ms",
    "operation_counts",
    "phases",
    "registry_transport",
}
MISMATCH_FIELDS = frozenset(
    {
        "wrong_boundary",
        "decision",
        "packages_shape",
        "package_shape",
        "package_count",
        "package_names",
        "package_decision",
        "ecosystem",
        "namespace",
        "completeness",
        "resolved_version",
        "package_reasons",
        "complete_reasons",
        "unresolved_fallback",
        "unresolved_direct",
        "unresolved_route",
        "transitive_identity",
        "transitive_reason",
        "evidence_count",
        "evidence_id_binding",
        "evidence_classification",
        "evidence_request_binding",
        "evidence_action_binding",
        "evidence_details",
        "evidence_input_binding",
        "evidence_package_binding",
        "evidence_coverage",
        "kernel_boundary",
        "kernel_action",
        "kernel_state",
        "kernel_reason",
        "protect_unsupported",
        "protect_executed",
        "protect_exit",
        "intent_unsupported",
        "frozen_fixture",
        "signed_bundle_fixture",
        "source_import",
        "fixture_trust_anchor",
        "network_attempted",
        "source_changed",
        "parser_coverage",
        "source_identity_changed",
        "registry_calls",
        "registry_deadline",
        "registry_direct",
        "registry_selected_version",
    }
)


def preset(name: str) -> tuple[str, ...]:
    if name == "registry-resolved":
        return tuple(case.id for case in supplemental_cases())
    if name == "format-preflight":
        return tuple(
            case.id
            for case in matrix()
            if case.dependencies == case.bundle_size == 100 and case.mode == "exact" and case.route != "bundle_kernel"
        )
    if name == "cardinality":
        return tuple(
            case.id
            for case in matrix()
            if case.format == "npm"
            and (
                (case.route == "evaluator" and case.mode in {"absent", "exact", "deny"})
                or case.route == "bundle_kernel"
            )
        )
    if name == "unresolved":
        return (Case("npm", 100, 100, "unresolved", "evaluator").id,)
    if name == "hot-route":
        return (Case("npm", 1000, 1000, "exact", "protect_dry_run").id,)
    if name in {"phase-validation", "phase-attribution"}:
        return (
            Case("npm", 1000, 1000, "exact", "protect_dry_run").id,
            Case("npm", 10000, 10000, "exact", "evaluator").id,
        )
    raise ValueError("package_matrix_preset_invalid")


def preset_arms(name: str | None) -> tuple[str, ...]:
    return ("candidate",) if name in {"phase-validation", "phase-attribution"} else ("baseline", "candidate")


def validate_worker_report(value: object, offered: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - _COMMON - _OPTIONAL or not set(value) >= _COMMON:
        raise ValueError("package_matrix_worker_output_invalid")
    if any(value.get(key) != offered[key] for key in IDENTITY_FIELDS):
        raise ValueError("package_matrix_worker_identity_invalid")
    if (
        value["schema"] != "hol-guard.package-attempt.v2"
        or value["status"] != "completed"
        or value["complete"] is not True
        or value["installed_artifact"] is not False
        or value["native_activation_authorized"] is not False
        or value["cpu_scope"] != "self_plus_waited_children"
        or value["worker_address_space_limit"] != 4 * 1024**3
        or value["worker_file_size_limit"] != 64 * 1024**2
        or value["bundle_admission_verified_before_route"] is not True
    ):
        raise ValueError("package_matrix_worker_state_invalid")
    for key in ("semantic_sha256", "evidence_sha256", "protect_sha256", "entry_sha256", "input_sha256"):
        if key in value and (not isinstance(value[key], str) or not _HASH.fullmatch(value[key])):
            raise ValueError("package_matrix_worker_hash_invalid")
    for key in ("packages", "evidence_rows", "input_bytes", "entries", "lookups", "matched"):
        if key in value and (type(value[key]) is not int or not 0 <= value[key] <= 10**8):
            raise ValueError("package_matrix_worker_count_invalid")
    for key in ("wall_ms", "cpu_ms"):
        if value["measurement"] == "timing":
            number = value.get(key)
            if (
                not isinstance(number, (int, float))
                or isinstance(number, bool)
                or not math.isfinite(number)
                or number <= 0
            ):
                raise ValueError("package_matrix_worker_timing_invalid")
        elif key in value:
            raise ValueError("package_matrix_worker_unexpected_timing")
    if "parser_version" in value and value["parser_version"] not in {"complete-v1", "complete-v2"}:
        raise ValueError("package_matrix_worker_parser_invalid")
    if "decision" in value and value["decision"] != "block":
        raise ValueError("package_matrix_worker_decision_invalid")
    identifier = str(offered["case_id"])
    required = (
        {"lookups", "matched"}
        if identifier.startswith("bundle_kernel.")
        else {"packages", "evidence_rows", "decision", "evidence_sha256", "protect_sha256"}
    )
    if not identifier.startswith("bundle_kernel.") and not any(
        mode in identifier for mode in (".unresolved.", ".registry-resolved.")
    ):
        required |= {"parser_version", "entry_sha256", "input_sha256", "input_bytes", "entries"}
    if ".registry-resolved." in identifier:
        required.add("registry_transport")
        if value["measurement"] != "validation":
            raise ValueError("package_registry_validation_only")
        validate_registry(value.get("registry_transport"))
    elif "registry_transport" in value:
        raise ValueError("package_registry_unexpected")
    if value["measurement"] == "attribution":
        required.update(("operation_counts", "phases"))
    if "phases" in value:
        if value["measurement"] != "attribution":
            raise ValueError("package_matrix_worker_unexpected_phases")
        validate_phases(value["phases"])
    if not required <= set(value):
        raise ValueError("package_matrix_worker_coverage_invalid")
    if "operation_counts" in value:
        counts = value["operation_counts"]
        allowed = {
            "lockfile_parse_result.parse_lockfile_text",
            "lockfile_parse_result._validate_lockfile_structure",
            "lockfile_parse_result._validate_text_lockfile",
            "text_lockfile_parse.parse_text_lockfile",
            "workspace_path_guard.read_bytes_within_workspace",
            "workspace_path_guard.read_text_within_workspace",
            "store_evidence_facade.add_evidence",
            "store_evidence_facade.add_evidence_batch",
        }
        if (
            value["measurement"] != "attribution"
            or not isinstance(counts, dict)
            or set(counts) - allowed
            or any(type(count) is not int or count < 0 for count in counts.values())
        ):
            raise ValueError("package_matrix_worker_counts_invalid")
    return value


def descriptive_summary(comparisons: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Never pool different cases or call five observations a tail distribution."""
    groups: dict[str, list[Mapping[str, object]]] = {}
    for row in comparisons:
        groups.setdefault(str(row["case_id"]), []).append(row)
    output: list[dict[str, object]] = []
    for identifier, rows in sorted(groups.items()):
        entry: dict[str, object] = {
            "case_id": identifier,
            "offered_pairs": len(rows),
            "comparable_pairs": sum(row.get("comparable") is True for row in rows),
            "tail_qualified": False,
            "native_benefit_proven": False,
        }
        # All observations must survive; no favorable subset statistic.
        if all(row.get("comparable") is True and "wall_reduction" in row and "cpu_reduction" in row for row in rows):
            for metric in ("wall", "cpu"):
                values = [float(cast("float", row[f"{metric}_reduction"])) for row in rows]
                entry[f"{metric}_reduction"] = {
                    "median": statistics.median(values),
                    "min": min(values),
                    "max": max(values),
                    "samples": len(values),
                }
        output.append(entry)
    return output
