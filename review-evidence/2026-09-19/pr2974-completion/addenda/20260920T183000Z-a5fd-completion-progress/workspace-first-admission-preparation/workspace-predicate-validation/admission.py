"""Reconstruct original lifecycle evidence before separate five-cell admission."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, cast

SCENARIOS = ("lost_metadata_hint", "first_admission_fault", "first_admission_fault", "expiry_fault", "service_restart")
MAX_LEDGER = 2 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def decode(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def invalid(_value: str) -> None:
        raise ValueError("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


class MemoryLedger:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def write(self, row: dict[str, Any]) -> None:
        require(len(self.rows) < 128, "cell_part_bound")
        self.rows.append(row)


def reconstruct(report: dict[str, Any], raw: bytes) -> list[dict[str, Any]]:
    from scripts.native_slo_workspace_lifecycle_evidence import retain_cell

    require(0 < len(raw) <= MAX_LEDGER and raw.endswith(b"\n"), "ledger_bound_or_tail")
    lines = raw.splitlines(keepends=True)
    require(all(len(line) <= 8192 for line in lines), "ledger_record_bound")
    require(
        report["ledger"] == {"bytes": len(raw), "records": len(lines), "sha256": hashlib.sha256(raw).hexdigest()},
        "ledger_identity",
    )
    rows = [decode(line) for line in lines]
    cells = report["cells"]
    require(type(cells) is list and len(cells) <= 5, "cell_count")
    cells = cast(list[dict[str, Any]], cells)
    cursor, restored = 0, []
    for summary in cells:
        require(type(summary) is dict, "summary_shape")
        summary = cast(dict[str, Any], summary)
        expected_offer = {
            "kind": "lifecycle_cell_offer",
            "scenario": summary["scenario"],
            "registered_workspaces": summary["registered_workspaces"],
        }
        require(cursor < len(rows) and rows[cursor] == expected_offer, "offer_join")
        cursor += 1
        reference = summary["evidence"]
        parts = reference["parts"]
        require(type(parts) is int and 1 <= parts <= 128 and cursor + parts <= len(rows), "part_count")
        group = rows[cursor : cursor + parts]
        cursor += parts
        content: list[str] = []
        for index, row in enumerate(group):
            require(
                type(row) is dict and set(row) == {"kind", "part", "parts", "result_sha256", "content"}, "part_shape"
            )
            row = cast(dict[str, Any], row)
            require(
                row["kind"] == "lifecycle_cell_terminal_part"
                and type(row["part"]) is int
                and row["part"] == index
                and type(row["parts"]) is int
                and row["parts"] == parts
                and row["result_sha256"] == reference["sha256"]
                and type(row["content"]) is str
                and len(row["content"]) <= 2048,
                "part_identity",
            )
            content.append(row["content"])
        encoded = "".join(content).encode("ascii")
        require(0 < len(encoded) <= 256 * 1024, "cell_bound")
        require(
            len(encoded) == reference["bytes"] and hashlib.sha256(encoded).hexdigest() == reference["sha256"],
            "cell_digest",
        )
        envelope = decode(encoded)
        require(type(envelope) is dict and set(envelope) == {"schema", "summary", "proof"}, "cell_envelope")
        require(envelope["schema"] == "hol-guard.workspace-lifecycle-evidence.v1", "cell_schema")
        require(
            envelope["summary"] == {key: value for key, value in summary.items() if key != "evidence"},
            "cell_summary_join",
        )
        proof = envelope["proof"]
        require(type(proof) is dict and not set(proof).intersection(envelope["summary"]), "proof_partition")
        cell = {**envelope["summary"], **proof}
        # Reapply the original complete schema, receipt, authority, request join,
        # publication digest and phase-chain checks, preserving exact bytes.
        replay = MemoryLedger()
        require(retain_cell(replay, cell) == summary and replay.rows == group, "producer_schema_roundtrip")
        restored.append(cell)
    require(cursor == len(rows), "unexpected_ledger_tail")
    return restored


def admit(
    report: dict[str, Any], cells: list[dict[str, Any]], *, returncode: int, runtime: dict[str, Any]
) -> dict[str, Any]:
    require(returncode == 1, "original_subset_exit")
    require(report.get("schema") == "hol-guard.native-workspace-lifecycle.v1", "report_schema")
    require(report.get("counts") == [100] and report.get("scenarios") == list(SCENARIOS), "declared_roster")
    require(report.get("declared_cells_visited") is True, "declared_visit")
    for flag in (
        "complete_lifecycle_matrix_visited",
        "implemented_checks_passed",
        "headline_timing_eligible",
        "full_rsp_128_129_qualification",
    ):
        require(report.get(flag) is False, "original_scope_flags")
    observed_runtime = report["runtime"]
    for field in ("build_sha", "rule_digest", "runtime_sha256"):
        require(observed_runtime.get(field) == runtime[field], "runtime_identity")
    require(
        observed_runtime.get("mode") == "auto" and observed_runtime.get("package_origin") == "installed",
        "installed_default",
    )
    require(len(cells) == 5 and [cell["scenario"] for cell in cells] == list(SCENARIOS), "terminal_roster")
    for cell in cells:
        require(cell["registered_workspaces"] == 100 and cell["status"] == "completed", "terminal_identity")
        for flag in (
            "passed",
            "installed_runtime_matches",
            "declared_cell_matches",
            "publisher_contained",
            "writer_drained",
            "stricter_overlay_retained",
            "secondary_workspace_probe_declared",
            "secondary_workspace_probed",
        ):
            require(cell.get(flag) is True, "original_cell_failure:" + cell["scenario"])
        require(
            not any(key in cell for key in ("failure", "cleanup_failures", "fixture_cleanup_failure")),
            "cell_failure_evidence",
        )
        require(cell.get("readiness_deadline_ms") == 400, "original_deadline")
        elapsed = cell.get("accept_to_ack_ms")
        require(type(elapsed) in (int, float), "readiness_type")
        elapsed = cast(float, elapsed)
        require(math.isfinite(elapsed) and 0 <= elapsed <= 400, "readiness_miss")
        require(
            cell.get("probe_workspace_index") == 99 and cell.get("recovered_requests_declared") == 1, "request_scope"
        )
        requests = cell["requests"]
        require(
            requests.get("passed") is True
            and requests.get("observed_requests") == 1
            and requests.get("declared_requests") == 1,
            "request_receipt_join",
        )
        require(
            len(requests["actual_request_rows"]) == 1 and requests["actual_request_rows"][0]["workspace_index"] == 99,
            "secondary_scope",
        )
        require(cell["binding"]["runtime_identity"] == runtime["runtime_sha256"], "cell_runtime")
    return {
        "schema": "hol-guard.current-workspace100-admission.v1",
        "current100_subset_passed": True,
        "exact_cells": [{"scenario": cell["scenario"], "registered_workspaces": 100, "passed": True} for cell in cells],
        "original_exit": returncode,
        "original_complete_lifecycle_matrix_visited": False,
        "original_implemented_checks_passed": False,
        "full_15_cell_or_cross_platform_qualification": False,
        "headline_timing_eligible": False,
        "observation_scope": "original built-in fixture observers only; no added cause forwarding",
        "exact_barrier_commit_time_claimed": False,
    }
