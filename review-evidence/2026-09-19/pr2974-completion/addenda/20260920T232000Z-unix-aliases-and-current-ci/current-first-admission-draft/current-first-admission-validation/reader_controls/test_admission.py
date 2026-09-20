"""Synthetic reader controls; no native lifecycle or timing is executed."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest
from scripts.native_slo_workspace_decision import join_decisions
from scripts.native_slo_workspace_lifecycle_evidence import retain_cell
from scripts.native_slo_workspace_trace import event_digest

from admission import SCENARIOS, SELECTED_SCENARIOS, MemoryLedger, admit, decode, reconstruct

pytest_plugins = ["tests.test_native_slo_workspace_lifecycle_evidence"]


def packet(cell: dict[str, Any]) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    """Translate the existing synthetic receipt/SQLite fixture to reader scope."""
    model = copy.deepcopy(cell)
    model.update(
        registered_workspaces=100,
        installed_runtime_matches=True,
        declared_cell_matches=True,
        publisher_contained=True,
        writer_drained=True,
        stricter_overlay_retained=True,
        secondary_workspace_probe_declared=True,
        secondary_workspace_probed=True,
        readiness_deadline_ms=400.0,
        probe_workspace_index=99,
        recovered_requests_declared=1,
    )
    model["requests"]["actual_request_rows"][0]["workspace_index"] = 99
    requests = model["requests"]
    requests.update(
        join_decisions(
            requests["actual_request_rows"],
            authority=requests["authority"],
            action="allow",
            accepted_ms=requests["accepted_ms"],
            declared_attempts=requests["declared_attempts"],
            observation_complete=requests["observation_complete"],
        )
    )
    compile_row = model["publication_rows"][0]
    compile_row.update(registered_workspaces=100, cache_entries=101, scope_loads=[1] * 101)
    model["publication_observer"]["event_digest"] = event_digest(model["publication_rows"])
    model["fault"] = {
        "scope": "one_real_accepted_reply_discarded_before_first_python_admission",
        "real_client_calls": 2,
        "real_accepted_reply_discarded": True,
        "production_ack_error_observed": True,
        "first_error_withheld_ack": True,
        "subsequent_transport_forwarded": True,
        "successful_ack_fabricated": False,
    }
    model["service_replacement"] = {
        "scope": "two_python_service_instances_same_process_same_owned_home",
        "service_instances": 2,
        "cold_observation_boundary": "before_real_constructor_start",
        "python_process_restarted": False,
        "old_publisher_stopped": True,
        "old_resident_contained": True,
        "old_service_contained": True,
        "old_owner_lock_released": True,
        "same_owned_home_identity": True,
        "fresh_store_and_service": True,
        "cold_publisher_without_ack": True,
        "empty_command_authority_reloaded": True,
    }
    ledger = MemoryLedger()
    summaries = []
    for scenario in SELECTED_SCENARIOS:
        owned = {**model, "scenario": scenario}
        ledger.write({"kind": "lifecycle_cell_offer", "scenario": scenario, "registered_workspaces": 100})
        summaries.append(retain_cell(ledger, owned))
    raw = b"".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n" for row in ledger.rows
    )
    runtime = {"runtime_sha256": model["binding"]["runtime_identity"], "build_sha": "a" * 40, "rule_digest": "b" * 64}
    report = {
        "schema": "hol-guard.native-workspace-lifecycle.v1",
        "counts": [100],
        "scenarios": list(SELECTED_SCENARIOS),
        "cells": summaries,
        "declared_cells_visited": True,
        "complete_lifecycle_matrix_visited": False,
        "implemented_checks_passed": False,
        "headline_timing_eligible": False,
        "full_rsp_128_129_qualification": False,
        "runtime": {**runtime, "mode": "auto", "package_origin": "installed"},
        "ledger": {"bytes": len(raw), "records": len(ledger.rows), "sha256": hashlib.sha256(raw).hexdigest()},
    }
    return report, raw, runtime


def test_complete_proof_roundtrip_preserves_original_subset_failure(cell: dict[str, Any]) -> None:
    report, raw, runtime = packet(cell)
    original = copy.deepcopy(report)
    cells = reconstruct(report, raw)
    result = admit(report, cells, returncode=1, runtime=runtime)
    assert result["current_first_admission_passed"] is True
    assert result["original_implemented_checks_passed"] is False
    assert report == original
    assert len(cells) == 1
    assert (
        cells[0]["requests"]["actual_request_rows"][0]["native_receipt"]
        == cell["requests"]["actual_request_rows"][0]["native_receipt"]
    )


@pytest.mark.parametrize("damage", ["tail", "truncate", "hash", "duplicate_part", "summary"])
def test_incomplete_or_changed_ledger_is_refused(cell: dict[str, Any], damage: str) -> None:
    report, raw, _runtime = packet(cell)
    if damage == "tail":
        raw += b"{}\n"
    elif damage == "truncate":
        raw = raw[:-1]
    elif damage == "hash":
        report["ledger"]["sha256"] = "f" * 64
    elif damage == "duplicate_part":
        rows = raw.splitlines(keepends=True)
        rows[2] = rows[1]
        raw = b"".join(rows)
        report["ledger"] = {"bytes": len(raw), "records": len(rows), "sha256": hashlib.sha256(raw).hexdigest()}
    else:
        report["cells"][0]["passed"] = False
    with pytest.raises(ValueError):
        reconstruct(report, raw)


@pytest.mark.parametrize(
    "damage",
    [
        "exit",
        "full_matrix",
        "case_order",
        "missing_case",
        "failed_cell",
        "late",
        "runtime",
        "cleanup",
        "secondary",
        "receipt",
    ],
)
def test_original_failure_cannot_be_admitted(cell: dict[str, Any], damage: str) -> None:
    report, raw, runtime = packet(cell)
    cells = reconstruct(report, raw)
    code = 1
    if damage == "exit":
        code = 0
    elif damage == "full_matrix":
        report["implemented_checks_passed"] = True
    elif damage == "case_order":
        cells[0]["scenario"] = "key_rotation"
    elif damage == "missing_case":
        cells.pop()
    elif damage == "failed_cell":
        cells[0]["passed"] = False
    elif damage == "late":
        cells[0]["accept_to_ack_ms"] = 400.00001
    elif damage == "runtime":
        runtime["build_sha"] = "c" * 40
    elif damage == "cleanup":
        cells[0]["cleanup_failures"] = []
    elif damage == "secondary":
        cells[0]["requests"]["actual_request_rows"][0]["workspace_index"] = 0
    else:
        cells[0]["requests"]["passed"] = False
    with pytest.raises(ValueError):
        admit(report, cells, returncode=code, runtime=runtime)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_ambiguous_json_is_refused(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode(raw)


def test_selected_cell_preserves_original_canonical_fifteen_cell_census() -> None:
    from scripts import native_slo_workspace_lifecycle_runner as original

    assert SCENARIOS == original.LIFECYCLE_SCENARIOS
    assert original.WORKSPACE_COUNTS == (1, 10, 100)
    matrix = [(count, scenario) for count in original.WORKSPACE_COUNTS for scenario in SCENARIOS]
    assert len(matrix) == len(set(matrix)) == 15
    assert SELECTED_SCENARIOS == ("first_admission_fault",)
    assert [(100, scenario) for scenario in SELECTED_SCENARIOS] != matrix


def test_duplicate_census_refuses_before_any_original_setup(tmp_path, monkeypatch) -> None:
    from scripts import native_slo_workspace_lifecycle_runner as original

    calls = []
    monkeypatch.setattr(original, "_clear_proof_overrides", lambda: calls.append("setup"))
    invalid = (
        "lost_metadata_hint",
        "first_admission_fault",
        "first_admission_fault",
        "expiry_fault",
        "service_restart",
    )
    ledger = tmp_path / "not-created.jsonl"
    with pytest.raises(ValueError, match="declared matrix invalid"):
        original.run_lifecycle_sweep(tmp_path / "not-executed", ledger_path=ledger, scenarios=invalid)
    assert calls == [] and not ledger.exists()


@pytest.mark.parametrize(
    "field",
    [
        "real_accepted_reply_discarded",
        "production_ack_error_observed",
        "first_error_withheld_ack",
        "subsequent_transport_forwarded",
        "successful_ack_fabricated",
    ],
)
def test_fault_evidence_is_required_despite_a_true_top_level_pass(cell, field) -> None:
    report, raw, runtime = packet(cell)
    cells = reconstruct(report, raw)
    cells[0]["fault"][field] = field == "successful_ack_fabricated"
    with pytest.raises(ValueError, match="original_fault_not_proved"):
        admit(report, cells, returncode=1, runtime=runtime)


@pytest.mark.parametrize("field", ["fresh_store_and_service", "old_resident_contained", "cold_publisher_without_ack"])
def test_actual_replacement_evidence_is_required(cell, field) -> None:
    report, raw, runtime = packet(cell)
    cells = reconstruct(report, raw)
    cells[0]["service_replacement"][field] = False
    with pytest.raises(ValueError, match="original_replacement_not_proved"):
        admit(report, cells, returncode=1, runtime=runtime)
