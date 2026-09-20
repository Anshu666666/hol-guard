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

from admission import SCENARIOS, MemoryLedger, admit, decode, reconstruct

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
    ledger = MemoryLedger()
    summaries = []
    for scenario in SCENARIOS:
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
        "scenarios": list(SCENARIOS),
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
    assert result["current100_subset_passed"] is True
    assert result["original_implemented_checks_passed"] is False
    assert report == original
    assert len(cells) == 5
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
        cells.reverse()
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
