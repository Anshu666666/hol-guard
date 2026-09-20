"""Finite source/registration controls; none is installed native qualification."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from scripts.native_slo_pi_sources import cases, installed_registration, validate_delivery, validate_reference_join


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_actual_adapter_registers_the_exact_generated_extension(tmp_path, harness):
    home, workspace, guard_home = (tmp_path / name for name in ("home", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    extension, evidence = installed_registration(context, harness)
    assert evidence["registered_exactly_once"] is True
    assert evidence["external_host_application_executed"] is False
    assert evidence["extension_sha256"] == hashlib.sha256(extension.read_bytes()).hexdigest()
    source = extension.read_text()
    for event in ("tool_call", "tool_result", "message_end"):
        assert f'pi.on("{event}"' in source
    assert f"/v1/hooks/{harness}" in source


def test_source_fixtures_put_scanner_material_beyond_excerpt_and_keep_changed_bytes(tmp_path):
    cohort = cases(tmp_path, "pi")
    assert len(cohort) == 5
    clean, sensitive, changed = cohort[2:]
    assert clean.output == sensitive.output[: len(clean.output)]
    assert len(clean.output) > 12_000
    assert Path(sensitive.arguments["file_path"]).read_text() == sensitive.output
    assert Path(changed.arguments["file_path"]).read_text() != changed.output
    assert all(len(case.correlation) >= 16 for case in cohort)
    assert len({case.correlation for case in cohort}) == 5


def _row(case) -> dict[str, Any]:
    digest = hashlib.sha256(case.output.encode()).hexdigest()
    return {
        "id": case.label,
        "offered": True,
        "returned": True,
        "input_unchanged": True,
        "preserved": case.decision == "allow",
        "blocked": case.decision == "deny",
        "model_blocked": True,
        "fetches": [
            {
                "method": "POST",
                "pathname": "/v1/hooks/" + case.harness,
                "status": 200,
                "decision": case.decision,
                "policy_action": case.policy_action,
                "source_ref_present": True,
                "source_ref_sha256": digest,
                "source_ref_chars": len(case.output),
                "excerpt_truncated": True,
                "reason_code": case.reason,
                "model_output_action": "allow_original",
                "reviewed_output_sha256": digest,
            }
        ],
    }


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4])
def test_fixed_delivery_contract_accepts_each_declared_shape(tmp_path, index):
    case = cases(tmp_path, "omp")[index]
    validate_delivery(case, _row(case))


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "route",
        "status",
        "source",
        "digest",
        "chars",
        "excerpt",
        "original_proof",
        "mutation",
        "unreturned",
        "verdict",
    ],
)
def test_clean_source_cannot_pass_with_missing_or_wrong_independent_evidence(tmp_path, change):
    case = cases(tmp_path, "pi")[2]
    row = _row(case)
    fetch = row["fetches"][0]
    if change == "missing":
        row["fetches"] = []
    elif change == "duplicate":
        row["fetches"].append(copy.deepcopy(fetch))
    elif change == "mutation":
        row["input_unchanged"] = False
    elif change == "unreturned":
        row["returned"] = False
    elif change == "verdict":
        row["preserved"] = False
    else:
        field, value = {
            "route": ("pathname", "/v1/hooks/omp"),
            "status": ("status", 503),
            "source": ("source_ref_present", False),
            "digest": ("source_ref_sha256", "0" * 64),
            "chars": ("source_ref_chars", 1),
            "excerpt": ("excerpt_truncated", False),
            "original_proof": ("reviewed_output_sha256", "0" * 64),
        }[change]
        fetch[field] = value
    with pytest.raises(RuntimeError):
        validate_delivery(case, row)


def test_block_requires_model_visible_message_replacement(tmp_path):
    case = cases(tmp_path, "pi")[3]
    row = _row(case)
    row["model_blocked"] = False
    with pytest.raises(RuntimeError, match="message_end"):
        validate_delivery(case, row)


def test_evidence_reader_keeps_offered_row_after_callback_failure(tmp_path):
    from scripts.ci.verify_installed_pi_sources import read_rows

    path = tmp_path / "partial.jsonl"
    row = {"id": "pi-pre-allow", "offered": True, "returned": False}
    path.write_text(json.dumps(row) + "\n")
    assert read_rows(path) == [row]
    path.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(RuntimeError, match="bound"):
        read_rows(path)


@pytest.mark.parametrize("change", [False, True])
def test_http_ciphertext_must_match_the_exact_native_entry_reference(change):
    rows = [
        {
            "id": "pi-source-clean",
            "returned": True,
            "fetches": [{"encrypted_payload_ref_present": True, "encrypted_payload_sha256": "a" * 64}],
        }
    ]
    native = {"rows": {"pi-source-clean": {"entry_encrypted_payload_sha256": ("b" if change else "a") * 64}}}
    if change:
        with pytest.raises(RuntimeError, match="reference_join_mismatch"):
            validate_reference_join(rows, native)
    else:
        validate_reference_join(rows, native)


@pytest.mark.parametrize("leak", ["secret", "output", "command", "private_path"])
@pytest.mark.parametrize("surface", ["receipt", "metrics", "failure"])
def test_declared_raw_inputs_cannot_enter_any_exported_evidence_surface(tmp_path, leak, surface):
    from scripts.native_slo_pi_sources import validate_export_privacy

    cohort = cases(tmp_path, "pi")
    value = {
        "secret": cohort[3].output.splitlines()[-1],
        "output": cohort[2].output,
        "command": cohort[1].arguments["command"],
        "private_path": cohort[2].arguments["file_path"],
    }[leak]
    report = {surface: {"unexpected": value}}
    with pytest.raises(ValueError, match="installed_pi_export_raw_"):
        validate_export_privacy(report, tmp_path)
    assert report[surface]["unexpected"] == value


def test_privacy_check_preserves_full_valid_receipt_and_failure_digest(tmp_path):
    from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
    from scripts.native_slo_failure import failure_evidence
    from scripts.native_slo_pi_sources import validate_export_privacy
    from tests.native_workspace_request_fixtures import receipt, snapshot

    value = receipt(snapshot())
    report = {"receipt": value, "failure": failure_evidence(RuntimeError(str(tmp_path) + " private fixture"))}
    original = json.dumps(report, sort_keys=True)
    proof = validate_export_privacy(report, tmp_path)
    assert proof["declared_markers_absent"] and proof["all_exporters_qualified"] is False
    assert json.dumps(report, sort_keys=True) == original
    assert validate_native_decision_receipt(report["receipt"]) == value
