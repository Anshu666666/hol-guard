"""Original failed-run records and actual default compiler; no native replay."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes, validate_native_decision_receipt
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from scripts.native_slo_pi_receipts import PiReceipts
from scripts.native_slo_pi_sources import cases, validate_delivery
from tests.test_native_slo_pi_receipts import exercise, fixture

CAPTURE = json.loads((Path(__file__).parent / "fixtures" / "native_pi_default_policy.json").read_text())


@pytest.mark.parametrize("index", [0, 2], ids=["benign-command", "clean-source"])
def test_original_warning_delivery_and_native_receipt_match_exact_current_case(tmp_path, index):
    case = cases(tmp_path, "pi")[index]
    captured = next(row for row in CAPTURE["rows"] if row["callback"]["id"] == case.label)
    assert validate_native_decision_receipt(captured["receipt"]) == captured["receipt"]
    assert captured["receipt"]["policy_action"] == case.policy_action == "warn"
    assert captured["receipt"]["reason_code"] == case.reason == "native_policy_warning"
    validate_delivery(case, copy.deepcopy(captured["callback"]))


def test_actual_default_compiler_preserves_warn_floor_for_declared_benign_cases(tmp_path):
    config = GuardConfig(guard_home=tmp_path / "guard", workspace=tmp_path)
    policy = effective_native_policy_v3(config)
    assert policy["protection_posture"] == "protected"
    assert policy["default_action"] == policy["subprocess_action"] == "warn"
    assert policy["harness_actions"] == {}
    assert [case.policy_action for case in cases(tmp_path, "pi")] == ["warn", "block", "warn", "block", "block"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_action", "allow"),
        ("policy_action", "review"),
        ("reason_code", "source_full_scan_allow"),
        ("reason_code", "different_warning"),
    ],
)
@pytest.mark.parametrize("index", [0, 2], ids=["benign-command", "clean-source"])
def test_original_warning_http_cannot_be_replaced_by_different_policy_or_reason(tmp_path, index, field, value):
    case = cases(tmp_path, "pi")[index]
    captured = next(row for row in CAPTURE["rows"] if row["callback"]["id"] == case.label)
    row = copy.deepcopy(captured["callback"])
    row["fetches"][0][field] = value
    with pytest.raises(RuntimeError, match="policy_verdict"):
        validate_delivery(case, row)


@pytest.mark.parametrize(
    "action,reason,accepted",
    [
        ("warn", "native_policy_warning", True),
        ("allow", "native_policy_warning", False),
        ("warn", "source_full_scan_allow", False),
        ("review", "native_policy_warning", False),
    ],
)
def test_exact_warning_policy_is_required_in_real_committed_receipt(tmp_path, action, reason, accepted):
    state = fixture(tmp_path)
    captured = next(row for row in CAPTURE["rows"] if row["callback"]["id"] == state.case.label)
    value = state.edge["receipt"]
    # Native calls remain modeled. Reuse the observed public policy projection,
    # then recompute its identity digest as the existing SQLite fixture does.
    value["policy_action"] = captured["receipt"]["policy_action"] if accepted else action
    value["reason_code"] = reason
    value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    state.edge["result"]["policy_action"] = value["policy_action"]
    state.edge["result"]["reason_code"] = reason
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    result = exercise(state, witness)
    row = result["rows"][state.case.label]
    assert row["committed_receipt"] == value
    assert row["edge_binding_valid"] and row["ack_binding_valid"] and row["request_binding_valid"]
    assert row["receipt_checks"] is accepted and result["complete"] is accepted
