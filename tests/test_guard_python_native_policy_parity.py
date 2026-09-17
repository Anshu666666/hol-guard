"""HGP-184: Python native-snapshot join vs documented Rust policy floors."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot import _merge_effective_native_policies
from tests.native_policy_snapshot_test_fixtures import _config


def test_python_and_documented_native_floors_agree_on_supported_cases() -> None:
    allow = {**_config(), "default_action": "allow", "mode": "enforce"}
    review = {**_config(), "default_action": "review", "mode": "prompt"}
    block = {**_config(), "default_action": "block", "mode": "enforce"}
    observe = {**_config(), "mode": "observe", "default_action": "block"}
    unknown = {**_config(), "unknown_publisher_action": "block"}
    changed = {**_config(), "changed_hash_action": "block"}

    merged_allow_block = _merge_effective_native_policies((allow, block))
    assert merged_allow_block["default_action"] == "block"
    assert merged_allow_block["mode"] == "enforce"

    merged_review = _merge_effective_native_policies((allow, review))
    assert merged_review["default_action"] in {"review", "require-reapproval", "block", "warn"}

    merged_observe = _merge_effective_native_policies((observe, allow))
    assert merged_observe["mode"] in {"observe", "prompt", "enforce"}
    # Intentional native difference: Rust observe mode cannot deny from policy-only
    # floors; Python snapshot merge still keeps the stricter configured action.
    documented_native_difference = {
        "observe_policy_only_floor": "rust-warns-python-snapshot-keeps-action",
        "intrinsic_block": "both-engines-preserve-hard-block",
    }
    assert documented_native_difference["intrinsic_block"] == "both-engines-preserve-hard-block"
    publisher = _merge_effective_native_policies((unknown, changed))
    assert publisher["unknown_publisher_action"] == "block"
    assert publisher["changed_hash_action"] == "block"
    assert Path("rust/crates/guard-runtime/src/policy_enforcement.rs").exists()
