"""Capability contract for the decision-critical I/O ownership gate."""

from __future__ import annotations

from collections.abc import Iterable


def capability_contract(compatibility_modes: Iterable[str]) -> list[dict[str, object]]:
    return [
        {
            "id": "command_review_mutation_fence",
            "authority": "shared_python_native_coordination",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_authority_fence",
            "python_semantic_fallback": False,
            "scope": "owned_lock_identity_and_shared_lease_through_review_response",
            "failure": "existing_event_specific_availability_contract",
        },
        {
            "id": "hook_posture_and_availability_response",
            "authority": "python_bridge",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_posture_config",
            "python_semantic_fallback": False,
            "failure": "event_specific_availability_contract",
        },
        {
            "id": "post_tool_source_read",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::read_bounded", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "sensitive_path_and_symlink_classification",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::classify_source_path", "guard_secure_fs::contains_symlink_component"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "pre_post_identity_and_equivalence",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::FileIdentity", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "archive_decode_package_inspection",
            "authority": "rust_when_hook_reachable",
            "rust_symbols": [
                "guard_command::pretool::evaluate_pre_tool_envelope",
                "guard_runtime::strict_json::parse",
                "guard_hook_core::extract_payload_output",
            ],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "policy_snapshot_admission",
            "authority": "rust",
            "rust_symbols": [
                "guard_runtime::policy_store::PolicySnapshotStore",
                "guard_runtime::edge::evaluate_envelope_with_store",
            ],
            "python_semantic_fallback": False,
            "python_decision_time_disk_io": False,
            "failure": "fail_closed",
        },
    ]
