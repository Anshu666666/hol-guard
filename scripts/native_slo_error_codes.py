"""Finite already-public native codes for diagnostic projection only.

No prefix matching, raw native frame or OS diagnostic is exposed. This module
changes neither the production decoder nor the decision/availability contract.
The command-control list is pinned to the Rust transport vocabulary by a test.
"""

from codex_plugin_scanner.guard.native_approval_errors import (
    NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
)

COMMAND_CONTROL_ERROR_CODES = frozenset(
    {
        "native_command_control_authority_downgrade",
        "native_command_control_authority_epoch_reused",
        "native_command_control_authority_invalid",
        "native_command_control_authority_mac_invalid",
        "native_command_control_authority_missing",
        "native_command_control_authority_noncanonical",
        "native_command_control_authority_not_current",
        "native_command_control_authority_path_invalid",
        "native_command_control_authority_removed",
        "native_command_control_binding_invalid",
        "native_command_control_binding_removed",
        "native_command_control_digest_mismatch",
        "native_command_control_encoding_failed",
        "native_command_control_floor_invalid",
        "native_command_control_layer_invalid",
        "native_command_control_mutation_in_progress",
        "native_command_control_mutation_lock_invalid",
        "native_command_control_mutation_lock_missing",
        "native_command_control_mutation_lock_unsupported",
        "native_command_control_mutation_reused",
        "native_command_control_recovery_context_mismatch",
        "native_command_control_recovery_invalid",
        "native_command_control_recovery_missing",
        "native_command_control_revision_downgrade",
        "native_command_control_revision_reused",
        "native_command_control_target_invalid",
        "native_command_control_target_unknown",
        "native_policy_snapshot_command_authority_invalid",
        "native_policy_snapshot_command_authority_not_private",
        "native_policy_snapshot_command_authority_read_failed",
        "native_policy_snapshot_command_authority_stat_failed",
        "native_policy_snapshot_command_authority_too_large",
        "native_resident_command_mutation_lock_invalid",
        "native_resident_command_mutation_lock_read_failed",
    }
)
PUBLIC_NATIVE_ERROR_CODES = (
    NATIVE_APPROVAL_ERROR_CODES
    | NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
    | COMMAND_CONTROL_ERROR_CODES
    | {"native_request_deadline_exceeded", "native_frame_read_failed", "native_request_digest_mismatch"}
)
