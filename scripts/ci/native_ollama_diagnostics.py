"""Bounded, observational installed-probe progress without policy or process data."""

from __future__ import annotations

import hashlib
import math
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_startup import startup_code_locations

_PUBLISHER_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "native_command_control_binding_invalid",
        "native_command_control_catalog_mismatch",
        "native_command_control_digest_mismatch",
        "native_command_control_layer_invalid",
        "native_command_control_target_invalid",
        "native_command_program_artifact_invalid",
        "native_command_program_artifact_unavailable",
        "native_command_program_digest_mismatch",
        "native_policy_generation_exhausted",
        "native_policy_generation_home_invalid",
        "native_policy_generation_lock_invalid",
        "native_policy_generation_lock_timeout",
        "native_policy_generation_state_invalid",
        "native_policy_generation_state_missing",
        "native_policy_runtime_state_invalid",
        "native_policy_runtime_state_not_private",
        "native_policy_snapshot_array_too_wide",
        "native_policy_snapshot_cache_integrity_invalid",
        "native_policy_snapshot_cache_invalid",
        "native_policy_snapshot_cache_missing",
        "native_policy_snapshot_cache_noncanonical",
        "native_policy_snapshot_cache_read_failed",
        "native_policy_snapshot_cache_sync_failed",
        "native_policy_snapshot_cache_write_failed",
        "native_policy_snapshot_digest_invalid",
        "native_policy_snapshot_digest_mismatch",
        "native_policy_snapshot_duplicate_key",
        "native_policy_snapshot_expiry_invalid",
        "native_policy_snapshot_generation_exhausted",
        "native_policy_snapshot_generation_invalid",
        "native_policy_snapshot_generation_lock_invalid",
        "native_policy_snapshot_generation_lock_timeout",
        "native_policy_snapshot_generation_state_invalid",
        "native_policy_snapshot_generation_state_missing",
        "native_policy_snapshot_generation_state_read_failed",
        "native_policy_snapshot_generation_state_write_failed",
        "native_policy_snapshot_identity_invalid",
        "native_policy_snapshot_integrity_invalid",
        "native_policy_snapshot_json_invalid",
        "native_policy_snapshot_key_too_large",
        "native_policy_snapshot_mode_invalid",
        "native_policy_snapshot_nested_cycle",
        "native_policy_snapshot_nested_depth_exceeded",
        "native_policy_snapshot_number_invalid",
        "native_policy_snapshot_object_key_invalid",
        "native_policy_snapshot_object_too_wide",
        "native_policy_snapshot_policy_invalid",
        "native_policy_snapshot_protocol_invalid",
        "native_policy_snapshot_push_invalid",
        "native_policy_snapshot_schema_invalid",
        "native_policy_snapshot_scope_invalid",
        "native_policy_snapshot_serialization_failed",
        "native_policy_snapshot_string_too_large",
        "native_policy_snapshot_too_large",
        "native_policy_snapshot_transaction_conflict",
        "native_policy_snapshot_transaction_invalid",
        "native_policy_snapshot_unknown_field",
        "native_policy_snapshot_version_invalid",
        "native_policy_verifier_master_invalid",
        "native_policy_windows_acl_apply_failed",
        "native_policy_windows_acl_build_failed",
        "native_policy_windows_acl_unavailable",
        "native_policy_windows_acl_verify_failed",
        "native_policy_windows_handle_close_failed",
        "native_policy_windows_handle_invalid",
        "native_policy_windows_owner_sid_failed",
        "native_policy_windows_owner_sid_invalid",
        "native_policy_windows_path_invalid",
        "native_policy_windows_path_open_failed",
        "native_policy_windows_path_stat_failed",
        "native_policy_windows_replace_failed",
        "native_policy_windows_state_directory_create_failed",
        "native_policy_windows_state_directory_invalid",
        "native_policy_windows_sync_failed",
        "native_policy_windows_temporary_cleanup_failed",
        "native_policy_windows_write_failed",
        "native_policy_windows_write_too_large",
        "native_command_control_binding_changed",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_integrity_key_unavailable",
        "native_policy_snapshot_native_disabled",
        "native_policy_snapshot_protocol_unsupported",
        "native_policy_snapshot_publish_failed",
        "native_policy_snapshot_resident_changed",
        "native_policy_snapshot_runtime_unavailable",
        "native_policy_snapshot_workspace_capacity",
        "native_policy_snapshot_ack_invalid",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_verifier_key_invalid",
        "native_policy_verifier_key_mismatch",
        "native_policy_verifier_key_not_private",
        "native_policy_verifier_key_read_failed",
        "native_policy_verifier_key_stat_failed",
        "native_policy_verifier_key_sync_failed",
        "native_policy_verifier_key_write_failed",
        "native_client_timed_out",
        "native_client_exit_nonzero",
        "native_client_process_failed",
        "native_client_status_missing",
        "native_client_launcher_failed",
        "native_client_pool_exhausted",
        "native_client_containment_failed",
        "native_client_output_missing",
        "native_client_output_limit_exceeded",
        "native_client_request_invalid",
        "oserror",
        "permissionerror",
        "runtimeerror",
        "typeerror",
        "valueerror",
        "attributeerror",
        "operationalerror",
    }
)
_PHASES = frozenset(
    {
        "setup",
        "initial",
        "enabled",
        "approved_retry",
        "disabled",
        "updated",
        "settings_rollback",
        "stale_write_rejected",
    }
)
_STEPS = frozenset(
    {
        "artifact_identity",
        "construct",
        "authority",
        "start",
        "control_commit",
        "ready",
        "review",
        "approve",
        "artifact_recheck",
        "complete",
    }
)


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1 else None


def _milliseconds(value: float) -> float | None:
    return round(min(180_000.0, max(0.0, value)), 3) if math.isfinite(value) else None


def publisher_state(publisher: object, *, with_stack: bool = False) -> dict[str, object]:
    """Sample cached state only; never wait, retry, publish, or inspect controls.

    The nonblocking condition capture describes one instant, independently of
    the completed readiness attempt. No public accessor can renew/expire state
    or copy a full snapshot as a side effect of this diagnostic.
    """
    result: dict[str, object] = {"capture": "unavailable"}
    condition = getattr(publisher, "_condition", None)
    try:
        thread = getattr(publisher, "_thread", None)
        result["publisher_alive"] = thread.is_alive() if thread is not None else False
        if with_stack and thread is not None:
            # Reuse the reviewed eight-location/no-locals diagnostic contract,
            # including when the publisher condition itself is busy.
            result["stack"] = startup_code_locations(sys._current_frames().get(thread.ident))
        if condition is None:
            return result
        if not condition.acquire(blocking=False):
            return {**result, "capture": "busy"}
        try:
            snapshot = getattr(publisher, "_snapshot", None)
            current = snapshot if isinstance(snapshot, Mapping) else {}
            binding = current.get("command_extensions")
            binding = binding if isinstance(binding, Mapping) else {}
            error = getattr(publisher, "_last_error", None)
            expires = _integer(current.get("expires_at_ms"))
            result.update(
                {
                    "capture": "sampled",
                    "acknowledged": getattr(publisher, "_acked", None) is True,
                    "closed": getattr(publisher, "_closed", None) is True,
                    "retained_snapshot": isinstance(snapshot, Mapping),
                    "generation": _integer(current.get("generation")),
                    "control_revision": _integer(binding.get("revision")),
                    "managed_revision": _integer(binding.get("managed_revision")),
                    "epoch": _integer(getattr(publisher, "_epoch", None)),
                    "failure_count": _integer(getattr(publisher, "_failure_count", None)),
                    "retry_pending": getattr(publisher, "_retry_not_before_monotonic", None) is not None,
                    "expired": expires <= int(time.time() * 1000) if expires is not None else None,
                    "last_error": error
                    if isinstance(error, str) and error in _PUBLISHER_CODES
                    else "absent"
                    if error is None
                    else "redacted",
                }
            )
            if isinstance(error, str) and error not in _PUBLISHER_CODES:
                result["last_error_digest"] = hashlib.sha256(error[:4096].encode("utf-8", errors="replace")).hexdigest()
        finally:
            condition.release()
        return assert_privacy_safe(result)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return {"capture": "unavailable"}


@dataclass
class OllamaProbeProgress:
    """Retain at most the finite lifecycle corpus and its readiness observations."""

    phase: str = "setup"
    step: str = "artifact_identity"
    case: str | None = None
    adapter_readiness_ms: float | None = None
    completed_cases: list[dict[str, object]] = field(default_factory=list)
    readiness: list[dict[str, object]] = field(default_factory=list)
    publisher_stack: list[object] = field(default_factory=list)
    publisher_stack_attempt: int | None = None

    def at(self, *, step: str, phase: str | None = None, case: str | None = None) -> None:
        if step not in _STEPS or (phase is not None and phase not in _PHASES):
            raise ValueError("installed_ollama_progress_invalid")
        if assert_privacy_safe({"case": case})["case"] != case:
            raise ValueError("installed_ollama_progress_invalid")
        self.step, self.case = step, case
        if phase is not None:
            self.phase = phase

    def record_case(self, record: Mapping[str, object]) -> None:
        if len(self.completed_cases) >= 32:
            raise ValueError("installed_ollama_progress_limit")
        self.completed_cases.append(assert_privacy_safe(dict(record)))

    def observe_readiness(
        self,
        publisher: object,
        *,
        revision: int,
        before: Mapping[str, object],
        elapsed_ms: float,
        returned_snapshot: bool,
        within_budget: bool,
        raised: bool,
    ) -> None:
        if len(self.readiness) >= 16:
            raise ValueError("installed_ollama_progress_limit")
        after = publisher_state(publisher, with_stack=raised or not returned_snapshot or not within_budget)
        stack = after.pop("stack", None)
        if isinstance(stack, list):
            # Keep code locations near the evidence root. Nesting them below
            # readiness/after would exceed the aggregate privacy depth limit
            # once the outer installed driver adds its native result wrapper.
            self.publisher_stack = stack[:8]
            self.publisher_stack_attempt = len(self.readiness)
        self.readiness.append(
            {
                "phase": self.phase,
                "expected_revision": revision,
                "elapsed_ms": _milliseconds(elapsed_ms),
                "returned_snapshot": returned_snapshot,
                "within_budget": within_budget,
                "raised": raised,
                "before": dict(before),
                "after": after,
            }
        )

    def evidence(self) -> dict[str, object]:
        return assert_privacy_safe(
            {
                "phase": self.phase,
                "step": self.step,
                "case": self.case,
                "adapter_readiness_ms": self.adapter_readiness_ms,
                "completed_case_count": len(self.completed_cases),
                "completed_cases": list(self.completed_cases),
                "readiness": list(self.readiness),
                "publisher_stack": list(self.publisher_stack),
                "publisher_stack_attempt": self.publisher_stack_attempt,
                "observations_authorize_readiness": False,
            }
        )
