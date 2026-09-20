"""Closed native failure-frame reader; no raw stderr is retained."""

from __future__ import annotations

import json
from typing import Any

PREFIX = b"HG_MAC_RECOVERY_V2 "
CODES = frozenset(
    {
        "native_client_auth_nonce_failed",
        "native_client_auth_rejected",
        "native_client_auth_timeout_failed",
        "native_client_connect_failed",
        "native_client_deadline_exceeded",
        "native_client_deadline_invalid",
        "native_client_endpoint_invalid",
        "native_client_frame_invalid",
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
        "native_client_peer_identity_failed",
        "native_client_peer_identity_mismatch",
        "native_client_random_failed",
        "native_client_request_too_large",
        "native_client_response_binding_failed",
        "native_client_response_digest_mismatch",
        "native_client_response_too_large",
        "native_client_timeout_failed",
        "native_client_transport_invalid",
        "native_client_unix_unavailable",
        "native_resident_process_identity_mismatch",
        "native_resident_process_identity_unavailable",
        "native_resident_runtime_path_failed",
        "unknown",
    }
)


READ_PHASES = frozenset({"unobserved", "server_proof", "response_header", "response_body"})
READ_ORIGINS = frozenset(
    {
        "unobserved",
        "pre_read_deadline",
        "timeout_setter",
        "timeout_recovery",
        "underlying_read",
        "post_read_deadline",
        "underlying_eof",
        "read_exact",
        "timeout_recovery_eof",
    }
)
READ_KINDS = frozenset(
    {
        "unobserved",
        "not_found",
        "permission_denied",
        "connection_refused",
        "connection_reset",
        "connection_aborted",
        "not_connected",
        "addr_in_use",
        "addr_not_available",
        "broken_pipe",
        "already_exists",
        "would_block",
        "invalid_input",
        "invalid_data",
        "timed_out",
        "interrupted",
        "unexpected_eof",
        "other",
        "unlisted_kind",
    }
)


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_native_field")
        result[key] = value
    return result


def decode(stderr: bytes) -> dict[str, Any] | None:
    if type(stderr) is not bytes or len(stderr) > 8192:
        raise ValueError("native_stderr_bound")
    lines = stderr.splitlines()
    frames = [line for line in lines if line.startswith(PREFIX)]
    if not frames:
        return None
    if len(frames) != 1 or len(lines) != 2 or lines[0] != b"native_resident_live_request_failed":
        raise ValueError("native_frame_placement")
    body = frames[0][len(PREFIX) :]
    if len(body) > 1024:
        raise ValueError("native_frame_bound")
    value = json.loads(body, object_pairs_hook=pairs)
    fixed = {
        "schema": "hol-guard-macos-recovery-failure.v2",
        "complete_run": False,
        "headline_timing_eligible": False,
        "stage": "live_exchange_pre_collapse",
        "retained_observations": 1,
        "maximum_retained_observations": 1,
        "snapshot_atomic": False,
        "scope": "first_observed_non_retryable_live_exchange_error",
        "state_fields_coherent": True,
        "owner_liveness_observed": False,
    }
    extra = {
        "known_code",
        "retryable_teardown",
        "additional_observation_lost",
        "generation",
        "process_id",
        "owner_process_id",
        "transport",
        "read_phase",
        "read_origin",
        "read_error_kind",
        "read_raw_os_error",
    }
    if type(value) is not dict or set(value) != set(fixed) | extra:
        raise ValueError("native_frame_schema")
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in fixed.items()):
        raise ValueError("native_frame_fixed")
    if type(value["known_code"]) is not str or value["known_code"] not in CODES:
        raise ValueError("native_frame_code")
    if type(value["transport"]) is not str or value["transport"] not in {"unix", "loopback", "unknown"}:
        raise ValueError("native_frame_transport")
    for key in ("retryable_teardown", "additional_observation_lost"):
        if type(value[key]) is not bool:
            raise ValueError("native_frame_boolean")
    for key, maximum in (("generation", 2**64 - 1), ("process_id", 2**32 - 1), ("owner_process_id", 2**32 - 1)):
        if type(value[key]) is not int or not 0 <= value[key] <= maximum:
            raise ValueError("native_frame_integer")
    for key, allowed in (("read_phase", READ_PHASES), ("read_origin", READ_ORIGINS), ("read_error_kind", READ_KINDS)):
        if type(value[key]) is not str or value[key] not in allowed:
            raise ValueError("native_read_enum")
    raw = value["read_raw_os_error"]
    if raw is not None and (type(raw) is not int or not -(2**31) <= raw < 2**31):
        raise ValueError("native_read_os_error")
    unobserved = value["read_phase"] == "unobserved"
    if unobserved:
        if value["read_origin"] != "unobserved" or value["read_error_kind"] != "unobserved" or raw is not None:
            raise ValueError("native_read_unobserved")
    elif (
        value["known_code"] != "native_client_frame_read_failed"
        or value["read_origin"] == "unobserved"
        or value["read_error_kind"] == "unobserved"
    ):
        raise ValueError("native_read_scope")
    return value
