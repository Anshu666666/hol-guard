"""Read one bounded parent-only Windows startup record without changing its result."""

from __future__ import annotations

import json
from typing import Any

PREFIX = b"HG_WINDOWS_STARTUP_V1 "
MAX_RECORD_BYTES = 4096
MAX_COUNT = 65535
MAX_TIME = 4294967295
STAGES = [
    "Lease",
    "RuntimeDigest",
    "PrivateScope",
    "Discovery",
    "ReadState",
    "ValidateState",
    "ProcessIdentity",
    "Token",
    "Exchange",
    "StartupLock",
    "StaleLock",
    "RestartBudget",
    "Generation",
    "Spawn",
    "AbortTerminate",
    "AbortRetire",
]
EVENTS = [
    "Scopes",
    "Paths",
    "States",
    "NoResponse",
    "RejectedState",
    "PollEntered",
    "PollNoResponse",
    "PollExpired",
    "LeaseDropped",
]
CODES = [
    "native_client_auth_nonce_failed",
    "native_client_auth_rejected",
    "native_client_auth_timeout_failed",
    "native_client_connect_failed",
    "native_client_deadline_exceeded",
    "native_client_frame_read_failed",
    "native_client_frame_write_failed",
    "native_client_peer_identity_failed",
    "native_client_peer_identity_mismatch",
    "native_client_random_failed",
    "native_client_response_binding_failed",
    "native_client_response_digest_mismatch",
    "native_resident_child_cleanup_failed",
    "native_resident_clock_invalid",
    "native_resident_generation_invalid",
    "native_resident_live_request_failed",
    "native_resident_managed_exit_failed",
    "native_resident_owner_process_invalid",
    "native_resident_private_root_missing",
    "native_resident_process_identity_mismatch",
    "native_resident_process_identity_unavailable",
    "native_resident_runtime_digest_invalid",
    "native_resident_runtime_identity_mismatch",
    "native_resident_runtime_invalid",
    "native_resident_runtime_path_failed",
    "native_resident_runtime_read_failed",
    "native_resident_runtime_stat_failed",
    "native_resident_socket_dir_owner_mismatch",
    "native_resident_socket_dir_stat_failed",
    "native_resident_spawn_auth_failed",
    "native_resident_spawn_failed",
    "native_resident_spawn_stdin_failed",
    "native_resident_start_in_progress",
    "native_resident_start_timeout",
    "native_resident_state_dir_stat_failed",
    "native_resident_state_encode_failed",
    "native_resident_state_endpoint_invalid",
    "native_resident_state_invalid",
    "native_resident_state_list_failed",
    "native_resident_state_mac_invalid",
    "native_resident_state_prune_failed",
    "native_resident_state_read_failed",
    "native_resident_state_stat_failed",
    "native_resident_state_token_invalid",
    "native_resident_state_transport_invalid",
    "native_resident_state_write_failed",
    "native_resident_stop_unavailable",
    "native_resident_supervisor_wait_failed",
]
FIELDS = frozenset(
    {
        "schema",
        "parent_only",
        "child_observed",
        "complete_run",
        "headline_timing_eligible",
        "qualification_complete",
        "original_error",
        "original_budget_us",
        "observed_elapsed_us",
        "observed_remaining_us",
        "phases",
        "events",
        "retries",
        "counter_or_clock_overflow",
        "observation_lost",
    }
)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("nonfinite_constant")


def _integer(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("integer_bound")
    return value


def _row(value: Any, width: int, maximum: int) -> list[int]:
    if type(value) is not list or len(value) != width:
        raise ValueError("row_shape")
    return [_integer(item, maximum) for item in value]


def _code(value: Any) -> int:
    return _integer(value, len(CODES) + 1)


def _validate_record(value: Any) -> dict[str, Any]:
    if type(value) is not dict or value.keys() != FIELDS:
        raise ValueError("record_fields")
    if value["schema"] != "hol-guard-native-windows-startup.v1":
        raise ValueError("record_schema")
    for name in (
        "parent_only",
        "child_observed",
        "complete_run",
        "headline_timing_eligible",
        "qualification_complete",
        "counter_or_clock_overflow",
        "observation_lost",
    ):
        if type(value[name]) is not bool:
            raise ValueError("boolean_type")
    if not value["parent_only"] or any(
        value[name] for name in ("child_observed", "complete_run", "headline_timing_eligible", "qualification_complete")
    ):
        raise ValueError("scope_claim")
    if _integer(value["original_budget_us"], 750000) != 750000:
        raise ValueError("original_budget")
    elapsed = _integer(value["observed_elapsed_us"], MAX_TIME)
    remaining = _integer(value["observed_remaining_us"], 750000)
    if remaining and elapsed + remaining not in (749999, 750000):
        raise ValueError("clock_relation")
    if not remaining and elapsed < 749999:
        raise ValueError("clock_relation")
    _code(value["original_error"])
    phases = value["phases"]
    events = value["events"]
    if type(phases) is not list or len(phases) != len(STAGES):
        raise ValueError("phase_count")
    if type(events) is not list or len(events) != len(EVENTS):
        raise ValueError("event_count")
    for raw in phases:
        row = _row(raw, 7, MAX_TIME)
        started, ended, errors, first, last, first_code, last_code = row
        for count in row[:3]:
            _integer(count, MAX_COUNT)
        _code(first_code)
        _code(last_code)
        if errors > ended or ended > started or first > elapsed or last > elapsed:
            raise ValueError("phase_relation")
        if not started and any(row):
            raise ValueError("absent_phase")
        if ended and last < first:
            raise ValueError("phase_clock_order")
        if not ended and (last or errors or first_code or last_code):
            raise ValueError("unfinished_phase")
        if bool(errors) != bool(first_code) or bool(errors) != bool(last_code):
            raise ValueError("phase_error_relation")
    for raw in events:
        count, total, first, last = _row(raw, 4, MAX_TIME)
        _integer(count, MAX_COUNT)
        _integer(total, MAX_COUNT)
        if first > last or last > elapsed or (not count and (total or first or last)):
            raise ValueError("event_relation")
    count, first_code, last_code, first_retryable, last_retryable = _row(value["retries"], 5, MAX_COUNT)
    _code(first_code)
    _code(last_code)
    _integer(first_retryable, 1)
    _integer(last_retryable, 1)
    if bool(count) != bool(first_code) or bool(count) != bool(last_code):
        raise ValueError("retry_relation")
    if not count and (first_retryable or last_retryable):
        raise ValueError("absent_retry")
    return value


def parse_stderr(stderr: bytes, returncode: int) -> dict[str, Any]:
    """Keep absence and incomplete observation distinct from valid finite data."""
    if type(stderr) is not bytes or type(returncode) is not int:
        raise ValueError("original_result_type")
    if len(stderr) > 8192:
        raise ValueError("stderr_bound")
    lines = stderr.splitlines(keepends=True)
    framed = [index for index, line in enumerate(lines) if line.startswith(PREFIX)]
    if not framed:
        return {"status": "missing", "record": None, "original_stderr": stderr}
    if len(framed) != 1 or framed[0] != len(lines) - 1:
        raise ValueError("frame_position")
    frame = lines[-1]
    if len(frame) > MAX_RECORD_BYTES or not frame.endswith(b"\n"):
        raise ValueError("frame_bound_or_truncation")
    original = b"".join(lines[:-1])
    record = _validate_record(
        json.loads(
            frame[len(PREFIX) :].decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_constant,
        )
    )
    if returncode == 0:
        if original or record["original_error"] != 0:
            raise ValueError("original_success_join")
    elif returncode == 2:
        if not original.endswith(b"\n") or len(original.splitlines()) != 1:
            raise ValueError("original_failure_join")
        label = original[:-1].decode("ascii")
        expected = CODES.index(label) + 2 if label in CODES else 1
        if record["original_error"] != expected:
            raise ValueError("original_error_join")
    else:
        raise ValueError("original_exit")
    codes = [record["original_error"], *record["retries"][1:3]]
    codes.extend(code for row in record["phases"] for code in row[5:7])
    incomplete = (
        record["counter_or_clock_overflow"]
        or record["observation_lost"]
        or 1 in codes
        or any(row[0] != row[1] for row in record["phases"])
    )
    return {"status": "incomplete" if incomplete else "valid", "record": record, "original_stderr": original}
