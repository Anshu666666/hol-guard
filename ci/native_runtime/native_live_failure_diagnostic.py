"""Closed diagnostic retention for a directly owned native CLI subprocess.

The original error sanitizer, request, timeout, return code and assertion stay
unchanged. This helper never exports raw stderr or an unrecognized JSON value.
"""

from __future__ import annotations

import json

PREFIX = b"HG_LIVE_FAILURE_V1 "
MAX_RECORD_BYTES = 768
MAX_STDERR_BYTES = 8192
KNOWN_CODES = frozenset(
    (
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
    )
)
FIXED = {
    "schema": "hol-guard-native-live-failure.v1",
    "stage": "live_exchange_pre_collapse",
    "retained_observations": 1,
    "maximum_retained_observations": 1,
    "snapshot_atomic": False,
    "scope": "first_observed_non_retryable_live_exchange_error",
    "complete_run": False,
    "headline_timing_eligible": False,
}
FIELDS = frozenset((*FIXED, "known_code", "retryable_teardown", "additional_observation_lost"))


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("nonfinite")


def decode_diagnostic(stderr: bytes) -> dict[str, object]:
    report: dict[str, object] = {
        "schema": "hol-guard-native-live-failure-retained.v1",
        "scope": "owned_cli_stderr_after_original_run_failure",
        "headline_timing_eligible": False,
        "status": "unobserved",
        "record": None,
    }
    if type(stderr) is not bytes or len(stderr) > MAX_STDERR_BYTES:
        report["status"] = "refused"
        return report
    lines = stderr.splitlines(keepends=True)
    records = [line for line in lines if line.startswith(PREFIX)]
    if not records:
        return report
    if (
        len(records) != 1
        or not lines
        or lines[0].rstrip(b"\r\n") != b"native_resident_live_request_failed"
        or not records[0].endswith(b"\n")
    ):
        report["status"] = "refused"
        return report
    payload = records[0][len(PREFIX) :].rstrip(b"\r\n")
    if not 0 < len(payload) <= MAX_RECORD_BYTES:
        report["status"] = "refused"
        return report
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_unique, parse_constant=_constant)
        valid = type(value) is dict and set(value) == FIELDS
        if valid:
            valid = all(
                type(value[key]) is type(expected) and value[key] == expected for key, expected in FIXED.items()
            )
        if valid:
            valid = (
                type(value["known_code"]) is str
                and value["known_code"] in KNOWN_CODES
                and type(value["retryable_teardown"]) is bool
                and type(value["additional_observation_lost"]) is bool
            )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        valid = False
    if valid:
        report["status"] = "observed"
        report["record"] = value
    else:
        report["status"] = "refused"
    return report


def retain_diagnostic(stderr: bytes) -> None:
    # Formatting uses only validated closed fields or fixed refusal categories.
    # A diagnostic exporter failure must not replace the original assertion.
    try:
        print("HG_LIVE_FAILURE_RETAINED " + json.dumps(decode_diagnostic(stderr), sort_keys=True))
    except Exception:
        pass
