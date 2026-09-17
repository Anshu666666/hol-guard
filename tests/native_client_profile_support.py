from __future__ import annotations

from scripts.native_client_profile_records import PHASES


def record(*, digest="a" * 64, sequence=1):
    return {
        "schema": "hol-guard.native-client-profile.v1",
        "sequence": sequence,
        "request_sha256": digest,
        "helper_request_nanoseconds": 70,
        "phases": {name: {"calls": 1, "succeeded": 1, "nanoseconds": 10} for name in PHASES},
        "socket_opened": 1,
        "socket_count_complete": True,
        "overflow": False,
        "span_semantics": "inclusive_do_not_sum",
        "headline_timing_eligible": False,
    }


def resident_record(*, digest="a" * 64, sequence=1):
    return {
        "schema": "hol-guard.native-resident-profile.v1",
        "sequence": sequence,
        "generation": 1,
        "process_id": 123,
        "request_sha256": digest,
        "dispatch_encode_nanoseconds": 60,
        "edge_evaluation": {"calls": 1, "succeeded": 1, "nanoseconds": 40},
        "outcome": "success",
        "overflow": False,
        "span_semantics": "inclusive_do_not_sum",
        "headline_timing_eligible": False,
    }
