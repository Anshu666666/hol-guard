"""Closed resident-emitted attribution, separate from the v1 client records."""

from __future__ import annotations

import re
from typing import Any

from scripts.native_client_profile_records import count, require
from scripts.native_slo_contract import summarize


def validate_resident_record(value: Any) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "sequence",
            "generation",
            "process_id",
            "request_sha256",
            "dispatch_encode_nanoseconds",
            "edge_evaluation",
            "outcome",
            "overflow",
            "span_semantics",
            "headline_timing_eligible",
        }
    )
    require(value["schema"] == "hol-guard.native-resident-profile.v1")
    require(count(value["sequence"], 1024) > 0)
    require(count(value["generation"]) > 0 and count(value["process_id"], (1 << 32) - 1) > 0)
    require(
        isinstance(value["request_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["request_sha256"]) is not None
    )
    total = value["dispatch_encode_nanoseconds"]
    require(total is None or count(total) >= 0)
    edge = value["edge_evaluation"]
    require(isinstance(edge, dict) and set(edge) == {"calls", "succeeded", "nanoseconds"})
    require(count(edge["succeeded"], 1) <= count(edge["calls"], 1))
    require((edge["nanoseconds"] is None) == (edge["calls"] == 0))
    if edge["calls"]:
        count(edge["nanoseconds"])
    require(value["outcome"] in {"success", "rejected", "panicked"})
    require(type(value["overflow"]) is bool)
    require(value["span_semantics"] == "inclusive_do_not_sum" and value["headline_timing_eligible"] is False)
    return value


def require_evaluated(record: dict[str, Any]) -> None:
    require(not record["overflow"] and record["outcome"] == "success")
    require(record["dispatch_encode_nanoseconds"] is not None)
    edge = record["edge_evaluation"]
    require(edge["calls"] == edge["succeeded"] == 1 and edge["nanoseconds"] is not None)
    require(edge["nanoseconds"] <= record["dispatch_encode_nanoseconds"])


def validate_relay_record(value: Any) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "parent_process_id",
            "child_process_id",
            "records",
            "complete",
        }
    )
    require(value["schema"] == "hol-guard.native-resident-profile-relay.v1")
    require(count(value["parent_process_id"], (1 << 32) - 1) > 0)
    count(value["child_process_id"], (1 << 32) - 1)
    count(value["records"], 2048)
    require(type(value["complete"]) is bool)
    return value


def validate_relay_chains(
    helpers: dict[int, int], residents: list[dict[str, Any]], relays: list[dict[str, Any]]
) -> None:
    """Prove EOF/counts for each actual helper -> supervisor -> resident pipe."""
    resident_processes = {(item["helper"], item["resident_profile"]["process_id"]) for item in residents}
    require(bool(resident_processes))
    require(len(relays) == 2 * len(resident_processes))
    used: set[int] = set()
    for helper, process in resident_processes:
        second = [
            (i, x["relay"])
            for i, x in enumerate(relays)
            if x["helper"] == helper and x["relay"]["child_process_id"] == process
        ]
        require(len(second) == 1)
        index, child = second[0]
        first = [
            (i, x["relay"])
            for i, x in enumerate(relays)
            if x["helper"] == helper
            and x["relay"]["child_process_id"] == child["parent_process_id"]
            and x["relay"]["parent_process_id"] == helpers.get(helper)
        ]
        require(len(first) == 1)
        first_index, parent = first[0]
        require(index != first_index and index not in used and first_index not in used)
        used.update((index, first_index))
        count_records = sum(x["helper"] == helper and x["resident_profile"]["process_id"] == process for x in residents)
        require(child["complete"] and parent["complete"])
        require(child["records"] == count_records and parent["records"] == count_records + 1)


def summarize_resident_profiles(records: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for case in ("benign", "secret"):
        selected = [item["resident_profile"] for item in records if item["case"] == case]
        result["benign" if case == "benign" else "credential_fixture"] = {
            "count": len(selected),
            "edge_evaluation_ms": summarize([p["edge_evaluation"]["nanoseconds"] / 1e6 for p in selected])
            if selected
            else None,
            "dispatch_encode_ms": summarize([p["dispatch_encode_nanoseconds"] / 1e6 for p in selected])
            if selected
            else None,
        }
    return result
