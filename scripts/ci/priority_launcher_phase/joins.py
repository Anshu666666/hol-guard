"""Join only closed, uniquely identified records from the same 88-call block."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, cast

from .capture import _STAGE_NAMES, MAX_REPORT_BYTES, MAX_ROWS, MAX_STAGES, finite_milliseconds
from .projection import _pairs, declared_coordinates
from .schema import _DAEMON_FACTS, _DAEMON_KEYS, _ERROR_KINDS, _EVENT_FIELDS, _PARENT_FACTS, _REPORT_KEYS

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_COORDINATES = {tuple(value.values()) for value in declared_coordinates()}


def _fact_value(key: str, value: Any) -> None:
    if key in {"identity", "edge_identity"}:
        if value is None:
            return
        _require(
            type(value) is dict
            and set(value)
            == {
                "request_id",
                "request_digest",
                "decision_id",
                "harness",
                "event",
            },
            "identity_fields",
        )
        value = cast(dict[str, Any], value)
        _require(_digest(value["request_digest"]) and _digest(value["decision_id"]), "identity_digest")
        _require(
            type(value["request_id"]) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,255}", value["request_id"]) is not None,
            "request_id",
        )
        _require(
            (value["harness"], value["event"]) in {(item["harness"], item["event"]) for item in declared_coordinates()},
            "identity_route",
        )
    elif key.endswith("_sha256"):
        _require(_digest(value), "digest")
    elif key == "returncode" and value is None:
        return
    elif key.endswith("_bytes") or key in {"pid", "returncode"}:
        _require(type(value) is int and -(2**31) <= value < 2**31, "integer_fact")
    elif key == "launcher_latency_ms":
        _require(value is None or finite_milliseconds(value) is not None, "latency")
    elif key == "error_kind":
        _require(value in _ERROR_KINDS, "error_kind")
    elif key == "original_route":
        _require(value == "pending_batch_validation", "original_route")
    elif key == "edge_decision":
        _require(value in {None, "allow", "deny"}, "decision")
    else:
        _require(value is None or type(value) is bool, "boolean_fact")


def _facts(value: dict[str, Any]) -> None:
    for key, item in value.items():
        if key in _EVENT_FIELDS:
            _require(type(item) is list and len(item) <= MAX_STAGES, "event_list")
            for event in item:
                _require(type(event) is dict and not set(event) - _EVENT_FIELDS[key], "event_fields")
                event = cast(dict[str, Any], event)
                for field, content in event.items():
                    _fact_value(field, content)
        else:
            _fact_value(key, item)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError("phase_evidence_" + code)


def _bounded(value: Any, depth: int = 0) -> None:
    _require(depth <= 12, "depth")
    if type(value) is dict:
        _require(len(value) <= 40, "keys")
        for key, item in value.items():
            _require(type(key) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) is not None, "key")
            _bounded(item, depth + 1)
    elif type(value) is list:
        _require(len(value) <= MAX_ROWS, "list")
        for item in value:
            _bounded(item, depth + 1)
    elif type(value) is str:
        _require(len(value) <= 256 and not any(ord(char) < 32 for char in value), "string")
    elif type(value) in (int, float):
        _require(math.isfinite(value) and -(2**63) <= value < 2**63, "number")
    else:
        _require(value is None or type(value) is bool, "scalar")


def read_report_document(path: Path) -> tuple[dict[str, Any], dict[str, object]]:
    """Read once and bind the exact bytes separately from parsed JSON."""
    with path.open("rb") as stream:
        encoded = stream.read(MAX_REPORT_BYTES + 1)
    _require(len(encoded) <= MAX_REPORT_BYTES, "bytes")
    value = json.loads(encoded, object_pairs_hook=_pairs)
    _require(type(value) is dict, "object")
    _bounded(value)
    return value, {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def read_report(path: Path) -> dict[str, Any]:
    return read_report_document(path)[0]


def coordinate(value: object) -> tuple[Any, ...] | None:
    if type(value) is not dict or set(value) != {"harness", "event", "sample", "case"}:
        return None
    if type(value["sample"]) is not int:
        return None
    result = tuple(value[key] for key in ("harness", "event", "sample", "case"))
    return result if result in _COORDINATES else None


def _one(facts: dict[str, Any], key: str) -> dict[str, Any] | None:
    values = facts.get(key)
    return values[0] if type(values) is list and len(values) == 1 and type(values[0]) is dict else None


def _digest(value: object) -> bool:
    return type(value) is str and _HEX.fullmatch(value) is not None


def _report(value: dict[str, Any], side: str) -> list[dict[str, Any]]:
    _bounded(value)
    extra = _DAEMON_KEYS if side == "daemon" else set()
    _require(set(value) >= _REPORT_KEYS and not set(value) - (_REPORT_KEYS | extra), "report_fields")
    _require(value["schema"] == "hol-guard.priority-launcher-phases.v1" and value["side"] == side, "schema")
    _require(value["qualification_eligible"] is False, "scope")
    for key in (
        "started",
        "completed",
        "in_flight",
        "capture_faults",
        "row_overflow",
        "stage_overflow",
        "restore_failures",
    ):
        _require(type(value[key]) is int and value[key] >= 0, "count")
    for key in ("original_success", "tail_complete", "observation_complete"):
        _require(type(value[key]) is bool, "flag")
    rows = value["rows"]
    _require(type(rows) is list and len(rows) <= MAX_ROWS and value["started"] == len(rows), "rows")
    rows = cast(list[dict[str, Any]], rows)
    for index, row in enumerate(rows):
        _require(
            type(row) is dict
            and set(row)
            == {
                "row_index",
                "coordinate",
                "outcome",
                "completed",
                "facts",
                "stages",
            },
            "row_fields",
        )
        row = cast(dict[str, Any], row)
        _require(type(row["row_index"]) is int and row["row_index"] == index, "row_order")
        _require(type(row["completed"]) is bool and row["outcome"] in {"return", "exception", "in_flight"}, "outcome")
        _require(row["completed"] == (row["outcome"] != "in_flight"), "completion")
        facts = row["facts"]
        allowed = _PARENT_FACTS if side == "parent" else _DAEMON_FACTS
        _require(type(facts) is dict and not set(facts) - allowed, "facts")
        _facts(cast(dict[str, Any], facts))
        stages = row["stages"]
        _require(type(stages) is list and len(stages) <= MAX_STAGES, "stages")
        stages = cast(list[dict[str, Any]], stages)
        seen: set[int] = set()
        for stage in stages:
            _require(
                type(stage) is dict
                and set(stage)
                == {
                    "stage",
                    "index",
                    "occurrence",
                    "parent_index",
                    "start_ns",
                    "end_ns",
                    "duration_ms",
                    "outcome",
                    "error_kind",
                },
                "stage_fields",
            )
            stage = cast(dict[str, Any], stage)
            _require(
                type(stage["index"]) is int and 0 <= stage["index"] < MAX_STAGES and stage["index"] not in seen,
                "stage_index",
            )
            seen.add(stage["index"])
            _require(stage["stage"] in _STAGE_NAMES and stage["error_kind"] in _ERROR_KINDS, "stage_label")
            _require(stage["outcome"] in {"return", "exception"}, "stage_outcome")
            _require((stage["outcome"] == "return") == (stage["error_kind"] is None), "stage_error")
            _require(type(stage["occurrence"]) is int and stage["occurrence"] >= 0, "occurrence")
            start, end = stage["start_ns"], stage["end_ns"]
            _require(type(start) is int and type(end) is int and 0 <= start <= end, "clock")
            _require(stage["duration_ms"] == (end - start) / 1_000_000, "duration")
            parent = stage["parent_index"]
            _require(parent is None or (type(parent) is int and 0 <= parent < stage["index"]), "stage_parent")
        _require(seen == set(range(len(stages))), "stage_index_sequence")
        indexed = {stage["index"]: stage for stage in stages}
        occurrences: Counter[str] = Counter()
        for stage in sorted(stages, key=lambda item: item["index"]):
            label = stage["stage"]
            _require(stage["occurrence"] == occurrences[label], "stage_occurrence_sequence")
            occurrences[label] += 1
            parent = stage["parent_index"]
            if parent is not None:
                _require(parent in indexed, "stage_parent_missing")
                ancestor = indexed[parent]
                _require(
                    ancestor["start_ns"] <= stage["start_ns"] <= stage["end_ns"] <= ancestor["end_ns"],
                    "stage_parent_interval",
                )
    _require(value["completed"] == sum(row["completed"] for row in rows), "completed_count")
    _require(value["in_flight"] == len(rows) - value["completed"], "in_flight_count")
    expected_complete = (
        value["original_success"]
        and all(row["completed"] and coordinate(row["coordinate"]) is not None for row in rows)
        and not any(value[key] for key in ("capture_faults", "row_overflow", "stage_overflow", "restore_failures"))
    )
    _require(value["observation_complete"] == expected_complete, "complete_claim")
    _require(value["tail_complete"] == (value["original_success"] and not value["in_flight"]), "tail_claim")
    return rows


def interval_union_ms(stages: list[dict[str, Any]]) -> float:
    """Union only timestamps from one process/row; nested intervals are not added."""
    intervals = sorted((stage["start_ns"], stage["end_ns"]) for stage in stages)
    total = 0
    left = right = None
    for start, end in intervals:
        if right is None or start > right:
            if right is not None and left is not None:
                total += right - left
            left, right = start, end
        else:
            right = max(right, end)
    if right is not None and left is not None:
        total += right - left
    return total / 1_000_000


def _native_join(facts: dict[str, Any]) -> dict[str, object]:
    encoded = _one(facts, "encoded_envelopes")
    exchange = _one(facts, "native_exchanges")
    decoded = _one(facts, "decoded_edges")
    edge = _one(facts, "native_edges")
    submit = _one(facts, "receipt_submissions")
    envelope_match = bool(
        encoded
        and exchange
        and _digest(encoded.get("envelope_sha256"))
        and encoded.get("envelope_sha256") == exchange.get("envelope_sha256")
        and encoded.get("envelope_bytes") == exchange.get("envelope_bytes")
    )
    identity = decoded.get("edge_identity") if decoded else None
    receipt_match = bool(
        decoded
        and edge
        and submit
        and type(identity) is dict
        and decoded.get("original_decoder_accepted") is True
        and edge.get("edge_identity") == identity == submit.get("identity")
        and submit.get("accepted") is True
        and submit.get("exception") is False
    )
    return {
        "envelope_match": envelope_match,
        "validated_receipt_identity_match": receipt_match,
        "reply_available": bool(exchange and exchange.get("reply_available") is True),
        "native_edge_returned_none": bool(
            edge and edge.get("exception") is False and edge.get("edge_returned") is False
        ),
        "decoded_edge_present": decoded is not None,
        "receipt_submission_present": submit is not None,
        "native_stages_complete": bool(
            envelope_match
            and receipt_match
            and exchange
            and exchange.get("reply_available") is True
            and not exchange.get("exception")
            and not cast(dict[str, Any], edge).get("exception")
        ),
    }


def join_reports(parent: dict[str, Any], daemon: dict[str, Any]) -> dict[str, Any]:
    parents, daemons = _report(parent, "parent"), _report(daemon, "daemon")
    parent_counts = Counter(coordinate(row["coordinate"]) for row in parents)
    daemon_counts = Counter(coordinate(row["coordinate"]) for row in daemons)
    daemon_by_key = {coordinate(row["coordinate"]): row for row in daemons}
    joined: list[dict[str, object]] = []
    for row in parents:
        key = coordinate(row["coordinate"])
        target = daemon_by_key.get(key)
        unique = key is not None and parent_counts[key] == daemon_counts[key] == 1 and target is not None
        facts = row["facts"]
        process = _one(facts, "process_calls")
        semantic_match = bool(
            unique
            and process
            and target
            and _digest(process.get("semantic_sha256"))
            and process["semantic_sha256"] == target["facts"].get("semantic_sha256")
        )
        worker = _one(target["facts"], "worker_reviews") if target else None
        parent_stages = Counter(item["stage"] for item in row["stages"])
        daemon_stages = Counter(item["stage"] for item in target["stages"]) if target else Counter()
        edge = _one(target["facts"], "decoded_edges") if target else None
        identity = edge.get("edge_identity") if edge else None
        native = _native_join(target["facts"]) if target else {"native_stages_complete": False}
        checks = {
            "unique_coordinate": unique,
            "semantic_match": semantic_match,
            "original_parent_returned": row["outcome"] == "return",
            "original_expected_verdict": type(facts.get("original_allowed")) is bool
            and key is not None
            and (facts["original_allowed"] == (key[3] == "benign")),
            "parent_stage_coverage": all(
                parent_stages[name] == 1
                for name in (
                    "contained_process_call",
                    "spawn",
                    "io_setup",
                    "wait_and_reap",
                    "io_join_and_containment",
                )
            ),
            "daemon_stage_coverage": all(
                daemon_stages[name] == 1
                for name in (
                    "hook_handler",
                    "admission_policy",
                    "scheduler_acquire",
                    "worker_review",
                    "native_edge",
                    "runtime_status",
                    "encode_envelope",
                    "native_client_exchange",
                    "native_client_lease",
                    "decode_edge",
                    "receipt_submit",
                )
            )
            and daemon_stages["workspace_policy"] == 2,
            "native_identity_matches_coordinate": bool(
                type(identity) is dict
                and key is not None
                and (identity.get("harness"), identity.get("event")) == key[:2]
            ),
            "original_handler_returned": bool(target and target["outcome"] == "return"),
            "worker_entry_match": bool(worker and worker.get("entry_match") is True),
            "input_unchanged_within_handler": bool(
                target
                and target["facts"].get("exit_projection_valid") is True
                and target["facts"].get("mutation_detected") is False
            ),
            "original_process_valid": bool(
                process
                and process.get("returncode") == 0
                and process.get("timed_out") is False
                and process.get("containment_failed") is False
                and process.get("output_limit_exceeded") is False
            ),
            **native,
        }
        joined.append(
            {
                "coordinate": row["coordinate"],
                "parent_row": row["row_index"],
                "daemon_row": target["row_index"] if unique and target else None,
                "launcher_latency_ms": finite_milliseconds(facts.get("launcher_latency_ms")),
                "parent_observed_interval_union_ms": interval_union_ms(row["stages"]),
                "daemon_observed_interval_union_ms": interval_union_ms(target["stages"]) if unique and target else None,
                "checks": checks,
                "complete": all(
                    checks[name] is True
                    for name in (
                        "unique_coordinate",
                        "semantic_match",
                        "original_parent_returned",
                        "original_handler_returned",
                        "worker_entry_match",
                        "input_unchanged_within_handler",
                        "original_process_valid",
                        "native_stages_complete",
                        "original_expected_verdict",
                        "parent_stage_coverage",
                        "daemon_stage_coverage",
                        "native_identity_matches_coordinate",
                    )
                ),
            }
        )
    complete = (
        parent["observation_complete"] is True
        and daemon["observation_complete"] is True
        and len(parents) == len(daemons) == len(joined) == 88
        and set(parent_counts) == set(daemon_counts) == _COORDINATES
        and all(item["complete"] is True for item in joined)
    )
    return {
        "schema": "hol-guard.priority-launcher-phase-joins.v1",
        "rows": joined,
        "parent_rows": len(parents),
        "daemon_rows": len(daemons),
        "unknown_parent_coordinates": parent_counts.get(None, 0),
        "unknown_daemon_coordinates": daemon_counts.get(None, 0),
        "duplicate_parent_coordinates": sum(count - 1 for count in parent_counts.values() if count > 1),
        "duplicate_daemon_coordinates": sum(count - 1 for count in daemon_counts.values() if count > 1),
        "observation_complete": complete,
        "qualification_eligible": False,
        "cross_process_clock_subtraction": False,
        "interval_scope": "inclusive local-process intervals; union per row, no cross-process residual",
    }
