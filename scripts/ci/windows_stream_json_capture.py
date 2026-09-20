"""Failure-only JSON shape facts for an original native request and response.

Only fixed labels, lengths, counts and SHA-256 digests leave this observer.
Python syntax and structural checks are evidence, not Rust parser equivalence.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from collections.abc import Mapping
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

MAX_BYTES = 6 * 1024 * 1024
MAX_FAILURES = 4
MAX_NODES = 65_536
_ERROR_RESPONSES = frozenset(
    b'{"error":"native_request_invalid_json","retryable":' + retry + b"}" for retry in (b"false", b"true")
)


def json_shape(payload: bytes) -> dict[str, Any]:
    """Inspect bounded bytes after failure without exporting values or names."""
    result: dict[str, Any] = {
        "byte_count": min(len(payload), MAX_BYTES + 1),
        "byte_bound_met": len(payload) <= MAX_BYTES,
        "sha256": None,
        "utf8_valid": False,
        "json_syntax_valid": False,
        "duplicate_keys": False,
        "finite_numbers": True,
        "root_object": False,
        "maximum_depth": 0,
        "maximum_collection_items": 0,
        "maximum_string_bytes": 0,
        "maximum_key_bytes": 0,
        "nodes_observed": 0,
        "node_bound_met": True,
        "decoded_strings_utf8_valid": True,
        "recorded_structural_bounds_met": False,
        "rust_parser_equivalence_claim": False,
        "hook_schema_validation_claim": False,
    }
    if not result["byte_bound_met"]:
        return result
    result["sha256"] = hashlib.sha256(payload).hexdigest()
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return result
    result["utf8_valid"] = True

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value = dict(items)
        result["duplicate_keys"] |= len(value) != len(items)
        result["maximum_collection_items"] = max(result["maximum_collection_items"], len(items))
        return value

    def constant(_value: str) -> None:
        result["finite_numbers"] = False

    try:
        root = json.loads(decoded, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError):
        return result
    result["json_syntax_valid"] = result["finite_numbers"]
    result["root_object"] = type(root) is dict
    pending: list[tuple[object, int]] = [(root, 0)]
    while pending:
        if result["nodes_observed"] >= MAX_NODES:
            result["node_bound_met"] = False
            break
        value, depth = pending.pop()
        result["nodes_observed"] += 1
        result["maximum_depth"] = max(result["maximum_depth"], depth)
        if type(value) is str:
            try:
                length = len(value.encode("utf-8", errors="strict"))
                result["maximum_string_bytes"] = max(result["maximum_string_bytes"], length)
            except UnicodeEncodeError:
                result["decoded_strings_utf8_valid"] = False
        elif type(value) is float:
            result["finite_numbers"] &= math.isfinite(value)
        elif isinstance(value, (dict, list)):
            result["maximum_collection_items"] = max(result["maximum_collection_items"], len(value))
            if isinstance(value, dict):
                for key in value:
                    try:
                        length = len(key.encode("utf-8", errors="strict"))
                        result["maximum_key_bytes"] = max(result["maximum_key_bytes"], length)
                    except UnicodeEncodeError:
                        result["decoded_strings_utf8_valid"] = False
                children = value.values()
            else:
                children = value
            room = MAX_NODES - result["nodes_observed"] - len(pending)
            if len(value) > room:
                result["node_bound_met"] = False
                break
            pending.extend((child, depth + 1) for child in children)
    result["recorded_structural_bounds_met"] = bool(
        result["node_bound_met"]
        and result["decoded_strings_utf8_valid"]
        and result["finite_numbers"]
        and not result["duplicate_keys"]
        and result["maximum_depth"] <= 32
        and result["maximum_collection_items"] <= 4096
        and result["maximum_string_bytes"] <= 1024 * 1024
        and result["maximum_key_bytes"] <= 1024 * 1024
    )
    return result


class InvalidJsonCapture:
    """Forward once; record only the original fixed native invalid-JSON reply."""

    def __init__(self, edge_module: Any) -> None:
        self.edge = edge_module
        self.original = edge_module.native_resident_client_request
        self.stack = ExitStack()
        self.lock = threading.Lock()
        self.rows: list[dict[str, object]] = []
        self.dropped = 0
        self.faults = 0
        self.restored = False

    def observed(self, *args: Any, **kwargs: Any) -> Any:
        response = self.original(*args, **kwargs)
        try:
            if type(response) is bytes and response in _ERROR_RESPONSES:
                payload = kwargs.get("payload")
                if type(payload) is not bytes:
                    self.faults += 1
                elif len(self.rows) >= MAX_FAILURES:
                    self.dropped += 1
                else:
                    row: dict[str, object] = {
                        "response_code": "native_request_invalid_json",
                        "response_bytes": len(response),
                        "response_sha256": hashlib.sha256(response).hexdigest(),
                        "request": json_shape(payload),
                    }
                    if self.lock.acquire(blocking=False):
                        try:
                            if len(self.rows) < MAX_FAILURES:
                                self.rows.append(row)
                            else:
                                self.dropped += 1
                        finally:
                            self.lock.release()
                    else:
                        self.dropped += 1
        except Exception:
            self.faults += 1
        return response

    def __enter__(self) -> InvalidJsonCapture:
        self.stack.enter_context(patch.object(self.edge, "native_resident_client_request", self.observed))
        return self

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
        self.restored = self.edge.native_resident_client_request is self.original

    def report(self, stream_report: Mapping[str, Any]) -> dict[str, Any]:
        joins: list[dict[str, object]] = []
        for row in self.rows:
            shape = row["request"]
            assert isinstance(shape, dict)
            calls = [
                call
                for call in stream_report.get("calls", ())
                if call.get("payload_sha256") == shape["sha256"]
                and call.get("payload_bytes") == shape["byte_count"]
                and call.get("response_sha256") == row["response_sha256"]
                and call.get("response_bytes") == row["response_bytes"]
            ]
            frames = []
            for process in stream_report.get("processes", ()):
                for frame in process.get("records", ()):
                    native = frame.get("report")
                    if (
                        isinstance(native, dict)
                        and native.get("payload_sha256") == shape["sha256"]
                        and native.get("payload_bytes") == shape["byte_count"]
                        and frame.get("response_sha256") == row["response_sha256"]
                        and frame.get("response_bytes") == row["response_bytes"]
                    ):
                        frames.append(
                            {"process_index": process["process_index"], "frame_sequence": frame["frame_sequence"]}
                        )
            joins.append(
                {
                    "matching_python_calls": len(calls),
                    "matching_native_frames": frames,
                    "unambiguous_original_request_join": len(calls) == len(frames) == 1
                    and calls[0]["process_index"] == frames[0]["process_index"],
                }
            )
        return {
            "schema": "hol-guard.windows-invalid-json-caller.v1",
            "scope": "post_return_fixed_error_only_original_native_hook_request",
            "maximum_failures": MAX_FAILURES,
            "maximum_request_bytes": MAX_BYTES,
            "maximum_json_nodes": MAX_NODES,
            "failures": list(self.rows),
            "joins": joins,
            "dropped_failures": self.dropped,
            "collector_faults": self.faults,
            "provider_restored": self.restored,
            "observation_complete": not (self.dropped or self.faults)
            and self.restored
            and all(join["unambiguous_original_request_join"] for join in joins),
            "failure_reproduced": bool(self.rows),
            "original_results_preserved": True,
            "requests_or_retries_added": False,
            "deadlines_changed": False,
            "qualification": False,
            "headline_timing_eligible": False,
        }
