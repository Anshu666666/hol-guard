"""Observe already executed Codex completion lines without re-evaluating authority.

This private diagnostic never changes a deadline or interprets a grouped return
as a unique cause. Only exact built-in scalar projections leave the call frame.
"""

from __future__ import annotations

import hashlib
import sys
import threading
from pathlib import Path
from types import CodeType, FrameType, FunctionType
from typing import Any

SOURCE_SHA256 = "d3a9356754d1bde5c42143317871311ae57ed2fb9c318ee367ba7ebf7ca40d96"
MAX_CALLS = 8
MAX_EVENTS = 384
RETURN_GROUPS = {
    108: "request_shape_or_kind",
    110: "resolved_block_forwarding",
    114: "resolution_state",
    125: "input_home_mode_or_waiter",
    134: "allow_authority_missing",
    140: "replay_authority_missing",
    143: "snapshot_mode_or_deadline",
    153: "control_fence",
    167: "native_edge_absent",
    181: "native_receipt_binding",
    192: "policy_binding_mismatch",
    196: "stored_request_digest_mismatch",
    198: "artifact_request_digest_mismatch",
    210: "native_floor_waiter_or_deadline",
    230: "final_waiter_or_deadline",
    231: "completed_forwarding",
    233: "caught_original_exception",
}


def _dict(value: object) -> dict[str, Any]:
    return value if type(value) is dict else {}


def _digest(value: object) -> str | None:
    return value if type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value) else None


def _generation(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def _equal(left: object, right: object) -> bool | None:
    return left == right if type(left) in {str, int, bool} and type(right) is type(left) else None


def projected_locals(values: dict[str, Any]) -> dict[str, object]:
    """Copy bounded identity values; never walk arbitrary mappings or payloads."""
    request = _dict(values.get("request"))
    stored = _dict(request.get("action_envelope_json"))
    old_binding = _dict(stored.get("native_review_policy_binding"))
    receipt = _dict(values.get("receipt"))
    snapshot = _dict(values.get("snapshot"))
    binding = _dict(values.get("binding"))
    native = _dict(values.get("result"))
    fresh_request = _digest(receipt.get("request_digest"))
    old_request = _digest(stored.get("native_review_request_digest"))
    artifact = _digest(request.get("artifact_hash"))
    proof: dict[str, object] = {
        "stored_request_digest": old_request,
        "fresh_request_digest": fresh_request,
        "artifact_digest": artifact,
        "request_matches_stored": _equal(fresh_request, old_request),
        "request_matches_artifact": _equal(fresh_request, artifact),
    }
    for label, data in (("stored", old_binding), ("receipt", receipt), ("snapshot", snapshot), ("current", binding)):
        for key in ("policy_digest", "runtime_identity", "control_digest", "catalog_digest"):
            proof[label + "_" + key] = _digest(data.get(key))
        proof[label + "_generation"] = _generation(data.get("policy_generation", data.get("generation")))
    for key in ("policy_action", "minimum_action", "decision"):
        value = native.get(key)
        proof["native_" + key] = value if type(value) is str and value in {"allow", "review", "block", "deny"} else None
    for key in ("allowed", "reviewable", "fenced", "replay"):
        value = values.get(key)
        proof[key] = value if type(value) is bool else None
    return proof


class CallObserver:
    """A finite current-thread trace scoped to one exact original function."""

    def __init__(self, original: Any, helpers: dict[CodeType, str] | None = None, *, source_bound: bool = True):
        if type(original) is not FunctionType:
            raise TypeError("diagnostic_original_function_required")
        self.original = original
        self.code = original.__code__
        self.helpers = helpers or {}
        self.source_bound = source_bound
        self.rows: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.active = 0
        self.overflow = False

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        row: dict[str, Any] = {"events": [], "complete": False, "returned": False, "projection": {}}
        with self.lock:
            if len(self.rows) >= MAX_CALLS:
                self.overflow = True
                admitted = False
            else:
                self.rows.append(row)
                self.active += 1
                admitted = True
        if not admitted:
            return self.original(*args, **kwargs)
        previous = sys.gettrace()
        target_frame: FrameType | None = None
        installed = False
        capture_failed = False

        def trace(frame: FrameType, event: str, arg: Any) -> Any:
            nonlocal target_frame, capture_failed
            try:
                if frame.f_code is self.code:
                    if event == "call":
                        if target_frame is not None:
                            capture_failed = True
                            return None
                        target_frame = frame
                    if frame is not target_frame:
                        return None
                    if event in {"line", "return", "exception"}:
                        if len(row["events"]) >= MAX_EVENTS:
                            capture_failed = True
                            return None
                        row["events"].append({"event": event, "line": frame.f_lineno})
                    if event == "line" and frame.f_lineno in RETURN_GROUPS:
                        row["return_statement_line"] = frame.f_lineno
                    if event == "return":
                        # CPython reports the with-statement's cleanup line for
                        # early returns inside it. Preserve both observations.
                        row["return_event_line"] = frame.f_lineno
                        row["return_group"] = RETURN_GROUPS.get(row.get("return_statement_line", -1), "unmapped_return")
                        row["projection"] = projected_locals(frame.f_locals)
                    return trace
                name = self.helpers.get(frame.f_code)
                if name is not None and frame.f_back is target_frame:
                    if event == "return":
                        if len(row["events"]) >= MAX_EVENTS:
                            capture_failed = True
                        else:
                            row["events"].append(
                                {"event": "helper_return", "helper": name, "value": arg if type(arg) is bool else None}
                            )
                    return trace
            except BaseException:
                capture_failed = True
            return None

        try:
            if previous is None and self.source_bound and self.original.__code__ is self.code:
                try:
                    sys.settrace(trace)
                    installed = True
                except BaseException:
                    capture_failed = True
            else:
                row["refused"] = "existing_trace_or_source_changed"
            result = self.original(*args, **kwargs)
            row["returned"] = True
            return result
        finally:
            if installed:
                try:
                    row["trace_restored"] = sys.gettrace() is trace
                    sys.settrace(previous)
                except BaseException:
                    capture_failed = True
            row["complete"] = bool(
                installed and not capture_failed and row.get("trace_restored") and "return_event_line" in row
            )
            target_frame = None
            with self.lock:
                self.active -= 1

    def report(self) -> dict[str, object]:
        with self.lock:
            # All values were copied to closed scalar/list/dict shapes inside the call.
            import copy

            rows = copy.deepcopy(self.rows)
            active = self.active
        return {
            "schema": "hol-guard.codex-executed-guards.v1",
            "source_bound": self.source_bound,
            "source_sha256": SOURCE_SHA256,
            "calls": rows,
            "active_calls": active,
            "overflow": self.overflow,
            "complete": bool(rows and not active and not self.overflow and all(r["complete"] for r in rows)),
            "instrumented_deadline_unchanged": True,
            "latency_qualified": False,
        }


def production_observer(module: Any) -> CallObserver:
    body = Path(module.__file__).read_bytes()
    bound = hashlib.sha256(body).hexdigest() == SOURCE_SHA256
    original = module.complete_native_codex_live_decision
    bound = bound and (
        type(original) is FunctionType
        and original.__globals__ is module.__dict__
        and original.__name__ == "complete_native_codex_live_decision"
        and original.__code__.co_firstlineno == 90
    )
    helpers = {}
    for name in ("_original_hook_is_live", "native_review_binding_matches"):
        function = getattr(module, name)
        if type(function) is FunctionType:
            helpers[function.__code__] = name
        else:
            bound = False
    return CallObserver(original, helpers, source_bound=bound)


class NativeReturns:
    """Bind initial and fresh observed receipt identities from actual returns."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.active = 0
        self.overflow = False
        self.lock = threading.Lock()

    def wrap(self, original: Any) -> Any:
        def observed(*args: Any, **kwargs: Any) -> Any:
            row: dict[str, Any] = {"entered": True, "returned": False, "captured": False}
            with self.lock:
                admitted = len(self.rows) < MAX_CALLS
                if admitted:
                    self.rows.append(row)
                    self.active += 1
                else:
                    self.overflow = True
            if not admitted:
                return original(*args, **kwargs)
            try:
                try:
                    row["entry_snapshot"] = projected_locals({"snapshot": kwargs.get("policy_snapshot")})
                except BaseException:
                    row["entry_capture_failed"] = True
                result = original(*args, **kwargs)
                row["returned"] = True
                try:
                    edge = _dict(result)
                    row["receipt_identity"] = projected_locals(
                        {"receipt": edge.get("receipt"), "result": edge.get("result")}
                    )
                    row["edge_present"] = type(result) is dict
                    row["captured"] = "entry_capture_failed" not in row
                except BaseException:
                    row["capture_failed"] = True
                return result
            finally:
                with self.lock:
                    self.active -= 1

        return observed

    def report(self) -> dict[str, object]:
        import copy

        with self.lock:
            rows = copy.deepcopy(self.rows)
            return {
                "rows": rows,
                "active_calls": self.active,
                "overflow": self.overflow,
                "complete": bool(rows and not self.active and not self.overflow and all(r["captured"] for r in rows)),
            }
