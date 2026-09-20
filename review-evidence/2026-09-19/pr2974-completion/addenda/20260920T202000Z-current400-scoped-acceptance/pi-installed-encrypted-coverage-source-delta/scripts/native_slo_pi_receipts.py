"""Bounded, exact-forwarding receipt evidence for the registered Pi callbacks."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections.abc import Mapping
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from codex_plugin_scanner.guard.runtime.hook_payload_reference import hydrate_hook_payload_reference
from scripts.native_slo_mixed_witness import writer_drained
from scripts.native_slo_pi_sources import PiSourceCase


def _frozen_payload(payload: object) -> dict[str, Any] | None:
    """Copy only bounded JSON data; optional observation must not alter forwarding."""
    budget = 65_536

    def copy_value(value: object, depth: int) -> Any:
        nonlocal budget
        budget -= 1
        if budget < 0 or depth > 8:
            raise ValueError("installed_pi_capture_bound")
        if value is None or type(value) in (bool, int, float):
            return value
        if type(value) is str:
            budget -= len(value)
            if budget < 0:
                raise ValueError("installed_pi_capture_bound")
            return value
        if type(value) is dict and len(value) <= 64 and all(type(key) is str for key in value):
            return {copy_value(key, depth + 1): copy_value(child, depth + 1) for key, child in value.items()}
        if type(value) is list and len(value) <= 64:
            return [copy_value(child, depth + 1) for child in value]
        raise ValueError("installed_pi_capture_shape")

    try:
        result = copy_value(payload, 0)
        # Reject nonfinite numbers as the real JSON boundary does.
        json.dumps(result, allow_nan=False)
        return result if type(result) is dict else None
    except Exception:
        return None


class PiReceipts:
    def __init__(self, daemon: Any, cases: tuple[PiSourceCase, ...], *, installed_rule_digest: str) -> None:
        if (
            type(installed_rule_digest) is not str
            or len(installed_rule_digest) != 64
            or any(char not in "0123456789abcdef" for char in installed_rule_digest)
        ):
            raise ValueError("installed_pi_rule_identity_invalid")
        self.installed_rule_digest = installed_rule_digest
        self.daemon = daemon
        self.cases = {case.correlation: case for case in cases}
        self.ordered = cases
        self.offered = 0
        if len(self.cases) != len(cases) or not 1 <= len(cases) <= 10:
            raise ValueError("installed_pi_receipt_cohort")
        self.rows: dict[str, dict[str, Any]] = {}
        self.extra_calls = 0
        self.active_calls = 0
        self.admitted: dict[str, bool] = {}
        self.stack = ExitStack()
        self.lock = threading.Lock()

    def __enter__(self) -> PiReceipts:
        worker = self.daemon._server.hook_worker
        writer = self.daemon._server.runtime_hook_evidence_writer
        review, submit = worker._review_raw_hook_native, writer.submit_native_decision_receipt

        def observed_review(**kwargs: Any) -> Any:
            row: dict[str, Any] | None
            payload = kwargs.get("payload")
            with self.lock:
                self.active_calls += 1
                case = self.ordered[self.offered] if self.offered < len(self.ordered) else None
                self.offered += 1
                if case is None:
                    self.extra_calls += 1
                    row = None
                else:
                    row = {"label": case.label, "entered": True, "returned": False}
                    self.rows[case.label] = row
            snapshot = kwargs.get("policy_snapshot")
            binding_keys = ("generation", "policy_digest", "runtime_identity", "mode")
            binding = {key: snapshot.get(key) for key in binding_keys} if isinstance(snapshot, Mapping) else None
            entry_payload = _frozen_payload(payload)
            try:
                try:
                    result = review(**kwargs)
                except BaseException:
                    if row is not None:
                        row["raised"] = True
                    raise
                if row is not None:
                    row["returned"] = True
                    try:
                        receipt = validate_native_decision_receipt(
                            result.get("receipt") if isinstance(result, dict) else None
                        )
                        row["receipt"] = copy.deepcopy(receipt)
                        row["entry_payload_unchanged"] = entry_payload is not None and entry_payload == _frozen_payload(
                            payload
                        )
                        entry_reference = entry_payload.get("guard_payload_ref") if entry_payload is not None else None
                        entry_digest = entry_reference.get("sha256") if isinstance(entry_reference, dict) else None
                        row["entry_encrypted_payload_sha256"] = (
                            entry_digest
                            if (
                                isinstance(entry_digest, str)
                                and len(entry_digest) == 64
                                and all(character in "0123456789abcdef" for character in entry_digest)
                            )
                            else None
                        )
                        row["ack_binding"] = binding
                        row["edge_binding_valid"] = isinstance(result, dict) and receipt_matches_edge(result, receipt)
                        row["ack_binding_valid"] = (
                            receipt is not None
                            and isinstance(snapshot, Mapping)
                            and binding == {key: snapshot.get(key) for key in binding_keys}
                            and receipt["policy_generation"] == snapshot.get("generation")
                            and receipt["policy_digest"] == snapshot.get("policy_digest")
                            and receipt["runtime_identity"] == snapshot.get("runtime_identity")
                            and snapshot.get("mode") == "enforce"
                        )
                        # The admitted installed capabilities own the rule digest.
                        # The production compact ACK intentionally omits that field.
                        row["installed_rule_digest"] = self.installed_rule_digest
                        row["installed_rule_binding_valid"] = (
                            receipt is not None and receipt["rule_digest"] == self.installed_rule_digest
                        )
                        # Read only after the real native call. This is diagnostic
                        # observation, never an input to the native decision. The Node
                        # callback still owns the live encrypted reference until return.
                        observed_payload = (
                            hydrate_hook_payload_reference(entry_payload) if entry_payload is not None else {}
                        )
                        row["request_binding_valid"] = (
                            case is not None
                            and observed_payload.get("tool_call_id") == case.correlation
                            and observed_payload.get("tool_input") == case.arguments
                            and kwargs.get("harness") == case.harness
                            and kwargs.get("event") == ("PreToolUse" if case.event == "tool_call" else "PostToolUse")
                        )
                        if case is not None and case.event == "tool_result":
                            reference = observed_payload.get("guard_source_ref")
                            row["request_binding_valid"] = row["request_binding_valid"] and (
                                isinstance(reference, Mapping)
                                and reference.get("path") == case.arguments["file_path"]
                                and reference.get("tool_input_path") == case.arguments["file_path"]
                                and reference.get("output_sha256") == hashlib.sha256(case.output.encode()).hexdigest()
                                and reference.get("output_chars") == len(case.output)
                            )
                            row["source_payload_kind"] = (
                                "encrypted_payload_ref"
                                if entry_payload is not None and "guard_payload_ref" in entry_payload
                                else "source_file_ref"
                            )
                            row["request_binding_valid"] = row["request_binding_valid"] and (
                                receipt is not None and receipt["payload_kind"] == row["source_payload_kind"]
                            )
                    except Exception:
                        row["observation_failed"] = True
                return result
            finally:
                with self.lock:
                    self.active_calls -= 1

        def observed_submit(*args: Any, **kwargs: Any) -> Any:
            result = submit(*args, **kwargs)
            receipt = kwargs.get("receipt", args[0] if args else None)
            identity = receipt.get("decision_id") if isinstance(receipt, Mapping) else None
            if isinstance(identity, str):
                with self.lock:
                    if identity in self.admitted or len(self.admitted) >= len(self.cases):
                        self.extra_calls += 1
                    else:
                        self.admitted[identity] = result is True
            return result

        try:
            self.stack.enter_context(patch.object(worker, "_review_raw_hook_native", observed_review))
            self.stack.enter_context(patch.object(writer, "submit_native_decision_receipt", observed_submit))
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        self.stack.close()

    def reconcile(self) -> dict[str, object]:
        writer = self.daemon._server.runtime_hook_evidence_writer
        deadline = time.monotonic() + 5.0
        while True:
            with writer._condition:
                drained = writer_drained({**writer.stats(), "in_flight": writer._in_flight})
            if drained or time.monotonic() >= deadline:
                break
            time.sleep(0.025)
        self.close()
        with self.lock:
            rows = copy.deepcopy(self.rows)
            admitted = dict(self.admitted)
            active = self.active_calls
        complete = drained and not active and self.extra_calls == 0 and len(rows) == len(self.cases)
        for case in self.cases.values():
            row = rows.get(case.label)
            if row is None:
                complete = False
                continue
            receipt = row.get("receipt")
            if not isinstance(receipt, dict):
                complete = False
                continue
            committed = self.daemon._server.store.get_native_decision_receipt(receipt["decision_id"])
            row["committed_receipt"] = committed
            row["writer_admitted"] = admitted.get(receipt["decision_id"]) is True
            row["receipt_checks"] = (
                row.get("returned") is True
                and row.get("edge_binding_valid") is True
                and row.get("ack_binding_valid") is True
                and row.get("installed_rule_binding_valid") is True
                and row.get("request_binding_valid") is True
                and row.get("entry_payload_unchanged") is True
                and row["writer_admitted"]
                and committed == receipt
                and receipt["harness"] == case.harness
                and receipt["event_name"] == ("PreToolUse" if case.event == "tool_call" else "PostToolUse")
                and receipt["decision"] == case.decision
                and receipt["policy_action"] == ("allow" if case.decision == "allow" else "block")
                and receipt["observe_mode"] is False
                and (case.reason is None or receipt["reason_code"] == case.reason)
            )
            complete = complete and row["receipt_checks"]
        return {
            "complete": complete,
            "writer_drained": drained,
            "extra_calls": self.extra_calls,
            "active_calls": active,
            "rows": rows,
        }
