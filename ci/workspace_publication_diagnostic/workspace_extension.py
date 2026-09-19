"""Transparent forwarding observations used only by the disposable collector.

Production calls receive their original arguments and return their original
objects or exceptions. Observation failures are retained separately and cannot
replace a native verdict. Complete receipt readback happens after the original
collector's bounded drain; it adds no retry and changes no phase deadline.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

from witness_support import RUNTIME_SHA, compact_directory, digest, encoded, error_name, private_directory, require


def install(config: dict[str, Any]) -> None:
    from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
    from scripts.native_slo_mixed_witness import ReceiptWitness
    from scripts.native_slo_session import AdapterSession
    from scripts.native_slo_workspace_server import WORKSPACE_PHASES, WorkspaceScenarioFixture

    original_init = AdapterSession.__init__
    original_enter = ReceiptWitness.__enter__
    original_finish = WorkspaceScenarioFixture.finish

    def initialize(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        root = Path(self.root).resolve()
        parent = Path(config["temporary_parent"]).resolve()
        require(root.parent == parent and root.name.startswith("hol-guard-slo-"), "unexpected_disposable_home")
        private_directory(root)
        require(
            self.daemon._server.hook_worker.policy_snapshot_publisher._thread is None,
            "registration_after_publisher_start",
        )
        compact = compact_directory(self.guard_home)
        require(not os.path.lexists(compact), "preexisting_compact_socket_directory")
        # Private cleanup coordination only; these paths never enter the report.
        descriptor = os.open(config["private_registry"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            data = encoded({"root": str(root), "home": str(self.guard_home), "compact": str(compact)}) + b"\n"
            require(len(data) <= 4096 and os.write(descriptor, data) == len(data), "private_registry_write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def enter(self: Any) -> Any:
        result = original_enter(self)
        self.workspace_full_receipts = {}
        self.workspace_observation_failures = []
        worker = self.session.daemon._server.hook_worker
        original_review = worker._review_raw_hook_native

        def review(**kwargs: Any) -> Any:
            payload = kwargs.get("payload")
            attempt = payload.get("tool_use_id") if isinstance(payload, Mapping) else None
            selected = isinstance(attempt, str) and attempt in {
                f"mixed-policy-{index}" for index in range(len(WORKSPACE_PHASES))
            }
            before = None
            if selected:
                try:
                    before = digest(encoded(payload))
                except Exception as error:
                    self.workspace_observation_failures.append(error_name(error))
            # Preserve the exact call, result object and exception behavior.
            edge = original_review(**kwargs)
            if selected:
                try:
                    after = digest(encoded(payload))
                    receipt = validate_native_decision_receipt(
                        edge.get("receipt") if isinstance(edge, Mapping) else None
                    )
                    require(receipt is not None, "observed_native_receipt_invalid")
                    require(before == after, "forwarded_payload_changed")
                    require(attempt not in self.workspace_full_receipts, "duplicate_forwarded_request_identity")
                    self.workspace_full_receipts[attempt] = {"payload_sha256": before, "receipt": receipt}
                except Exception as error:
                    self.workspace_observation_failures.append(error_name(error))
            return edge

        self._stack.enter_context(patch.object(worker, "_review_raw_hook_native", review))
        return result

    def finish(self: Any) -> dict[str, Any]:
        original = original_finish(self)
        result = dict(original)
        failures = list(getattr(self.witness, "workspace_observation_failures", []))
        rows = []
        for phase in self.phases:
            if not phase.get("first_native_receipt_matches"):
                continue
            try:
                attempt = phase["attempt"]
                observed = self.witness.workspace_full_receipts[attempt]
                receipt = observed["receipt"]
                committed = self.witness.reader.read(phase["decision_id"])
                require(committed == receipt, "complete_committed_receipt_mismatch")
                require(receipt["runtime_identity"] == RUNTIME_SHA, "committed_runtime_mismatch")
                require(receipt["decision_id"] == phase["decision_id"], "committed_decision_mismatch")
                require(
                    receipt["workspace_bound"] is True and receipt["observe_mode"] is False,
                    "committed_workspace_mode_mismatch",
                )
                require(
                    receipt["harness"] == "claude-code" and receipt["event_name"] == "PreToolUse",
                    "committed_route_mismatch",
                )
                binding = phase["binding"]
                require(
                    receipt["policy_generation"] == binding["generation"]
                    and receipt["policy_digest"] == binding["policy_digest"],
                    "committed_policy_mismatch",
                )
                row = self.witness.row(attempt)
                require(
                    row is not None and row["committed"] and row["commit_binding_valid"],
                    "original_commit_witness_missing",
                )
                rows.append(
                    {
                        "phase": phase["phase"],
                        "attempt": attempt,
                        "forwarded_input_sha256": observed["payload_sha256"],
                        "native_request_digest": receipt["request_digest"],
                        "native_request_id_sha256": digest(str(receipt["request_id"]).encode()),
                        "decision_id": receipt["decision_id"],
                        "complete_native_receipt_sha256": digest(encoded(receipt)),
                        "complete_committed_receipt_sha256": digest(encoded(committed)),
                        "runtime_identity": receipt["runtime_identity"],
                        "rule_digest": receipt["rule_digest"],
                        "policy_generation": receipt["policy_generation"],
                        "policy_digest": receipt["policy_digest"],
                        "decision": receipt["decision"],
                        "policy_action": receipt["policy_action"],
                        "extension_binding_sha256": digest(encoded(receipt["command_extensions"])),
                        "native_finished_ms": row["native_finished_ms"],
                        "commit_observed_ms": row["commit_observed_ms"],
                        "accepted_to_commit_observed_ms": row["commit_observed_ms"]
                        - phase["accepted_ms"]
                        - (self.observer.started - self.witness.started) * 1000,
                        "complete_receipt_equal": True,
                    }
                )
            except Exception as error:
                failures.append(error_name(error))
        retained = {
            "registered_workspaces": len(self.workspaces),
            "passed": not failures and len(rows) == len(WORKSPACE_PHASES),
            "rows": rows,
            "failures": failures,
            "commit_time_scope": "original_end_of_series_sql_observation",
            "request_identity_scope": "forwarded_input_and_native_envelope_digests_are_distinct",
        }
        try:
            from scripts.native_slo_contract import assert_privacy_safe

            require(assert_privacy_safe(retained) == retained, "identity_observation_privacy_projection_changed")
            descriptor = os.open(config["receipt_identities"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            try:
                data = encoded(retained) + b"\n"
                require(len(data) <= 32768 and os.write(descriptor, data) == len(data), "identity_observation_write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except Exception as error:
            failures.append(error_name(error))
        result["complete_receipt_identity_observation"] = {
            "passed": not failures and len(rows) == len(WORKSPACE_PHASES),
            "receipt_count": len(rows),
            "identity_rows_sha256": digest(encoded(rows)),
            "failures": failures,
        }
        return result

    # Only the disposable qualification helper classes receive these wrappers.
    AdapterSession.__init__ = initialize
    ReceiptWitness.__enter__ = enter
    WorkspaceScenarioFixture.finish = finish
