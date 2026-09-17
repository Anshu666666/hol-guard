"""Witnessed, process-local synthetic faults for the qualification corpus.

These faults exist only in the private benchmark fixture. Injection scope is
reported explicitly; a failed transport function is not a simulated crash test.
"""

from __future__ import annotations

import math
import sqlite3
import time
from collections.abc import Mapping
from contextlib import ExitStack
from typing import Any, cast
from unittest.mock import patch

from scripts.native_slo_bridge_witness import native_bridge_witness
from scripts.native_slo_source_witness import _client_failure


class FaultFixture:
    def __init__(self, session: Any, setup: str) -> None:
        self.session = session
        self.setup = setup
        self.stack = ExitStack()
        self.last_native: dict[str, object] | None = None
        self.native_observations: list[dict[str, object]] = []
        self.observed: dict[str, object] = {}
        worker = session.daemon._server.hook_worker
        snapshot = worker.policy_snapshot_publisher.current_snapshot()
        effective = snapshot.get("effective_policy") if snapshot else None
        risk_actions = effective.get("risk_actions") if isinstance(effective, Mapping) else None
        self.evidence: dict[str, object] = {
            "command_authority_fixture": dict(session.command_authority_fixture),
            "isolated_store": session.guard_home.is_relative_to(session.root)
            and session.workspace.is_relative_to(session.root),
            "policy_ack_current": snapshot is not None and worker.policy_snapshot_publisher.is_ready(),
            "effective_policy_allow": isinstance(effective, Mapping)
            and effective.get("default_action") == "allow"
            and effective.get("subprocess_action") == "allow"
            and isinstance(risk_actions, Mapping)
            and all(value == "allow" for value in risk_actions.values()),
            "watch_observe_config": snapshot is not None
            and snapshot.get("mode") == "observe"
            and isinstance(effective, Mapping)
            and effective.get("protection_posture") == "watch",
            "python_oracle_disabled": worker.test_oracle is None,
            "fault_scope": "none",
        }

    def __enter__(self) -> FaultFixture:
        from codex_plugin_scanner.guard import native_hook_edge
        from codex_plugin_scanner.guard.runtime import hook_payload_reference

        worker = self.session.daemon._server.hook_worker
        original = worker._review_raw_hook_native

        def capture(**kwargs: object) -> object:
            # These ordinary contract cases precede headline sampling. Observe
            # the original bridge once, on its HTTP thread, using the same
            # nonblocking diagnostic owner as the source-reference witness.
            failure_before = _client_failure()
            with native_bridge_witness(kwargs.get("policy_snapshot")) as bridge:
                entered = time.monotonic()
                result = original(**kwargs)
                finished = time.monotonic()
            if len(self.native_observations) < 2:
                deadline = kwargs.get("deadline")
                known_deadline = type(deadline) in {int, float} and math.isfinite(cast(float, deadline))
                self.native_observations.append(
                    {
                        "client_failure_before": failure_before,
                        "client_failure_after": _client_failure(),
                        "deadline_remaining_ms": max(0, min(9_000, int((cast(float, deadline) - entered) * 1_000)))
                        if known_deadline
                        else None,
                        "deadline_exhausted_after": finished >= cast(float, deadline) if known_deadline else None,
                        "native_elapsed_ms": max(0, min(10_000, int((finished - entered) * 1_000))),
                        # The public failure envelope forbids output-named
                        # fields. This enum identifies only reply presence.
                        "bridge": {
                            ("client_reply" if key == "client_output" else key): value for key, value in bridge.items()
                        },
                    }
                )
            native_result = result.get("result") if isinstance(result, Mapping) else None
            self.last_native = (
                dict(cast(Mapping[str, object], native_result)) if isinstance(native_result, Mapping) else None
            )
            return result

        self.stack.enter_context(patch.object(worker, "_review_raw_hook_native", capture))
        if self.setup in {"unavailable", "watch_unavailable"}:

            def unavailable(**_kwargs: object) -> None:
                self.observed["native_request_unavailable"] = True
                return None

            self.stack.enter_context(patch.object(native_hook_edge, "native_resident_client_request", unavailable))
            self.evidence["fault_scope"] = "injected_native_transport_unavailable"
        elif self.setup == "off":
            self.stack.enter_context(patch.dict("os.environ", {"HOL_GUARD_NATIVE": "off"}))
            from codex_plugin_scanner.guard.native_runtime import native_mode

            self.evidence["native_mode_off"] = native_mode() == "off"
            self.evidence["fault_scope"] = "explicit_off_mode"
        elif self.setup == "integrity":
            # The HTTP handler imports this function inside each request. The
            # defining module is the actual runtime seam; server has no module
            # attribute with that name in the pinned baseline or candidate.
            original_size = hook_payload_reference.hook_payload_reference_size

            def reference_size(*args: Any, **kwargs: Any) -> object:
                try:
                    return original_size(*args, **kwargs)
                except hook_payload_reference.HookPayloadReferenceError:
                    self.observed["payload_reference_rejected"] = True
                    raise

            self.stack.enter_context(
                patch.object(hook_payload_reference, "hook_payload_reference_size", reference_size)
            )
            self.evidence["fault_scope"] = "malformed_encrypted_reference"
        elif self.setup == "queue_bytes":
            scheduler = self.session.daemon._server.runtime_hook_scheduler
            self.stack.enter_context(patch.object(scheduler, "_retained_bytes_limit", 1))
            original_reserve = scheduler.reserve_bytes

            def reserve(**kwargs: object) -> object:
                result = original_reserve(**kwargs)
                if result == (None, "daemon_hook_queue_bytes"):
                    self.observed["byte_reservation_rejected"] = True
                return result

            self.stack.enter_context(patch.object(scheduler, "reserve_bytes", reserve))
            self.evidence["fault_scope"] = "configured_byte_limit_rejection"
        elif self.setup == "review_queue_failed":
            # Both pinned production queue helpers call persist(request, now)
            # positionally. Rejecting that call at argument binding would yield
            # a caught TypeError without ever witnessing this injected failure.
            def approval_failed(*_args: object, **_kwargs: object) -> None:
                self.observed["approval_persistence_failed"] = True
                raise sqlite3.OperationalError("synthetic qualification write failure")

            self.stack.enter_context(patch.object(self.session.store, "add_approval_request", approval_failed))
            self.evidence["fault_scope"] = "injected_approval_persistence_error"
        elif self.setup == "expired":
            from scripts.native_slo_expiry import expire_acknowledged_authority

            self.evidence.update(expire_acknowledged_authority(self.session))
            self.evidence["fault_scope"] = "authenticated_short_lived_generation"
        elif self.setup == "revoked":
            from scripts.native_slo_revocation import revoke_acknowledged_authority

            self.evidence.update(revoke_acknowledged_authority(self.session))
            self.evidence["fault_scope"] = "withdrawn_accepted_authority_file"
        elif self.setup not in {"normal", "watch"}:
            raise RuntimeError("qualification fault setup has no witnessed implementation")
        return self

    def before_case(self) -> None:
        self.last_native = None
        self.native_observations.clear()
        self.observed.clear()

    def result(self) -> dict[str, object]:
        return {
            "setup": {**self.evidence, **self.observed},
            "native_result": self.last_native,
            "native_bridge": {
                "schema": "hol-guard.native-corpus-bridge-witness.v1",
                "headline_timing_eligible": False,
                "observed_calls_capped_at_two": len(self.native_observations),
                "observations": list(self.native_observations),
            },
        }

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
