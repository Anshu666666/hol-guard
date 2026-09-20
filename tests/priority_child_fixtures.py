"""Modeled stage/receipt rows for the separate24-population reader controls."""

from __future__ import annotations

import hashlib
from itertools import count
from typing import cast

from scripts.ci.priority_launcher_child.reader import coordinates
from scripts.ci.priority_launcher_phase.capture import Collector, bind, call, json_bytes, unbind
from scripts.ci.priority_launcher_phase.projection import freeze_input
from scripts.native_slo_priority_launchers import launcher_payload


def _reports():
    parent, daemon = Collector("parent", clock=count(1).__next__), Collector("daemon", clock=count(1000).__next__)
    for index, coordinate in enumerate(coordinates()):
        frozen = freeze_input(
            launcher_payload(
                cast(str, coordinate["event"]), cast(int, coordinate["sample"]), case=cast(str, coordinate["case"])
            ),
            cast(str, coordinate["harness"]),
        )
        identity = {
            "harness": coordinate["harness"],
            "event": coordinate["event"],
            "request_id": f"opaque.{index}",
            "request_digest": "b" * 64,
            "decision_id": hashlib.sha256(json_bytes(coordinate)).hexdigest(),
        }
        row = parent.begin(coordinate)
        assert row is not None
        parent.facts(
            row, registration_sha256="d" * 64, launcher_latency_ms=1.0, original_allowed=coordinate["case"] == "benign"
        )
        parent.event(
            row,
            "process_calls",
            {
                **frozen.facts(),
                "input_bytes": 100,
                "input_sha256": "e" * 64,
                "returncode": 0,
                "timed_out": False,
                "containment_failed": False,
                "output_limit_exceeded": False,
            },
        )
        tokens = bind(parent, row)
        for stage in ("contained_process_call", "spawn", "io_setup", "wait_and_reap", "io_join_and_containment"):
            call(parent, stage, lambda: None, (), {})
        unbind(tokens)
        parent.finish(row, None)
        row = daemon.begin(coordinate)
        assert row is not None
        daemon.facts(
            row, **frozen.facts(), exit_projection_valid=True, mutation_detected=True, only_transport_hint_removed=True
        )
        daemon.event(row, "worker_reviews", {"entry_match": True, "exception": False, "returned_dict": True})
        daemon.event(row, "encoded_envelopes", {"envelope_sha256": "a" * 64, "envelope_bytes": 10})
        daemon.event(
            row,
            "native_exchanges",
            {
                "envelope_sha256": "a" * 64,
                "envelope_bytes": 10,
                "reply_available": True,
                "reply_bytes": 10,
                "reply_sha256": "f" * 64,
                "exception": False,
            },
        )
        daemon.event(row, "decoded_edges", {"edge_identity": identity, "original_decoder_accepted": True})
        daemon.event(row, "native_edges", {"edge_identity": identity, "edge_returned": True, "exception": False})
        daemon.event(row, "receipt_submissions", {"identity": identity, "accepted": True, "exception": False})
        tokens = bind(daemon, row)
        for stage in (
            "hook_handler",
            "admission_policy",
            "workspace_policy",
            "scheduler_acquire",
            "worker_review",
            "workspace_policy",
            "native_edge",
            "runtime_status",
            "encode_envelope",
            "native_client_exchange",
            "native_client_lease",
            "decode_edge",
            "receipt_submit",
        ):
            call(daemon, stage, lambda: None, (), {})
        unbind(tokens)
        daemon.finish(row, None)
    return parent.snapshot(original_success=True), daemon.snapshot(original_success=True)
