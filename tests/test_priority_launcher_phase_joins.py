from __future__ import annotations

import hashlib
import json
from itertools import count
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.ci.priority_launcher_phase.capture import Collector, bind, call, json_bytes, unbind
from scripts.ci.priority_launcher_phase.daemon import AttachAfterEnter
from scripts.ci.priority_launcher_phase.fixture import serve_with_capture
from scripts.ci.priority_launcher_phase.joins import interval_union_ms, join_reports, read_report, read_report_document
from scripts.ci.priority_launcher_phase.projection import declared_coordinates, freeze_input
from scripts.ci.priority_launcher_phase.run import execute_block
from scripts.native_slo_priority_launchers import launcher_payload


def _reports():
    parent, daemon = Collector("parent", clock=count(1).__next__), Collector("daemon", clock=count(1000).__next__)
    for index, coordinate in enumerate(declared_coordinates()):
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
        daemon.facts(row, **frozen.facts(), exit_projection_valid=True, mutation_detected=False)
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


def test_reordered_daemon_completion_joins_by_coordinate_and_projection_not_order():
    parent, daemon = _reports()
    daemon["rows"].reverse()
    for index, row in enumerate(daemon["rows"]):
        row["row_index"] = index
    result = join_reports(parent, daemon)
    assert result["observation_complete"] is True
    assert result["parent_rows"] == result["daemon_rows"] == 88
    assert result["rows"][0]["daemon_row"] == 87
    assert result["rows"][0]["coordinate"]["sample"] == -1
    assert result["rows"][1]["coordinate"]["sample"] == -1
    assert result["rows"][0]["coordinate"]["case"] != result["rows"][1]["coordinate"]["case"]
    assert result["cross_process_clock_subtraction"] is False


@pytest.mark.parametrize(
    "mutation",
    ["duplicate", "semantic", "envelope", "receipt", "no-receipt", "worker", "mutation"],
    ids=["duplicate", "semantic", "envelope", "receipt", "no-receipt", "worker", "mutation"],
)
def test_join_rejects_each_independent_missing_or_mismatched_identity(mutation):
    parent, daemon = _reports()
    facts = daemon["rows"][0]["facts"]
    if mutation == "duplicate":
        daemon["rows"][1]["coordinate"] = daemon["rows"][0]["coordinate"]
    elif mutation == "semantic":
        facts["semantic_sha256"] = "0" * 64
    elif mutation == "envelope":
        facts["native_exchanges"][0]["envelope_sha256"] = "0" * 64
    elif mutation == "receipt":
        facts["receipt_submissions"][0]["identity"] = dict(
            facts["receipt_submissions"][0]["identity"], request_id="opaque.other"
        )
    elif mutation == "no-receipt":
        del facts["receipt_submissions"]
    elif mutation == "worker":
        facts["worker_reviews"][0]["entry_match"] = False
    else:
        facts["mutation_detected"] = True
    result = join_reports(parent, daemon)
    assert result["observation_complete"] is False
    assert result["rows"][0]["complete"] is False
    assert result["qualification_eligible"] is False


def test_native_normal_none_is_not_inferred_from_exception_or_missing_stage():
    parent, daemon = _reports()
    facts = daemon["rows"][0]["facts"]
    facts["native_edges"] = [{"edge_returned": False, "edge_identity": None, "exception": False}]
    result = join_reports(parent, daemon)
    assert result["rows"][0]["checks"]["native_edge_returned_none"] is True
    facts["native_edges"][0]["exception"] = True
    result = join_reports(parent, daemon)
    assert result["rows"][0]["checks"]["native_edge_returned_none"] is False
    del facts["native_edges"]
    assert join_reports(parent, daemon)["rows"][0]["checks"]["native_edge_returned_none"] is False


def test_inclusive_intervals_use_union_and_do_not_add_nested_spans():
    assert (
        interval_union_ms(
            [
                {"start_ns": 0, "end_ns": 10000000},
                {"start_ns": 2000000, "end_ns": 8000000},
                {"start_ns": 12000000, "end_ns": 15000000},
            ]
        )
        == 13.0
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update(capture_faults=1),
        lambda value: value["rows"][0]["facts"].update(private_payload="must not be admitted"),
        lambda value: value["rows"][0]["facts"]["process_calls"][0].update(command="must not be admitted"),
        lambda value: value["rows"][0]["stages"][0].update(duration_ms=999),
    ],
    ids=["false-complete", "unknown-fact", "unknown-event-field", "invented-duration"],
)
def test_reader_rejects_false_completeness_private_fields_and_changed_timing(mutator):
    parent, daemon = _reports()
    mutator(parent)
    with pytest.raises(ValueError):
        join_reports(parent, daemon)


def test_reader_preserves_duplicate_refusal_and_original_file_bytes(tmp_path):
    path = tmp_path / "duplicate.json"
    content = b'{"schema":"first","schema":"second"}'
    path.write_bytes(content)
    with pytest.raises(ValueError, match="duplicate"):
        read_report(path)
    assert path.read_bytes() == content


def test_final_cleanup_projection_failure_retains_already_captured_rows_and_original_return(tmp_path):
    collector = Collector("daemon", clock=count(1).__next__)
    row = collector.begin(declared_coordinates()[0])
    assert row is not None
    collector.finish(row, None)
    attach = SimpleNamespace(
        session=SimpleNamespace(last_stop_diagnostic={"unsupported": "private"}),
        enter_count=1,
        __enter__=lambda: None,
        __exit__=lambda: None,
    )

    class Session:
        def stop_resident(self):
            return True

    original = Session.stop_resident
    output = tmp_path / "report.json"
    assert serve_with_capture(lambda: 0, collector, cast(AttachAfterEnter, cast(object, attach)), Session, output) == 0
    report = json.loads(output.read_bytes())
    assert len(report["rows"]) == 1
    assert report["final_stop"] is None and report["final_stop_error_kind"] == "value_error"
    assert report["observation_complete"] is False
    assert Session.stop_resident is original
    assert b"private" not in output.read_bytes()


def test_producer_exception_and_cleanup_exception_remain_separate_without_second_call(tmp_path):
    calls: list[object] = []
    source_failure = RuntimeError("controlled original producer failure")
    cleanup_failure = OSError("controlled original cleanup failure")

    def observe(*args, **kwargs):
        return None

    def measure(session, plan):
        calls.append((session, plan))
        raise source_failure

    producer = SimpleNamespace(
        observe_priority_launcher=observe,
        measure_priority_launchers=measure,
        run_isolated_hook_process=lambda *args, **kwargs: None,
    )
    runtime = SimpleNamespace(
        _spawn_hook_process=lambda *args, **kwargs: None,
        start_hook_io=lambda *args, **kwargs: None,
        wait_for_hook_process=lambda *args, **kwargs: None,
        join_and_cleanup_hook_process=lambda *args, **kwargs: None,
    )
    fixture_module = SimpleNamespace(
        __file__=str(tmp_path / "fixture.py"), _spawn_hook_process=lambda *args, **kwargs: None
    )

    class Fixture:
        runtime = tmp_path / "runtime"
        startup_ms = readiness_ms = 1.0
        process = None
        _readers = ()

        def __enter__(self):
            return self

        def close(self):
            raise cleanup_failure

    fixture = Fixture()
    result = execute_block(
        fixture,
        producer,
        fixture_module,
        runtime,
        source_root=tmp_path,
        child_script=tmp_path / "child.py",
        daemon_report_path=tmp_path / "missing.json",
    )
    assert calls == [(fixture, {"priority_per_run": 2, "cold_per_run": 2})]
    assert result["producer_invocations"] == 1 and result["producer_completed"] is False
    assert result["original_failure"]["kind"] == "runtime_error"
    assert result["cleanup_failure"]["kind"] == "os_error"
    assert result["observation_complete"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "negative-index",
        "overflow-index",
        "gap",
        "negative-parent",
        "missing-parent",
        "parent-interval",
        "occurrence",
        "error-kind",
    ],
    ids=[
        "negative-index",
        "overflow-index",
        "gap",
        "negative-parent",
        "missing-parent",
        "parent-interval",
        "occurrence",
        "error-kind",
    ],
)
def test_reader_rejects_forged_span_structure(mutation):
    parent, daemon = _reports()
    stages = parent["rows"][0]["stages"]
    if mutation == "negative-index":
        stages[0]["index"] = -1
    elif mutation == "overflow-index":
        stages[-1]["index"] = 32
    elif mutation == "gap":
        stages[-1]["index"] = 7
    elif mutation == "negative-parent":
        stages[1]["parent_index"] = -1
    elif mutation == "missing-parent":
        stages[-1]["index"] = 7
        stages[-1]["parent_index"] = 6
    elif mutation == "parent-interval":
        stages[1]["parent_index"] = stages[0]["index"]
    elif mutation == "occurrence":
        stages[1]["occurrence"] = 8
    else:
        stages[0]["error_kind"] = "os_error"
    with pytest.raises(ValueError, match="phase_evidence_stage"):
        join_reports(parent, daemon)


def test_nested_span_parent_and_occurrence_are_checked_in_start_order():
    from scripts.ci.priority_launcher_phase.joins import _report

    collector = Collector("parent", clock=count(10).__next__)
    row = collector.begin(declared_coordinates()[0])
    assert row is not None
    tokens = bind(collector, row)
    try:
        call(collector, "contained_process_call", lambda: call(collector, "spawn", lambda: None, (), {}), (), {})
        call(collector, "spawn", lambda: None, (), {})
    finally:
        unbind(tokens)
    collector.finish(row, None)
    value = collector.snapshot(original_success=True)
    assert [item["index"] for item in value["rows"][0]["stages"]] == [1, 0, 2]
    assert _report(value, "parent") == value["rows"]
    value["rows"][0]["stages"][-1]["occurrence"] = 0
    with pytest.raises(ValueError, match="stage_occurrence_sequence"):
        _report(value, "parent")


def test_report_read_binds_original_bytes_without_canonical_digest_substitution(tmp_path):
    payload = b'{\n  "value": true\n}\n'
    path = tmp_path / "report.json"
    path.write_bytes(payload)
    value, identity = read_report_document(path)
    assert value == {"value": True}
    assert identity == {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    assert identity["sha256"] != hashlib.sha256(json_bytes(value)).hexdigest()
    assert path.read_bytes() == payload
