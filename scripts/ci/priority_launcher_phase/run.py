"""Execute one original producer call and preserve failures and cleanup separately."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .capture import Collector, error_kind, json_bytes
from .fixture import FixtureRedirect, stop_projection
from .joins import join_reports, read_report_document
from .parent import ParentCapture

SAMPLE_PLAN = {"priority_per_run": 2, "cold_per_run": 2}


def failure(error: BaseException) -> dict[str, object]:
    # Fixed type plus hashed message, never raw command/path/output diagnostics.
    result: dict[str, object] = {"kind": error_kind(error)}
    try:
        value = str(error).encode("utf-8")
        if len(value) <= 32768:
            result["message_sha256"] = hashlib.sha256(value).hexdigest()
            result["message_bytes"] = len(value)
        else:
            result["message_unavailable"] = True
    except BaseException:
        result["message_unavailable"] = True
    return result


def execute_block(
    fixture: Any,
    producer: Any,
    fixture_module: Any,
    launch_runtime: Any,
    *,
    source_root: Path,
    child_script: Path,
    daemon_report_path: Path,
) -> dict[str, Any]:
    collector = Collector("parent")
    report: dict[str, Any] = {
        "producer_completed": False,
        "producer_invocations": 0,
        "qualification_eligible": False,
        "expected_launches": 88,
    }
    redirect = FixtureRedirect(
        collector,
        fixture_module,
        runtime=fixture.runtime,
        source_root=source_root,
        child_script=child_script,
        report_path=daemon_report_path,
    )
    capture = ParentCapture(collector, producer, launch_runtime)
    try:
        with redirect, capture:
            try:
                session = fixture.__enter__()
                report["fixture_startup_ms"] = session.startup_ms
                report["fixture_readiness_ms"] = session.readiness_ms
                report["producer_invocations"] += 1
                measurements, raw = producer.measure_priority_launchers(session, dict(SAMPLE_PLAN))
                report.update(measurements=measurements, raw_samples_ms=raw, producer_completed=True)
            except BaseException as error:
                report["original_failure"] = failure(error)
            finally:
                try:
                    fixture.close()
                    report["fixture_cleanup_returned"] = True
                except BaseException as error:
                    report["fixture_cleanup_returned"] = False
                    report["cleanup_failure"] = failure(error)

                def retain_cleanup() -> None:
                    process = fixture.process
                    report["direct_fixture_child_reaped"] = process is not None and process.poll() is not None
                    readers = fixture._readers
                    report["fixture_readers_present"] = len(readers) == 2
                    report["fixture_reader_threads_stopped"] = bool(readers) and all(
                        not item.is_alive() for item in readers
                    )

                collector.guard(retain_cleanup)
    except BaseException as error:
        report["capture_setup_failure"] = failure(error)
    try:
        report["parent"] = collector.snapshot(original_success=report["producer_completed"])
    except BaseException as error:
        report["parent_capture_failure"] = failure(error)
    report["fixture_redirect_count"] = redirect.redirected
    try:
        report["daemon"], report["daemon_report_original_bytes"] = read_report_document(daemon_report_path)
        report["daemon_report_canonical_sha256"] = hashlib.sha256(json_bytes(report["daemon"])).hexdigest()
    except BaseException as error:
        report["daemon_capture_failure"] = failure(error)
    try:
        report["joins"] = join_reports(report["parent"], report["daemon"])
    except BaseException as error:
        report["join_failure"] = failure(error)
    daemon = report.get("daemon", {})
    try:
        stops = daemon.get("stop_observations", [])
        if type(stops) is not list or not 1 <= len(stops) <= 4:
            raise ValueError("phase_stop_observations_invalid")
        observed = []
        for item in stops:
            if type(item) is not dict or set(item) != {
                "returned_bool",
                "contained_return",
                "exception_kind",
                "diagnostic",
            }:
                raise ValueError("phase_stop_observation_fields")
            observed.append((item, stop_projection(item["diagnostic"])))
        final_stop = stop_projection(daemon.get("final_stop"))
        report["authenticated_stop_observed"] = any(
            item["contained_return"] is True
            and diagnostic["status"] == "contained"
            and diagnostic["authenticated"] == "verified"
            for item, diagnostic in observed
        )
        report["stop_failure_observed"] = final_stop["status"] in {"failed", "contained_client_cleanup_failed"} or any(
            item["exception_kind"] is not None or diagnostic["status"] in {"failed", "contained_client_cleanup_failed"}
            for item, diagnostic in observed
        )
    except BaseException as error:
        report["cleanup_evidence_failure"] = failure(error)
        report["authenticated_stop_observed"] = False
        report["stop_failure_observed"] = True
    report["observation_complete"] = (
        report["producer_completed"] is True
        and report["producer_invocations"] == 1
        and report.get("joins", {}).get("observation_complete") is True
        and redirect.redirected == 1
        and daemon.get("session_attachments") == 1
        and report.get("fixture_cleanup_returned") is True
        and report.get("direct_fixture_child_reaped") is True
        and report.get("fixture_readers_present") is True
        and report.get("fixture_reader_threads_stopped") is True
        and report["authenticated_stop_observed"] is True
        and report["stop_failure_observed"] is False
        and not any(key.endswith("_failure") for key in report)
    )
    return report
