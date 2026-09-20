"""Execute one declared explanatory subset and preserve failures and cleanup separately."""

from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .installation import Installation, current_site
from .population import measure_selected
from .reader import join_subset, read_profiles
from .registry import build

_capture = importlib.import_module("priority_launcher_phase.capture")
_fixture = importlib.import_module("priority_launcher_phase.fixture")
Collector = _capture.Collector
error_kind = _capture.error_kind
json_bytes = _capture.json_bytes
FixtureRedirect = _fixture.FixtureRedirect
stop_projection = _fixture.stop_projection
read_report_document = importlib.import_module("priority_launcher_phase.joins").read_report_document
ParentCapture = importlib.import_module("priority_launcher_phase.parent").ParentCapture


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


def children_reaped(parent: dict[str, Any]) -> bool:
    if parent.get("in_flight") != 0 or type(parent.get("rows")) is not list:
        return False
    for row in parent["rows"]:
        calls = row.get("facts", {}).get("process_calls", [])
        children = row.get("facts", {}).get("children", [])
        if (
            len(calls) != 1
            or len(children) != 1
            or calls[0].get("exception") is not False
            or type(calls[0].get("returncode")) is not int
            or calls[0].get("containment_failed") is not False
        ):
            return False
    return True


def execute_block(
    fixture: Any,
    producer: Any,
    fixture_module: Any,
    launch_runtime: Any,
    *,
    source_root: Path,
    child_script: Path,
    daemon_report_path: Path,
    package_root: Path,
    wheel: Path,
) -> dict[str, Any]:
    collector = Collector("parent")
    report: dict[str, Any] = {
        "subset_completed": False,
        "subset_invocations": 0,
        "qualification_eligible": False,
        "expected_launches": 24,
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
    installed: Installation | None = None
    registrations: list[Any] = []
    registry: dict[str, Any] = {}
    sidecar_path = Path(tempfile.mkdtemp(prefix="hol-guard-child-profile-"))
    try:
        with redirect, capture:
            try:
                session = fixture.__enter__()
                report["fixture_startup_ms"] = session.startup_ms
                report["fixture_readiness_ms"] = session.readiness_ms
                registrations = list(producer.install_priority_launchers(session))
                registry, report["frame_source_bindings"] = build(package_root, wheel)
                registry["modules"]["<string>"] = "dynamic_string_module"
                report["dynamic_string_module_origin"] = "unresolved; may include original -c or later exec(string)"
                config = {
                    **registry,
                    "executable": sys.executable,
                    "parent_pid": os.getpid(),
                    "python": list(sys.version_info[:3]),
                    "argv": [list(x.argv) for x in registrations],
                }
                installed = Installation(current_site(), sidecar_path, config).__enter__()
                report["startup_observer"] = installed.manifest
                report["subset_invocations"] += 1
                measurements, raw = measure_selected(session, producer, registrations)
                report.update(measurements=measurements, raw_samples_ms=raw, subset_completed=True)
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
        report["parent"] = collector.snapshot(original_success=report["subset_completed"])
    except BaseException as error:
        report["parent_capture_failure"] = failure(error)
    report["fixture_redirect_count"] = redirect.redirected
    try:
        report["daemon"], report["daemon_report_original_bytes"] = read_report_document(daemon_report_path)
        report["daemon_report_canonical_sha256"] = hashlib.sha256(json_bytes(report["daemon"])).hexdigest()
    except BaseException as error:
        report["daemon_capture_failure"] = failure(error)
    try:
        report["joins"] = join_subset(report["parent"], report["daemon"])
    except BaseException as error:
        report["join_failure"] = failure(error)
    try:
        if installed is not None:
            report["children"] = read_profiles(
                sidecar_path,
                report["parent"],
                registrations,
                installed.manifest["configuration_sha256"],
                registry,
                os.getpid(),
            )
    except BaseException as error:
        report["child_evidence_failure"] = failure(error)
    finally:
        try:
            reaped = children_reaped(report.get("parent", {}))
            report["registered_children_reaped"] = reaped
            if installed is not None and reaped:
                installed.close()
                report["observer_cleanup_complete"] = not installed.created and not installed.cleanup_faults
                report["observer_cleanup_faults"] = installed.cleanup_faults
            else:
                report["observer_cleanup_complete"] = False
            if report["observer_cleanup_complete"]:
                shutil.rmtree(sidecar_path)
                report["private_sidecars_removed"] = True
            elif installed is None and reaped:
                sidecar_path.rmdir()
                report["private_sidecars_removed"] = True
        except BaseException as error:
            report["observer_cleanup_failure"] = failure(error)
    try:
        _, report["frame_source_bindings_after"] = build(package_root, wheel)
        report["frame_source_unchanged"] = report.get("frame_source_bindings") == report["frame_source_bindings_after"]
    except BaseException as error:
        report["frame_source_after_failure"] = failure(error)
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
        report["subset_completed"] is True
        and report["subset_invocations"] == 1
        and report.get("joins", {}).get("observation_complete") is True
        and report.get("children", {}).get("observation_complete") is True
        and report.get("observer_cleanup_complete") is True
        and report.get("private_sidecars_removed") is True
        and report.get("frame_source_unchanged") is True
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
