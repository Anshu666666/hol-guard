"""Separate fresh-process preparation and first-hook identity diagnostic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_identity_lifecycle_record import binding, read_lifecycle
from scripts.native_slo_identity_run import _IdentityJournal
from scripts.native_slo_phase_run import _attempt, phase_cases

# Reachable bounds, independent of the shared journal's larger generic cap:
# one header, three offer/terminal pairs, and one bounded final summary.
MAX_SUMMARY_BYTES = 32 * 1024
MAX_SUMMARY_FILE_BYTES = MAX_SUMMARY_BYTES + 4096
MAX_PARENT_BYTES = 7 * 8192 + MAX_SUMMARY_BYTES + 8192


def measure_cold_identity(
    runtime: Path, evidence_file: Path, observer_file: Path, expected: object
) -> dict[str, object]:
    expected = binding(expected)
    session: Any = None
    primary: Exception | None = None
    cleanup: Exception | None = None
    ready = False
    body_finished = False
    with _IdentityJournal(evidence_file) as journal:
        journal.append(
            {"schema": "hol-guard.cold-identity-run.v1", "status": "started", "planned": 3, "binding": expected}
        )
        try:
            case = phase_cases()[0]
            session = DaemonFixture(
                runtime, setup="normal", cold_identity={"path": str(observer_file.absolute()), "binding": expected}
            )
            try:
                with session:
                    ready = True
                    try:
                        routes = session.daemon._server.hook_worker.metrics.snapshot().get("routes")
                        if not isinstance(routes, dict) or any(type(v) is not int or v != 0 for v in routes.values()):
                            raise RuntimeError("qualification cold fixture already received hooks")
                        for sample in range(3):
                            _attempt(session, case, sample, journal)
                    except Exception as error:
                        primary = error
                    finally:
                        body_finished = True
            except Exception as error:
                if body_finished:
                    cleanup = error
                if primary is None:
                    primary = error
        except Exception as error:
            if primary is None:
                primary = error
        observer = read_lifecycle(observer_file, expected)
        # Detailed per-call records stay in the private child journal. The
        # summary is closed and bounded, with aggregate owner counters only.
        observer.pop("calls", None)
        observer.pop("hooks", None)
        startup_failure = getattr(session, "cold_startup_failure", None)
        if startup_failure is not None and primary is not None:
            # __enter__ preserves its existing close-on-error behavior; close
            # can supersede the startup exception. Retain both observations.
            startup_outcome = startup_failure
            returned_failure = failure_evidence(primary)
        else:
            startup_outcome = None if ready or primary is None else failure_evidence(primary)
            returned_failure = failure_evidence(primary) if primary is not None else None
        child_exit = getattr(getattr(session, "process", None), "returncode", None)
        passed = (
            child_exit == 0
            and type(child_exit) is int
            and primary is None
            and cleanup is None
            and ready
            and journal.validated == 3
            and observer.get("complete") is True
        )
        summary: dict[str, object] = {
            "schema": "hol-guard.cold-hook-identity-run.v1",
            "scope": "fresh_process_preparation_first_hook_and_warm",
            "binding": expected,
            "headline_timing_eligible": False,
            "cache_state_modified": False,
            "cold_os_cache_measured": False,
            "interpreter_import_identity_measured": False,
            "diagnostic_io_in_original_deadlines": True,
            "planned": 3,
            "offered": journal.offered,
            "validated": journal.validated,
            "request_started": journal.request_started,
            "request_not_started": journal.terminal - journal.request_started,
            "request_start_unknown": journal.offered - journal.terminal,
            "unoffered": 3 - journal.offered,
            "ready": ready,
            "child_exit": child_exit if type(child_exit) is int and -255 <= child_exit <= 255 else None,
            "fixture_startup_ms": getattr(session, "startup_ms", None) if ready else None,
            "startup_failure": startup_outcome,
            "returned_failure": returned_failure,
            "cleanup_failure": failure_evidence(cleanup) if cleanup is not None else None,
            "observer": observer,
            "passed": passed,
        }
        if len(json.dumps(summary, separators=(",", ":"), allow_nan=False).encode()) > MAX_SUMMARY_BYTES:
            raise RuntimeError("qualification cold summary exceeded bound")
        journal.append(
            {"schema": "hol-guard.cold-identity-run.v1", "status": "finished", "report": summary}, report=True
        )
        if journal.size > MAX_PARENT_BYTES:
            raise RuntimeError("qualification cold journal exceeded reachable bound")
        summary.update(
            journal_sha256=journal.digest.hexdigest(), journal_records=journal.records, journal_bytes=journal.size
        )
    if not passed:
        raise FixtureFailureError(
            {"reason": "cold_identity_diagnostic_incomplete", "cold_identity_diagnostic": summary}
        ) from primary
    return summary
