"""Three unchanged evaluated hooks in a fresh, normally prepared fixture.

This is a separate diagnostic, not a new headline series. The first hook does
not claim cold resident, executable, capability-cache or OS-cache state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_identity_phases import validate_identity_report
from scripts.native_slo_phase_run import _attempt, _Journal, phase_cases


class _IdentityJournal(_Journal):
    """Count only successfully retained offer and terminal records.

    An offered attempt can fail during setup, before calling the request API.
    A missing terminal record leaves dispatch unknown, never assumed absent.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.offered = self.terminal = self.validated = self.request_started = 0

    def __enter__(self) -> _IdentityJournal:
        super().__enter__()
        return self

    def append(self, value: dict[str, object], *, report: bool = False) -> None:
        super().append(value, report=report)
        if value.get("schema") == "hol-guard.phase-attempt.v1":
            if value.get("status") == "offered":
                self.offered += 1
            elif value.get("status") in {"validated", "failed"}:
                self.terminal += 1
                self.validated += value.get("status") == "validated"
                self.request_started += value.get("request_started") is True


def measure_evaluated_identity(session: Any, evidence_file: Path) -> dict[str, object]:
    """Retain every offered/terminal hook and the observer even on failure."""
    if getattr(session, "setup", None) != "normal":
        raise ValueError("qualification identity requires normal fresh fixture")
    case = phase_cases()[0]
    started = False
    failure: Exception | None = None
    observer: dict[str, Any] | None = None
    with _IdentityJournal(evidence_file) as journal:
        journal.append({"schema": "hol-guard.identity-run.v1", "status": "started", "planned": 3})
        try:
            routes = session.daemon._server.hook_worker.metrics.snapshot().get("routes")
            if not isinstance(routes, dict) or any(type(v) is not int or v != 0 for v in routes.values()):
                raise RuntimeError("qualification identity fixture already received hooks")
            started = True
            if session.control("identity_start").get("started") is not True:
                raise RuntimeError("qualification identity observer start missing")
            for sample in range(3):
                _attempt(session, case, sample, journal)
        except Exception as error:
            failure = error
        finally:
            if started:
                try:
                    observer = validate_identity_report(session.control("identity_finish"))
                    journal.append({"schema": "hol-guard.identity-observer.v1", "report": observer}, report=True)
                    if observer.get("complete") is not True:
                        raise RuntimeError("qualification identity observer incomplete")
                except Exception as error:
                    if failure is None:
                        failure = error
            summary: dict[str, object] = {
                "schema": "hol-guard.evaluated-hook-identity-run.v1",
                "scope": "prepared_resident_first_hook_and_warm",
                "headline_timing_eligible": False,
                "cold_resident_measured": False,
                "planned": 3,
                "offered": journal.offered,
                "validated": journal.validated,
                "request_started": journal.request_started,
                "request_not_started": journal.terminal - journal.request_started,
                "request_start_unknown": journal.offered - journal.terminal,
                "unoffered": 3 - journal.offered,
                "passed": failure is None and journal.validated == 3,
                "observer": observer,
            }
            if failure is not None:
                summary["failure"] = failure_evidence(failure)
            journal.append(
                {"schema": "hol-guard.identity-run.v1", "status": "finished", "report": summary}, report=True
            )
        summary.update(
            journal_sha256=journal.digest.hexdigest(), journal_records=journal.records, journal_bytes=journal.size
        )
    if failure is not None:
        raise FixtureFailureError(
            {"reason": "identity_diagnostic_incomplete", "identity_diagnostic": summary}
        ) from failure
    return summary
