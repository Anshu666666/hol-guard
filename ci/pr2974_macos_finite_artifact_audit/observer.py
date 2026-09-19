"""Audit one original failed workflow artifact; execute no original workload."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, EMITTED, OUTPUT, REPORT, digest, failure, frame, source_witness, write_json
from download import download, metadata, read_zip
from finite import audit_finite
from reports import audit_environment, audit_reports, audit_syntax_and_admission, emit_original, original_log


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stages, results = [], {}
    before = None
    payloads = None

    def stage(name, action):
        row = {"stage": name, "status": "running", "passed": False}
        stages.append(row)
        write_json(REPORT / "observer-stages.json", stages)
        try:
            value = action()
            row.update(status="finished", passed=True)
            return value
        except Exception as error:
            row.update(status="finished", error=failure(error))
            return None
        finally:
            write_json(REPORT / "observer-stages.json", stages)

    assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
    before = stage("exact-source-before", lambda: source_witness("before"))
    original_metadata = stage("original-failed-attempt-metadata", metadata)
    results["original_log"] = stage("original-framing-failure", original_log)
    if before is not None and original_metadata is not None:
        pin = CONFIG["artifacts"][0]
        path = stage("single-pinned-zip-download", lambda: download(pin))
        if path is not None:
            payloads = stage("all-original-zip-members", lambda: read_zip(path, pin["label"]))
    if payloads is not None:
        results["original_emission"] = stage("complete-original-byte-emission", lambda: emit_original(payloads))
        results["reports"] = stage("original-manifest-commands-and-source", lambda: audit_reports(payloads, before))
        results["syntax_and_admission"] = stage("original-syntax-and-admission", lambda: audit_syntax_and_admission(payloads))
        results["environment"] = stage("original-full-environment-maps", lambda: audit_environment(payloads))
        results["finite"] = stage("all-original-junit-and-case-records", lambda: audit_finite(payloads, before))
    after = stage("exact-source-after", lambda: source_witness("after"))
    unchanged = before is not None and before == after
    required = {"original_log", "original_emission", "reports", "syntax_and_admission", "environment", "finite"}
    passed = (unchanged and set(results) == required and all(value is not None for value in results.values())
              and all(row["passed"] for row in stages))
    outcome = {
        "status": "finished", "passed": bool(passed), "observer_source_unchanged": unchanged,
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_harness_sha": CONFIG["original_harness_sha"], "original_run_id": CONFIG["original_run_id"],
        "original_job_id": CONFIG["original_job_id"], "original_run_attempt": 1,
        "observer_harness_sha": os.environ["GITHUB_SHA"], "observer_run_id": os.environ["GITHUB_RUN_ID"],
        "observer_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "started_utc": started, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "stages": stages, "actual_original_results": results, "qualification_complete": False,
        "original_workflow_conclusion": "failure", "original_driver_framing_failure_preserved": True,
        "original_workloads_reexecuted": False, "observer_workload_execution_credit": False,
        "native_qualification_credit": False, "installed_qualification_credit": False,
        "full_original_emitted_labels": list(EMITTED), "scope": CONFIG["scope"]}
    write_json(REPORT / "job-outcome.json", outcome)
    for name in ("original-log-audit.json", "original-reports-audit.json", "source-and-admission-audit.json",
                 "original-environment-audit.json", "original-finite-audit.json",
                 "original-junit-report-bijection.json", "original-zip-members.json", "original-download.json",
                 "job-outcome.json"):
        path = REPORT / name
        if path.is_file():
            frame("observer/" + name, path.read_bytes(),
                  limit=(8 if name == "original-junit-report-bijection.json" else 2) * 1024 * 1024)
    inventory = {str(path.relative_to(OUTPUT)): digest(path.read_bytes()) for path in sorted(OUTPUT.rglob("*"))
                 if path.is_file() and path.name != "observer-output-manifest.json"}
    write_json(REPORT / "observer-output-manifest.json", inventory)
    print(json.dumps({"observer_audit_passed": bool(passed), "original_run_conclusion": "failure",
                      "original_workloads_reexecuted": False, "stages": stages}, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
