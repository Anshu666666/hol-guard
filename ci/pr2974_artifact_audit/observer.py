"""Inspect three original ZIPs once; all original workloads remain untouched."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, OUTPUT, REPORT, digest, failure, frame, json_summary, source_witness, write_json
from download import download, metadata, read_zip
from finite import audit_finite
from packages import audit_packages
from reports import audit_reports, emit_original
from scanner import audit_scanner


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stages = []
    before = None
    after = None
    results = {}
    payloads = {}
    reports = {}

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

    before = stage("immutable-source-before", lambda: source_witness("before"))
    original_metadata = stage("complete-original-api-populations", metadata)
    if before is not None and original_metadata is not None:
        for pin in CONFIG["artifacts"]:
            label = pin["label"]
            path = stage(label + "-pinned-zip-download", lambda pin=pin: download(pin))
            if path is not None:
                value = stage(label + "-all-zip-members", lambda path=path, label=label: read_zip(path, label))
                if value is not None:
                    payloads[label] = value
        for label in ("gitleaks", "finite"):
            if label in payloads:
                stage(label + "-original-framed-reports", lambda label=label: emit_original(label, payloads[label]))
                value = stage(label + "-report-manifest-and-commands",
                              lambda label=label: audit_reports(label, payloads[label], before))
                if value is not None:
                    reports[label] = value
                    results[label + "_reports"] = value["summary"]
        if "gitleaks" in reports:
            results["scanner"] = stage("original-scan-range-audit",
                                       lambda: audit_scanner(payloads["gitleaks"], reports["gitleaks"]))
        if "finite" in reports:
            results["finite"] = stage("original-finite-and-environment-audit",
                                      lambda: audit_finite(payloads["finite"], reports["finite"], before))
        if "finite" in reports and "distributions" in payloads:
            results["packages"] = stage("original-package-byte-audit", lambda: audit_packages(
                payloads["distributions"], payloads["finite"], reports["finite"], before))
    after = stage("immutable-source-after", lambda: source_witness("after"))
    unchanged = before is not None and before == after
    required = {"gitleaks_reports", "finite_reports", "scanner", "finite", "packages"}
    passed = unchanged and set(results) == required and all(value is not None for value in results.values())
    passed = bool(passed and all(row["passed"] for row in stages))
    outcome = {
        "status": "finished", "passed": passed, "source_unchanged": unchanged,
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_harness_sha": CONFIG["original_harness_sha"], "original_run_id": CONFIG["original_run_id"],
        "original_run_attempt": 1, "observer_harness_sha": os.environ["GITHUB_SHA"],
        "observer_run_id": os.environ["GITHUB_RUN_ID"], "observer_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "started_utc": started, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "stages": stages, "actual_original_results": results, "qualification_complete": False,
        "scope": CONFIG["scope"], "original_workloads_reexecuted": False}
    write_json(REPORT / "job-outcome.json", outcome)
    inventory = {}
    for path in sorted(OUTPUT.rglob("*")):
        if path.is_file() and path.name != "observer-output-manifest.json":
            inventory[str(path.relative_to(OUTPUT))] = digest(path.read_bytes())
    write_json(REPORT / "observer-output-manifest.json", inventory)
    for label, result in results.items():
        json_summary(label, result)
    frame("observer/job-outcome.json", (REPORT / "job-outcome.json").read_bytes())
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
