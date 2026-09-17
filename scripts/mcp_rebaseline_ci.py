"""Publish only bounded component aggregates, including interrupted CI attempts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.mcp_rebaseline_public import BASELINE, TOOL_CALLS, WORKERS, project
from scripts.mcp_rebaseline_report import write_private
from scripts.mcp_rebaseline_statistics import paired_comparisons
from scripts.native_slo_evidence_files import read_file

MAX_PUBLIC_BYTES = 2 * 1024 * 1024


def publish(private: Path, output: Path, *, candidate: str, outcome: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
        raise ValueError("invalid candidate revision")
    failure = None
    report: dict[str, Any] = {}
    try:
        raw = json.loads(read_file(private / "aggregate.json", MAX_PUBLIC_BYTES, private=True))
        report = project(raw, candidate=candidate)
    except FileNotFoundError:
        failure = "aggregate_missing"
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        failure = "aggregate_invalid_or_outside_bound"
    if failure:
        report = {
            "schema": "hol-guard.mcp-rebaseline.v2",
            "status": "incomplete",
            "qualification": False,
            "native_selection": "not_selected_by_this_component_report",
            "sources": {"baseline": BASELINE, "candidate": candidate},
            "expected_worker_attempts": WORKERS,
            "expected_tool_call_attempts": TOOL_CALLS,
            "failures": [failure],
            "measurements": None,
        }
    if outcome != "success":
        report["status"] = "incomplete" if failure else "failed"
        report["failures"].append("matrix_step_not_successful")
        for comparison in report.get("comparisons", []):
            comparison["headline_eligible"] = False
        for row in report.get("run_trace_summaries", []):
            row["headline_eligible"] = False
        if "paired_comparisons" in report:
            report["paired_comparisons"] = paired_comparisons(report["run_trace_summaries"], runs=5, eligible=False)
    report["scope"] = "linux_source_stdio_component_rebaseline"
    report["installed_or_cross_platform_qualification"] = False
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_private(output, report, limit=MAX_PUBLIC_BYTES)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--matrix-outcome", required=True, choices=("success", "failure", "cancelled", "skipped"))
    args = parser.parse_args()
    report = publish(args.private, args.public, candidate=args.candidate, outcome=args.matrix_outcome)
    print(json.dumps({"status": report["status"], "qualification": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
