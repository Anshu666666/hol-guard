"""Summarize actual pytest/JUnit outcomes without masking failures or skipped controls."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path


def summarize(report: Path, config: dict, source_files: dict) -> dict:
    result = {"errors": [], "native_qualification_credit": False,
              "installed_qualification_credit": False, "qualification_complete": False}
    try:
        capture = json.loads((report / "pytest-capture.json").read_text())
        nodes = capture["nodeids"]
        result.update(collected=len(nodes), pytest_exit_code=capture["pytest_exit_code"],
                      modules=sorted({node.split("::", 1)[0] for node in nodes}))
        if len(set(nodes)) != len(nodes) or set(result["modules"]) != set(config["finite_modules"]):
            result["errors"].append("Actual collection differs from the thirteen selected finite modules")
        if capture["error"] is not None or capture["pytest_exit_code"] != 0:
            result["errors"].append("Original pytest process failed: " + repr(capture["error"]))
        by_node = {node: [] for node in nodes}
        for row in capture["actual_reports"]:
            if row["nodeid"] not in by_node:
                result["errors"].append("Unexpected executed node: " + row["nodeid"])
            else:
                by_node[row["nodeid"]].append(row)
        execution_counts = {"passed": 0, "failed": 0, "skipped": 0, "incomplete": 0}
        for node, rows in by_node.items():
            if any(row["outcome"] == "failed" for row in rows):
                execution_counts["failed"] += 1
            elif any(row["outcome"] == "skipped" or row["wasxfail"] is not None for row in rows):
                execution_counts["skipped"] += 1
            elif [row["when"] for row in rows] == ["setup", "call", "teardown"] and all(
                    row["outcome"] == "passed" for row in rows):
                execution_counts["passed"] += 1
            else:
                execution_counts["incomplete"] += 1
        result["actual_execution_counts"] = execution_counts
        if execution_counts != {"passed": len(nodes), "failed": 0, "skipped": 0, "incomplete": 0}:
            result["errors"].append("Finite failures, skips, expected failures, or incomplete cases were observed")
        cases = capture["portable_c_cases"]
        parameters = {(row["parameters"]["cycles"], row["parameters"]["scenario"]) for row in cases}
        expected = {(cycles, scenario) for cycles in (1, 8, 17) for scenario in (0, 1, 2)}
        result["portable_c_cases"] = cases
        result["portable_c_programs"] = capture["portable_c_programs"]
        if len(cases) != 9 or parameters != expected or capture["portable_c_programs"] != 1:
            result["errors"].append("The actual nine compiled portable C controls were not all admitted")
        if len(capture["portable_c_fixture_files"]) != 6:
            result["errors"].append("Complete compiled fixture source and executable evidence is absent")
        origins = capture["source_origins"]
        result["observed_source_modules"] = len(origins)
        if not origins:
            result["errors"].append("No actual candidate module origins were captured")
        for name, row in origins.items():
            if row["path"] not in source_files or source_files[row["path"]]["sha256"] != row["sha256"]:
                result["errors"].append("Observed source origin did not match the full source map: " + name)
    except Exception as error:
        result["errors"].append("Pytest evidence: " + repr(error))
    try:
        root = ET.parse(report / "finite-junit.xml").getroot()
        cases = root.findall(".//testcase")
        counts = {
            "tests": len(cases), "failed": sum(case.find("failure") is not None for case in cases),
            "errored": sum(case.find("error") is not None for case in cases),
            "skipped": sum(case.find("skipped") is not None for case in cases),
            "passed": sum(all(case.find(tag) is None for tag in ("failure", "error", "skipped")) for case in cases),
        }
        result["actual_junit_counts"] = counts
        result["actual_junit_suites"] = [dict(suite.attrib) for suite in root.findall(".//testsuite")]
        if counts["tests"] != result.get("collected") or counts["failed"] or counts["errored"] or counts["skipped"]:
            result["errors"].append("Actual JUnit counts contain failures/skips or differ from collection")
    except Exception as error:
        result["errors"].append("JUnit evidence: " + repr(error))
    result["passed"] = not result["errors"]
    (report / "finite-results.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result
