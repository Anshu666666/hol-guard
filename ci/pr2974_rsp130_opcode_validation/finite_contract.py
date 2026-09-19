"""Retain the existing exact per-node collection, phase and JUnit contract."""

from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

from common import REPORT, write_json


def collected(path: Path) -> dict:
    data = json.loads(path.read_text())
    assert data["pytest_exit_code"] == 0 and data["error"] is None, str(path)
    assert data["collection_only"] and data["collection_bound_before_execution"], str(path)
    assert data["test_call_entries"] == data["fixture_setup_entries"] == 0 and not data["phase_reports"]
    cases = data["cases"]
    assert 0 < len(cases) <= 2000 and len({case["nodeid"] for case in cases}) == len(cases)
    return data


def junit_key(nodeid: str) -> tuple[str, str]:
    plain, separator, parameter = nodeid.partition("[")
    parts = plain.split("::")
    assert parts[0].endswith(".py") and len(parts) >= 2, nodeid
    classname = ".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]])
    return classname, parts[-1] + (separator + parameter if separator else "")


def execution(path: Path, prior: Path, junit: Path, *, no_skips: bool) -> dict:
    data = json.loads(path.read_text())
    collection = collected(prior)
    assert not data["collection_only"] and data["collection_bound_before_execution"]
    assert data["cases"] == collection["cases"]
    root = ET.parse(junit).getroot()
    cases = root.findall(".//testcase")
    nodes = [case["nodeid"] for case in data["cases"]]
    expected_keys = [junit_key(node) for node in nodes]
    actual_keys = [(case.get("classname"), case.get("name")) for case in cases]
    ordered_identity_equal = actual_keys == expected_keys
    by_node = {node: [] for node in nodes}
    unexpected_phases = []
    for row in data["phase_reports"]:
        if row["nodeid"] in by_node:
            by_node[row["nodeid"]].append(row)
        else:
            unexpected_phases.append(row)
    case_bindings = []
    for index, node in enumerate(nodes):
        phases = by_node[node]
        case = cases[index] if index < len(cases) else None
        expected_outcomes = {
            "failure": sum(row["when"] == "call" and row["outcome"] == "failed" for row in phases),
            "error": sum(row["when"] != "call" and row["outcome"] == "failed" for row in phases),
            "skipped": sum(row["outcome"] == "skipped" for row in phases)}
        actual_outcomes = (
            {kind: len(case.findall(kind)) for kind in ("failure", "error", "skipped")}
            if case is not None else None)
        same_identity = index < len(actual_keys) and actual_keys[index] == expected_keys[index]
        case_bindings.append({
            "nodeid": node, "expected_xml_identity": expected_keys[index],
            "actual_xml_identity": actual_keys[index] if index < len(actual_keys) else None,
            "identity_equal": same_identity, "phase_outcomes": [
                {"phase": row["when"], "outcome": row["outcome"], "wasxfail": row["wasxfail"]}
                for row in phases],
            "expected_xml_outcome_elements": expected_outcomes,
            "actual_xml_outcome_elements": actual_outcomes,
            "xml_outcomes_match_node_phases": same_identity and actual_outcomes == expected_outcomes})
    counts = {"tests": len(cases), "failed": sum(item.find("failure") is not None for item in cases),
              "errored": sum(item.find("error") is not None for item in cases),
              "skipped": sum(item.find("skipped") is not None for item in cases)}
    observed = {
        "snapshot": path.name, "prior_collection": prior.name, "junit": junit.name,
        "pytest_exit_code": data["pytest_exit_code"], "observer_error": data["error"],
        "collection_count": len(data["cases"]), "execution_collection_equals_prior": data["cases"] == collection["cases"],
        "ordered_junit_identities_equal": ordered_identity_equal,
        "expected_junit_identities_unique": len(set(expected_keys)) == len(expected_keys),
        "actual_junit_identities_unique": len(set(actual_keys)) == len(actual_keys),
        "junit_node_bindings": case_bindings, "unexpected_phase_nodes": unexpected_phases,
        "junit_counts": counts, "phase_counts": {
            phase: {outcome: sum(row["when"] == phase and row["outcome"] == outcome
                                for row in data["phase_reports"])
                    for outcome in ("passed", "failed", "skipped")}
            for phase in ("setup", "call", "teardown")},
        "nonpassing_phase_nodes": [{"nodeid": row["nodeid"], "phase": row["when"], "outcome": row["outcome"]}
                                  for row in data["phase_reports"] if row["outcome"] != "passed"],
        "no_skips_required": no_skips, "qualification_complete": False}
    write_json(REPORT / (path.stem + "-reconciliation.json"), observed)
    assert ordered_identity_equal, "JUnit case identities differ from ordered collection"
    assert len(set(expected_keys)) == len(expected_keys) and len(set(actual_keys)) == len(actual_keys)
    assert not unexpected_phases
    assert all(row["xml_outcomes_match_node_phases"] for row in case_bindings)
    assert data["pytest_exit_code"] == 0 and data["error"] is None, str(path)
    assert counts["tests"] == len(data["cases"])
    assert counts["failed"] == counts["errored"] == 0, counts
    if no_skips:
        assert counts["skipped"] == 0, counts
    reports = {}
    for row in data["phase_reports"]:
        assert row["nodeid"] in set(nodes)
        phases = reports.setdefault(row["nodeid"], {})
        assert row["when"] not in phases
        phases[row["when"]] = row
    assert set(reports) == set(nodes)
    phase_passed = phase_skipped = 0
    for node in nodes:
        phases = reports[node]
        assert [row["when"] for row in by_node[node]] in (
            ["setup", "call", "teardown"], ["setup", "teardown"])
        assert phases["teardown"]["outcome"] == "passed"
        assert all(row["outcome"] != "failed" and row["wasxfail"] is None for row in phases.values())
        if phases["setup"]["outcome"] == "skipped":
            assert "call" not in phases
            phase_skipped += 1
        elif phases["call"]["outcome"] == "skipped":
            phase_skipped += 1
        else:
            assert phases["setup"]["outcome"] == phases["call"]["outcome"] == "passed"
            phase_passed += 1
    assert phase_skipped == counts["skipped"]
    assert phase_passed + phase_skipped == counts["tests"]
    return counts | {"passed": phase_passed, "all_cases_without_skip": phase_skipped == 0,
                     "ordered_junit_and_node_phase_outcomes_equal": True}


