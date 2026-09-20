"""Retain separate logical outcomes for nine declared supplemental commands."""

from __future__ import annotations

import hashlib
import json

from common import CONFIG, REPORT, write_json
from finite_controls import selection_matches

SCHEDULE = [
    ("oauth_fingerprint_original", 13, 600),
    ("secret_promotion", 13, 60),
    ("incoming_python_additions", 112, 600),
    ("workspace-pure", 62, 300),
    ("workspace-forward", 16, 300),
    ("workspace-lifecycle", 10, 300),
    ("incoming_ed731_python", 253, 600),
    ("incoming_2433_python", 94, 600),
    ("incoming_017_python", 20, 60),
]
GROUPS = [
    ("oauth_fingerprint_original", ["oauth_fingerprint_original"], 13),
    ("secret_promotion", ["secret_promotion"], 13),
    ("incoming_python_additions", ["incoming_python_additions"], 112),
    ("workspace_original88", ["workspace-pure", "workspace-forward", "workspace-lifecycle"], 88),
    ("incoming_ed731_python", ["incoming_ed731_python"], 253),
    ("incoming_2433_python", ["incoming_2433_python"], 94),
    ("incoming_017_python", ["incoming_017_python"], 20),
]


def validate_schedule() -> None:
    cohorts = CONFIG["python_cohorts"]
    assert [(row["name"], row["expected_cases"], row["timeout"]) for row in cohorts] == SCHEDULE
    selections = []
    for cohort in cohorts:
        assert [row["selector"] for row in cohort["selection_counts"]] == cohort["selectors"]
        assert sum(row["expected_cases"] for row in cohort["selection_counts"]) == cohort["expected_cases"]
        selections.extend(cohort["selectors"])
    assert len(selections) == len(set(selections))
    # Exact parameter selectors may split one current definition between an
    # original population and its separately declared incoming addition.
    for index, left in enumerate(selections):
        for right in selections[index + 1:]:
            assert not selection_matches(left, right) and not selection_matches(right, left), (left, right)
    assert sum(row["expected_cases"] for row in cohorts) == sum(row[1] for row in SCHEDULE)


def summarize_groups() -> dict:
    validate_schedule()
    path = REPORT / "finite-controls.json"
    actual = {"cohorts": [], "passed": False}
    finite_reference = None
    if path.is_file():
        raw = path.read_bytes()
        assert len(raw) <= 16 * 1024 * 1024
        finite_reference = {
            "path": "finite-controls.json", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }
        actual = json.loads(raw)
        assert actual["source_sha"] == CONFIG["source_sha"] and actual["source_tree"] == CONFIG["source_tree"]
        assert actual["schema"] == "pr2974-current-combined-finite.v1"
    actual_rows = actual["cohorts"]
    names = [row["cohort"] for row in actual_rows]
    planned_names = [row[0] for row in SCHEDULE]
    assert names == planned_names[:len(names)]
    assert len(names) == len(set(names))
    planned = {row["name"]: row for row in CONFIG["python_cohorts"]}
    physical = []
    observed_nodes = []
    for name, count, timeout in SCHEDULE:
        matches = [row for row in actual_rows if row["cohort"] == name]
        assert len(matches) <= 1
        entry = matches[0] if matches else None
        if entry is not None:
            assert entry["expected_cases"] == count and type(entry["passed"]) is bool
        admitted = entry is not None and entry["passed"] is True
        reconciliation = entry.get("reconciliation") if entry is not None else None
        nodes = []
        if reconciliation is not None:
            assert reconciliation["cohort"] == name and reconciliation["source_sha"] == CONFIG["source_sha"]
            nodes = [row["nodeid"] for row in reconciliation["ordered_duplicate_user_properties"]]
            assert len(nodes) == len(set(nodes)) == count
            assert reconciliation["cases_passed"] == count and reconciliation["phases_passed"] == count * 3
            coverage = []
            for row in planned[name]["selection_counts"]:
                selector = row["selector"]
                matching = [node for node in nodes if selection_matches(node, selector)]
                assert len(matching) == row["expected_cases"]
                coverage.extend(matching)
            assert coverage == nodes
        if admitted:
            assert reconciliation is not None
        observed_nodes.extend(nodes)
        physical.append({
            "cohort": name, "expected_cases": count, "expected_phases": count * 3,
            "collection_and_body_timeout_seconds_each": timeout,
            "attempted": entry is not None, "passed": admitted,
            "admitted_cases": count if admitted else 0,
            "admitted_phases": count * 3 if admitted else 0,
            "reconciled_nodeids": nodes,
            "original_finite_entry_index": names.index(name) if entry is not None else None,
            "body_attempted": entry["body_command_attempted"] if entry is not None else False,
        })
    assert len(observed_nodes) == len(set(observed_nodes)), "Cross-cohort duplicate node identity"
    by_name = {row["cohort"]: row for row in physical}
    logical = []
    for group, members, count in GROUPS:
        rows = [by_name[name] for name in members]
        assert sum(row["expected_cases"] for row in rows) == count
        logical.append({
            "group": group, "physical_cohorts": members, "expected_cases": count, "expected_phases": count * 3,
            "passed": all(row["passed"] for row in rows),
            "admitted_cases": sum(row["admitted_cases"] for row in rows),
            "admitted_phases": sum(row["admitted_phases"] for row in rows),
            "reconciled_nodeids": [node for row in rows for node in row["reconciled_nodeids"]],
        })
    passed = all(row["passed"] for row in logical)
    assert not passed or actual["passed"] is True
    result = {
        "schema": "pr2974.supplemental-logical-results.v1",
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "physical_cohorts": physical, "logical_groups": logical, "passed": passed,
        "planned_cases": sum(row[1] for row in SCHEDULE),
        "planned_phases": 3 * sum(row[1] for row in SCHEDULE),
        "planned_selection_entries": sum(len(row["selectors"]) for row in CONFIG["python_cohorts"]),
        "selector_domains_disjoint": True, "reconciled_node_populations_disjoint": True,
        "all_planned_nodes_reconciled": len(observed_nodes) == sum(row[1] for row in SCHEDULE),
        "complete_original_finite_reference": finite_reference,
        "historical_outcomes_are_not_current_execution": True,
        "installed_workload_executed": False, "qualification_complete": False,
    }
    if finite_reference is not None:
        assert path.read_bytes() == raw
    write_json(REPORT / "supplemental-groups.json", result)
    return result
