"""Retain the exact earlier outcomes without replaying successful bodies."""

from __future__ import annotations

import json

from common import CONFIG, HERE, REPORT, write_json
from preparation_contract import PRIOR, digest, pinned


def retained_results() -> dict:
    raw = pinned(HERE, CONFIG, "prior_terminal")
    old = json.loads(raw)
    assert old["source"]["sha"] == PRIOR and old["source"]["files"] == 4640
    assert old["run"]["id"] == 35460722218 and old["run"]["run_attempt"] == 1
    assert old["run"]["head_sha"] == "b3ff35a5a41823f3f2158d3bfb7bda8383b6cc0a"
    assert old["run"]["conclusion"] == "failure" and old["qualification_complete"] is False
    assert old["proof_issues"] == old["junit_proof_issues"] == []
    groups = {}
    for name, count, failed_count in (("python", 9, 0), ("native", 7, 1)):
        group = old["cohorts"][name]
        assert group["collected"] == group["expected"] == count
        assert group["ordered_contract_equal"] and group["ordered_phases_equal"]
        rows = group["case_records"]
        nodes = [row["nodeid"] for row in rows]
        assert len(nodes) == len(set(nodes)) == count
        failed = []
        passed = []
        for row in rows:
            assert row["complete_phases"]
            phases = row["phases"]
            assert [phase["when"] for phase in phases] == ["setup", "call", "teardown"]
            assert phases[0]["outcome"] == phases[2]["outcome"] == "passed"
            assert all(phase["wasxfail"] is None for phase in phases)
            is_passed = all(phase["outcome"] == "passed" for phase in phases)
            assert row["passed"] is is_passed
            (passed if is_passed else failed).append(row["nodeid"])
        assert len(failed) == failed_count
        xml = group["junit"]["run"]
        assert xml["present"] and xml["failed"] == failed_count
        assert xml["errors"] == xml["skipped"] == 0
        assert xml["passed"] == count - failed_count
        assert xml["complete_identity_bijection"] and xml["all_ordered_properties_equal"]
        groups[name] = {"passed_nodes": passed, "failed_nodes": failed,
                        "original_ordered_phases_and_properties": rows,
                        "original_junit_sha256": xml["sha256"]}
    failed = groups["native"]["failed_nodes"]
    assert failed == CONFIG["python_cohorts"][0]["selectors"]
    prior_rust_raw = pinned(HERE, CONFIG, "prior_rust")
    original = json.loads(prior_rust_raw)
    assert original["run_id"] == old["run"]["id"] and original["source_sha"] == PRIOR
    assert len(original["files"]) == 6
    for path, record in original["files"].items():
        recorded = old["all133_original_record_pins"][path]
        data = record["content"].encode("utf-8")
        assert record["encoding"] == recorded["encoding"] == "utf-8"
        assert len(data) == record["bytes"] == recorded["bytes"]
        assert digest(data) == record["sha256"] == recorded["sha256"]
    rust = {}
    for variant, expected in (("default", 16), ("diagnostic", 29)):
        unit = old["rust"][variant]["units"]
        assert unit["collected"] is True
        assert unit["completed"] == unit["expected"] == unit["passed"] == expected
        prefix = "rust-" + variant + "-unit-"
        collection = json.loads(original["files"][prefix + "collection.json"]["content"])
        results = json.loads(original["files"][prefix + "results.json"]["content"])
        listed = original["files"][prefix + "list.log"]["content"].splitlines()
        all_names = [line[:-6] for line in listed if line.endswith(": test")]
        assert len(all_names) == len(set(all_names)) and all_names == collection["all_collected_names"]
        assert collection["source_sha"] == results["source_sha"] == PRIOR
        assert collection["selected_count"] == results["selected_count"] == expected
        assert collection["selected_names"] == CONFIG["rust_variants"][variant]["selected_tests"]
        assert set(collection["selected_names"]).issubset(all_names)
        binary = collection["binary"]
        assert binary["source_sha"] == PRIOR and binary["git_source_tree"] == old["source"]["tree"]
        assert binary["test_binary"] is True and binary["toolchain"] == CONFIG["rust_toolchain"]
        assert binary["features"] == CONFIG["rust_variants"][variant]["features"]
        assert results["binary_sha256"] == binary["sha256"] and results["passed"] is True
        assert len(results["records"]) == expected
        rows = unit["records"]
        assert len(rows) == expected and len({row["name"] for row in rows}) == expected
        assert [row["name"] for row in rows] == CONFIG["rust_variants"][variant]["selected_tests"]
        for row, recorded in zip(rows, results["records"], strict=True):
            assert row["name"] == recorded["name"] and row["command"] == recorded["command_name"]
            assert row["passed"] and recorded["passed"] and recorded["command_passed"]
            assert recorded["exact_one_passed_zero_ignored"] is True
            assert recorded["expected_filtered_out"] == len(all_names) - 1
            assert row["raw_summary"] == recorded["summaries"] == [
                ["ok", "1", "0", "0", "0", str(len(all_names) - 1)],
            ]
        rust[variant] = {"historical_passes": expected, "original_records": rows,
                         "original_collected_count": len(all_names), "original_binary_sha256": binary["sha256"]}
    assert old["historical_independent_proof"]["passed"] is True
    assert old["historical_independent_proof"]["original_passed"] == 66
    assert old["historical_independent_proof"]["original66_runtime_replayed"] is False
    result = {
        "schema": "pr2974.native_retained_results.v1", "source_sha": CONFIG["source_sha"],
        "prior_executed_source": PRIOR, "prior_terminal_sha256": digest(raw),
        "prior_rust_records_sha256": digest(prior_rust_raw),
        "earlier_workflow_failure_retained": True, "groups": groups, "rust": rust,
        "earlier66_source_reconciliation": old["historical_independent_proof"],
        "fresh_successful_body_replays": 0,
        "scope": "original_outcomes_with_separate_exact_current_source_inverse_not_new_runtime_credit",
        "combined_VFS_native_validation_in_this_run": False,
        "passed": True, "qualification_complete": False,
    }
    write_json(REPORT / "retained-results.json", result)
    return result
