"""Reconcile the retained original installed cases without changing their historical outcome."""

from __future__ import annotations

import ast
from collections import Counter
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from artifact_common import parsed
from common import CONFIG, REPORT, SOURCE, sha256, write_json

COUNTS = {
    "test_supply_chain_can_import_each_owner_first_and_resolve_annotations": 18,
    "test_refresh_uses_replaced_facade_lock_state_path_and_interval": 1,
    "test_imported_policy_hash_recomputation_uses_current_facade_authority": 1,
    "test_lazy_resolvers_keep_the_original_package_anchor": 4,
    "test_lazy_runtime_exports_follow_current_facade_resolver": 1,
}


def historical_junit_key(address: str) -> tuple[str, str]:
    # The preserved pytest9.0.3 mangle_test_address accepts the original empty file prefix.
    # This historical reader is separate from the unchanged fresh-run junit_key contract.
    plain, separator, parameters = address.partition("[")
    names = plain.split("::")
    assert len(names) == 2 and names[0] == "", address
    names[0] = re.sub(r"\.py$", "", names[0].replace("/", "."))
    names[-1] += separator + parameters
    return ".".join(names[:-1]), names[-1]


def original_installed(payloads: dict[str, bytes]) -> list[dict]:
    collection = parsed(payloads, "installed-seam-collection.json")
    execution = parsed(payloads, "installed-seam-execution.json")
    before = parsed(payloads, "installed-before.json")
    outcome = parsed(payloads, "job-outcome.json")
    for record in (collection, execution):
        assert record["pytest_exit_code"] == 0 and record["error"] is None
        assert record["collection_bound_before_execution"] is True
        assert record["qualification_complete"] is False
        assert all(row["outcome"] == "passed" for row in record["collection_reports"])
    assert collection["collection_only"] is True and execution["collection_only"] is False
    assert collection["fixture_setup_entries"] == collection["test_call_entries"] == 0
    assert not collection["phase_reports"]
    assert execution["fixture_setup_entries"] == execution["test_call_entries"] == 25
    cases = collection["cases"]
    assert execution["cases"] == cases and len(cases) == 25
    nodes = [case["nodeid"] for case in cases]
    assert len(set(nodes)) == 25 and all(node.startswith("::") for node in nodes)
    assert Counter(case["function"]["name"] for case in cases) == COUNTS
    seam = SOURCE / CONFIG["seam_test"]
    raw = seam.read_bytes()
    assert sha256(raw) == CONFIG["partition_files"][CONFIG["seam_test"]]["sha256"]
    definitions = {
        node.name: node for node in ast.parse(raw).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    assert set(definitions) == set(COUNTS)
    for case in cases:
        node = definitions[case["function"]["name"]]
        expected = {
            "path": "@tests/" + seam.name, "name": node.name,
            "first_line": min([node.lineno, *[item.lineno for item in node.decorator_list]]),
            "function_ast_sha256": sha256(ast.dump(node, include_attributes=False).encode()),
            "whole_file_sha256": sha256(raw),
        }
        assert case["function"] == expected, case["nodeid"]
        assert case["nodeid"].partition("[")[0] == "::" + node.name
    assert before["installed_versions"] == CONFIG["installed_versions"] and before["installed_count"] == 69
    assert before["wheel_sha256"] == CONFIG["original"]["packages"]["wheel"]["sha256"]
    origin_bindings = {}
    for label, record in (("collection", collection), ("execution", execution)):
        assert record["product_module_origins"], label
        for module, origin in record["product_module_origins"].items():
            assert origin["path"] in before["installed_package_files"], (label, module)
            assert origin["sha256"] == before["installed_package_files"][origin["path"]]["sha256"]
        origin_bindings[label] = record["product_module_origins"]
    xml = ET.fromstring(payloads["installed-seam-execution-junit.xml"])
    rows = xml.findall(".//testcase")
    keys = [(row.get("classname"), row.get("name")) for row in rows]
    expected_keys = [historical_junit_key(node) for node in nodes]
    by_node = {node: [] for node in nodes}
    unexpected = []
    for phase in execution["phase_reports"]:
        if phase["nodeid"] in by_node:
            by_node[phase["nodeid"]].append(phase)
        else:
            unexpected.append(phase)
    bindings = []
    for index, node in enumerate(nodes):
        actual = rows[index] if index < len(rows) else None
        phases = by_node[node]
        outcomes = (
            {kind: len(actual.findall(kind)) for kind in ("failure", "error", "skipped")}
            if actual is not None else None)
        bindings.append({
            "nodeid": node, "expected_xml_identity": expected_keys[index],
            "actual_xml_identity": keys[index] if index < len(keys) else None,
            "phases": phases, "xml_outcome_elements": outcomes,
        })
    report = {
        "original_run": CONFIG["original"]["run"], "cases": len(cases),
        "original_ordered_collection_equals_execution": execution["cases"] == cases,
        "ordered_xml_identities_equal": keys == expected_keys,
        "original_node_bindings": bindings, "unexpected_phases": unexpected,
        "product_origin_bindings": origin_bindings,
        "original_overall_passed": False, "original_error": outcome["error"],
        "original_installed_after_missing": True, "original_lifetime_binding_complete": False,
        "qualification_complete": False,
    }
    write_json(REPORT / "original-installed-reconciliation.json", report)
    assert keys == expected_keys and len(set(keys)) == 25 and not unexpected
    assert len(execution["phase_reports"]) == 75
    for binding in bindings:
        assert [row["when"] for row in binding["phases"]] == ["setup", "call", "teardown"]
        assert all(row["outcome"] == "passed" and row["wasxfail"] is None for row in binding["phases"])
        assert binding["xml_outcome_elements"] == {"failure": 0, "error": 0, "skipped": 0}
    for label in ("installed-seam-collection", "installed-seam-execution"):
        steps = [step for step in outcome["steps"] if step["name"] == label]
        assert len(steps) == 1 and steps[0]["returncode"] == 0 and steps[0]["passed"] is True
        args = steps[0]["command"]
        assert "--noconftest" in args and args[args.index("-c") + 1] == "/dev/null" and "--rootdir" not in args
        assert not Path(steps[0]["cwd"]).is_relative_to(Path("/dev"))
        assert sha256(payloads[label + ".log"]) == steps[0]["log_sha256"]
        assert len(payloads[label + ".log"]) == steps[0]["log_bytes"]
    report["original_installed_case_passes_reconciled"] = 25
    report["original_rootdir_failure_preserved"] = True
    write_json(REPORT / "original-installed-reconciliation.json", report)
    return cases


def bind_fresh_collection(original_cases: list[dict], collection_path: Path) -> None:
    assert collection_path == REPORT / "installed-seam-collection.json"
    fresh = json.loads(collection_path.read_bytes())
    expected = json.loads(json.dumps(original_cases))
    filename = Path(CONFIG["seam_test"]).name
    for case in expected:
        assert case["nodeid"].startswith("::")
        case["nodeid"] = filename + case["nodeid"]
    observed = {
        "original_cases": original_cases, "expected_after_filename_prefix_repair": expected,
        "actual_fresh_cases": fresh["cases"], "exact_all_other_case_fields_equal": expected == fresh["cases"],
        "allowed_change": "Only prepend the actual unchanged seam filename to each original :: node ID",
        "generic_fresh_junit_contract_unchanged": True, "qualification_complete": False,
    }
    write_json(REPORT / "installed-original-collection-bridge.json", observed)
    assert fresh["pytest_exit_code"] == 0 and fresh["error"] is None
    assert fresh["collection_only"] and fresh["collection_bound_before_execution"]
    assert fresh["fixture_setup_entries"] == fresh["test_call_entries"] == 0 and not fresh["phase_reports"]
    assert expected == fresh["cases"], "Fresh installed case metadata differs beyond the explicit filename prefix"
