"""Bind the exact lexical-scope repair and the complete first finite observation."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zlib

OLD_SOURCE = "b81da3dd48dd0315bd17a22ce5f1c221c941c0ee"
OLD_TREE = "9933bc7dcb8fc874b5d6ba976ae3ebd90d15bc29"
OLD_HARNESS = "38e71e163872c35e1740092d8ac7fb61d30248dd"
FAILED_NODE = ("tests/test_guard_package_unversioned_source_witness.py::"
               "test_source_witness_excludes_nested_and_comprehension_scopes")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def restore_scope(current: bytes, here: Path) -> bytes:
    record = json.loads((here / "witness-scope-repair.json").read_bytes())
    before = record["before"]["content"].encode("utf-8")
    after = record["after"]["content"].encode("utf-8")
    assert current == after and digest(current) == record["after"]["sha256"]
    assert digest(before) == record["before"]["sha256"]
    assert len(before) == record["before"]["bytes"] and len(after) == record["after"]["bytes"]
    assert record["sole_parent"] == OLD_SOURCE and record["parent_tree"] == OLD_TREE
    assert record["only_changed_path"] == "scripts/qualify_guard_package_unversioned_route.py"
    assert len(record["edits"]) == 4
    inverse = current.decode("utf-8")
    for edit in reversed(record["edits"]):
        assert inverse.count(edit["after"]) == 1
        inverse = inverse.replace(edit["after"], edit["before"], 1)
    assert inverse.encode("utf-8") == before
    original_ast = ast.parse(before, type_comments=True)
    current_ast = ast.parse(current, type_comments=True)
    assert not original_ast.type_ignores and not current_ast.type_ignores
    old_functions = {node.name: node for node in original_ast.body if isinstance(node, ast.FunctionDef)}
    new_functions = {node.name: node for node in current_ast.body if isinstance(node, ast.FunctionDef)}
    assert old_functions.keys() == new_functions.keys()
    changed = [name for name in old_functions if ast.dump(old_functions[name]) != ast.dump(new_functions[name])]
    assert changed == ["_bound_lookup_source_records"]
    assert len(current.splitlines()) <= 500
    return before


def load_observation(config: dict, here: Path) -> dict:
    raw = (here / "previous-finite-observation.json").read_bytes()
    assert len(raw) == 5378640 and digest(raw) == config["previous_finite_observation_sha256"]
    envelope = json.loads(raw)
    assert envelope["run_id"] == 35446100641 and envelope["job_id"] == 105905167726
    assert envelope["run_attempt"] == 1 and envelope["qualification_complete"] is False
    header = envelope["header"]
    assert header["harness_sha"] == OLD_HARNESS
    assert header["source_sha"] == OLD_SOURCE and header["source_tree"] == OLD_TREE
    assert header["files"] == 128 and header["raw_bytes"] == 28639279
    assert header["gzip_bytes"] == 4018465 and header["base64_chars"] == 5357956
    encoded = envelope["gzip_base64"]
    assert isinstance(encoded, str) and len(encoded) == header["base64_chars"]
    compressed = base64.b64decode(encoded, validate=True)
    assert len(compressed) == header["gzip_bytes"] <= 8 * 1024 * 1024
    assert digest(compressed) == header["gzip_sha256"]
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = decoder.decompress(compressed, 48 * 1024 * 1024 + 1)
    assert decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
    assert len(expanded) == header["raw_bytes"] <= 48 * 1024 * 1024
    assert digest(expanded) == header["raw_sha256"]
    projection = json.loads(expanded)
    assert projection["harness_sha"] == OLD_HARNESS
    assert projection["source_sha"] == OLD_SOURCE and projection["source_tree"] == OLD_TREE
    assert projection["run_id"] == "35446100641" and projection["run_attempt"] == "1"
    assert projection["qualification_complete"] is False and projection["file_count"] == 128
    files = projection["files"]
    assert len(files) == 128
    for name, row in files.items():
        assert row["encoding"] == "utf-8"
        content = row["content"].encode("utf-8")
        assert len(content) == row["bytes"] and digest(content) == row["sha256"], name
    return projection


def read_record(projection: dict, name: str) -> dict:
    return json.loads(projection["files"][name]["content"])


def verify_observation(config: dict, here: Path) -> dict:
    projection = load_observation(config, here)
    files = projection["files"]
    outcome = read_record(projection, "job-outcome.json")
    assert outcome["passed"] is False and outcome["status"] == "finished"
    assert outcome["source_unchanged"] and outcome["baseline_source_unchanged"]
    assert outcome["all_original_owned_groups_retired"] is True
    assert outcome["workflow_step_outcomes"]["DRIVER_OUTCOME"] == "failure"
    assert outcome["known_corpus_performance_contract"] == "failed"
    assert outcome["qualification_complete"] is False and outcome["overall_qualification_complete"] is False
    assert len(outcome["steps"]) == 24
    assert [row["name"] for row in outcome["steps"] if not row["passed"]] == [
        "candidate-candidate-only-execution"]
    assert all(not row["timed_out"] and row["group_cleanup"]["passed"] for row in outcome["steps"])
    assert read_record(projection, "source-gates-result.json")["all_commands_passed"] is True
    types = read_record(projection, "scoped-error-level-types.json")["summary"]
    assert types["filesAnalyzed"] == 21 and types["errorCount"] == 0
    for left, right in (("source-before.json", "source-after.json"),
                        ("baseline-before.json", "baseline-after.json"),
                        ("environment-before.json", "environment-after.json")):
        assert files[left]["content"] == files[right]["content"]
    for group, count, failed in (("existing", 17, None), ("candidate-only", 12, FAILED_NODE)):
        prefix = "candidate-" + group
        prior = read_record(projection, prefix + "-collection.json")
        result = read_record(projection, prefix + "-execution.json")
        assert prior["passed"] and prior["terminal"] and prior["exit_code"] == 0
        assert prior["mode"] == "collection_only" and not prior["body_reports"]
        assert result["terminal"] and result["collection_complete"]
        assert result["execution_collection_matches_prior"] is True
        assert result["actual_cases"] == prior["actual_cases"] == count
        assert result["comparison"] == prior["comparison"]
        assert result["prior_collection_sha256"] == files[prefix + "-collection.json"]["sha256"]
        assert result["passed"] is (failed is None) and result["exit_code"] == (0 if failed is None else 1)
        assert not result["refused_execution"]
        nodes = [row["nodeid"] for row in result["comparison"]]
        assert len(nodes) == len(set(nodes)) == count
        rows = result["body_reports"]
        assert len(rows) == count * 3
        for index, node in enumerate(nodes):
            phases = rows[index * 3:index * 3 + 3]
            assert all(row["nodeid"] == node and row["wasxfail"] is None for row in phases)
            assert [row["phase"] for row in phases] == ["setup", "call", "teardown"]
            assert [row["outcome"] for row in phases] == (
                ["passed", "failed", "passed"] if node == failed else ["passed"] * 3)
        tree = ET.fromstring(files[prefix + "-execution.xml"]["content"])
        suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
        assert suites and sum(int(row.attrib["tests"]) for row in suites) == count
        assert sum(int(row.attrib["failures"]) for row in suites) == (0 if failed is None else 1)
        assert all(int(row.attrib["errors"]) == int(row.attrib["skipped"]) == 0 for row in suites)
        cases = [case for suite in suites for case in suite.findall("testcase")]
        from finite import junit_key
        assert [(row.attrib["classname"], row.attrib["name"]) for row in cases] == [junit_key(n) for n in nodes]
        for node, case in zip(nodes, cases, strict=True):
            assert len(case.findall("failure")) == (1 if node == failed else 0)
            assert not case.findall("error") and not case.findall("skipped")
    return projection


def verify_existing_currentness(config: dict, here: Path, current_source: dict, current: dict) -> dict:
    projection = verify_observation(config, here)
    previous = read_record(projection, "candidate-existing-execution.json")
    original = read_record(projection, "source-before.json")
    assert original["source_sha"] == OLD_SOURCE and original["source_tree"] == OLD_TREE
    assert current_source["source_sha"] == config["source_sha"]
    assert current_source["source_tree"] == config["source_tree"]
    before, after = original["files"], current_source["files"]
    assert before.keys() == after.keys() and len(after) == 4567
    changed = [path for path in before if before[path] != after[path]]
    assert changed == [config["source_route_witness"]], changed
    assert current["mode"] == "collection_only" and not current["body_reports"]
    assert current["source_commit"] == config["source_sha"] and current["source_tree"] == config["source_tree"]
    assert current["comparison"] == previous["comparison"]
    assert current["actual_selector_counts"] == previous["actual_selector_counts"]
    assert current["repeated_root_import_evidence"] == previous["repeated_root_import_evidence"]
    assert current["raw_origins"] == previous["raw_origins"]
    assert config["source_route_witness"] not in previous["source_files"]
    assert current["source_files"] == previous["source_files"]
    assert len(previous["source_files"]) == 33
    return {
        "schema": "pr2974-package-existing17-currentness.v1",
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "original_run_id": 35446100641, "original_job_id": 105905167726,
        "original_source_sha": OLD_SOURCE, "original_source_tree": OLD_TREE,
        "previous_observation_sha256": config["previous_finite_observation_sha256"],
        "original_execution_snapshot_sha256": projection["files"]["candidate-existing-execution.json"]["sha256"],
        "original_existing_passed_cases": 17, "current_existing_body_execution": False,
        "current_17_collection_equals_actual_passing_contract": True,
        "current_raw_origins_and_all_33_observed_sources_equal": True,
        "only_source_delta": changed, "new_case_failure_retained": FAILED_NODE,
        "known_corpus_performance_contract": "failed", "qualification_complete": False,
    }
