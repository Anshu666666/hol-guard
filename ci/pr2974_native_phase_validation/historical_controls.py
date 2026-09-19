"""Bind the original 66 Python passes to exact current source without replay."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from common import CONFIG, HERE, REPORT, SOURCE, write_json
from source_repair_contract import verified_prior_source

NEW_PATH = "tests/test_native_slo_rust_phase_sender.py"
NEW_MODULE = "tests.test_native_slo_rust_phase_sender"
NEW_NODES = [
    NEW_PATH + "::test_owned_sender_failure_preserves_bounded_original_stderr[" + label + "]"
    for label in ("complete", "oversize")
]
FAILED_NODES = [
    "tests/test_native_slo_rust_phase_receiver.py::" + name
    for name in (
        "test_live_owned_sender_binds_actual_process_and_exports_only_aggregate_fields",
        "test_sender_identity_mismatches_are_refused[kernel_pid]",
        "test_sender_identity_mismatches_are_refused[generation]",
        "test_sender_identity_mismatches_are_refused[actual_role]",
        "test_same_user_same_executable_outside_owned_fixture_tree_is_refused",
        "test_replayed_frame_cannot_replace_the_last_valid_snapshot",
        "test_data_cap_stops_before_another_receive",
    )
]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pinned(name: str) -> bytes:
    pin = CONFIG["prior_python"][name]
    path = (HERE / pin["path"]).resolve(strict=True)
    assert path.is_relative_to(HERE) and path.parent == HERE / "prior-python"
    raw = path.read_bytes()
    assert len(raw) == pin["bytes"] <= 16 * 1024 * 1024 and digest(raw) == pin["sha256"]
    return raw


def definitions(node: ast.AST, prefix: str = ""):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        qualified = prefix + node.name
        yield qualified, node
        prefix = qualified + ".<locals>."
    elif isinstance(node, ast.ClassDef):
        prefix += node.name + "."
    for child in ast.iter_child_nodes(node):
        yield from definitions(child, prefix)


def original_outcomes(collected: dict, executed: dict, xml_raw: bytes) -> tuple[list, list]:
    pin = CONFIG["prior_python"]
    for mode, value, code in (("collect", collected, 0), ("run", executed, 1)):
        assert value["schema"] == "hol-guard-native-controls-observation.v1"
        assert value["source_sha"] == pin["source_sha"] == CONFIG["source_parent"]
        assert value["source_tree"] == pin["source_tree"]
        assert value["mode"] == mode and value["cohort"] == "python"
        assert value["pytest_exit_code"] == code
        assert value["collection_admitted"] and value["source_unchanged"] and value["binary_unchanged"]
        assert value["error"] is value["evidence_error"] is None and not value["qualification_complete"]
        assert value["execution_collection_matches_prior"] == (mode == "run")
    assert collected["reports"] == [] and collected["contract"] == executed["contract"]
    items = executed["contract"]["collection"]
    nodes = [row["nodeid"] for row in items]
    assert len(nodes) == len(set(nodes)) == 73
    phases = executed["reports"]
    assert [(row["nodeid"], row["when"]) for row in phases] == [
        (node, when) for node in nodes for when in ("setup", "call", "teardown")
    ]
    failed = []
    passed = []
    for index, node in enumerate(nodes):
        rows = phases[index * 3:index * 3 + 3]
        assert all(row["wasxfail"] is None for row in rows)
        assert rows[0]["outcome"] == rows[2]["outcome"] == "passed"
        assert rows[1]["outcome"] in {"passed", "failed"}
        for row in rows:
            if row["outcome"] == "passed":
                assert row["longrepr_bytes"] == 0 and row["failure_file"] is None
            else:
                assert row["longrepr_bytes"] > 0 and row["failure_file"] is not None
        (passed if rows[1]["outcome"] == "passed" else failed).append(node)
    assert failed == FAILED_NODES and len(passed) == 66
    assert b"<!DOCTYPE" not in xml_raw and b"<!ENTITY" not in xml_raw
    xml = ET.fromstring(xml_raw)
    assert xml.tag == "testsuites" and len(xml) == 1 and xml[0].tag == "testsuite"
    suite = xml[0]
    assert {key: int(suite.attrib[key]) for key in ("tests", "failures", "errors", "skipped")} == {
        "tests": 73, "failures": 7, "errors": 0, "skipped": 0,
    }
    cases = list(suite)
    assert len(cases) == 73 and all(case.tag == "testcase" for case in cases)
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [
        (row["junit"]["classname"], row["junit"]["name"]) for row in items
    ]
    for index, (node, case) in enumerate(zip(nodes, cases, strict=True)):
        assert case.find("skipped") is None and case.find("error") is None
        assert len(case.findall("failure")) == (1 if node in failed else 0)
        properties = [[row.attrib["name"], row.attrib["value"]]
                      for row in case.findall("properties/property")]
        assert properties == phases[index * 3 + 2]["user_properties"]
    return passed, failed


def compare_prior_python(current: dict) -> dict:
    collected = json.loads(pinned("collect"))
    executed = json.loads(pinned("run"))
    xml_raw = pinned("junit")
    passed, failed = original_outcomes(collected, executed, xml_raw)
    before, after = collected["contract"], current["contract"]
    assert current["mode"] == "collect" and current["cohort"] == "python_inventory"
    assert current["pytest_exit_code"] == 0 and current["collection_admitted"]
    assert current["error"] is current["evidence_error"] is None and not current["reports"]
    assert current["source_unchanged"] and current["binary_unchanged"]
    assert after["source_sha"] == CONFIG["source_sha"] and after["source_tree"] == CONFIG["source_tree"]
    assert after["selectors"] == [*before["selectors"], NEW_PATH]
    old_nodes = [row["nodeid"] for row in before["collection"]]
    new_nodes = [row["nodeid"] for row in after["collection"]]
    assert new_nodes == [*old_nodes, *NEW_NODES]
    assert after["conftests"] == before["conftests"]
    cache = {}
    source_rows = {}
    mapped_definitions = set()

    def prior_bytes(relative: str) -> bytes:
        if relative not in cache:
            raw = (SOURCE / relative).read_bytes()
            restored = verified_prior_source(relative, raw, config=CONFIG, here=HERE, source=SOURCE)
            cache[relative] = (raw, restored)
            source_rows[relative] = {
                "current_sha256": digest(raw), "current_bytes": len(raw),
                "prior_sha256": digest(restored), "prior_bytes": len(restored),
                "exact_committed_source_inverse": True,
            }
        return cache[relative][1]

    def mapped_source(row: dict) -> dict:
        if "namespace_paths" in row:
            return row
        assert row["origin"] == "candidate"
        prior = prior_bytes(row["path"])
        raw = cache[row["path"]][0]
        assert row["sha256"] == digest(raw) and row["bytes"] == len(raw)
        return {**row, "sha256": digest(prior), "bytes": len(prior)}

    for name in ("definitions",):
        for contract in (before, after):
            for sha, value in contract[name].items():
                assert digest(value.encode()) == sha
    assert set(after["providers"]) == set(before["providers"]) | {"candidate/" + NEW_PATH}
    for key, old in before["providers"].items():
        now = after["providers"][key]
        raw = now["content"].encode("utf-8")
        assert digest(raw) == now["sha256"] and len(raw) == now["bytes"]
        assert digest(old["content"].encode("utf-8")) == old["sha256"]
        if now["origin"] == "candidate":
            mapped = mapped_source({name: value for name, value in now.items() if name != "content"})
            mapped["content"] = prior_bytes(now["path"]).decode("utf-8")
            assert mapped == old
        else:
            assert now["origin"] == "owned_dependency" and now == old

    def mapped_function(now: dict, old: dict) -> dict:
        key = now["origin"] + "/" + now["path"]
        current_provider = after["providers"][key]
        assert all(now[name] == current_provider[name] for name in ("origin", "path", "sha256", "bytes"))
        if now["origin"] == "owned_dependency":
            assert now == old
            mapped_definitions.add(old["definition_ast_sha256"])
            return now
        restored = prior_bytes(now["path"]).decode("utf-8")
        original_nodes = list(definitions(ast.parse(restored, type_comments=True)))
        matches = [
            node for qualified, node in original_nodes if qualified == now["code_qualname"]
            and min([node.lineno, *(mark.lineno for mark in node.decorator_list)])
            <= old["first_line"] <= node.lineno
        ]
        assert len(matches) == 1, (now["path"], now["code_qualname"])
        node = matches[0]
        encoded = ast.dump(node, include_attributes=False)
        sha = digest(encoded.encode())
        assert before["definitions"][sha] == encoded
        mapped_definitions.add(sha)
        result = mapped_source({name: value for name, value in now.items()})
        result.update(first_line=old["first_line"], definition_end_line=node.end_lineno,
                      signature_ast=ast.dump(node.args, include_attributes=False),
                      definition_ast_sha256=sha)
        assert result == old
        return result

    for now, old in zip(after["collection"][:73], before["collection"], strict=True):
        result = copy.deepcopy(now)
        result["function"] = mapped_function(now["function"], old["function"])
        assert set(now["fixtures"]) == set(old["fixtures"])
        for name, current_fixtures in now["fixtures"].items():
            original_fixtures = old["fixtures"][name]
            assert len(current_fixtures) == len(original_fixtures)
            for index, (current_fixture, original_fixture) in enumerate(
                zip(current_fixtures, original_fixtures, strict=True)
            ):
                result["fixtures"][name][index]["function"] = mapped_function(
                    current_fixture["function"], original_fixture["function"]
                )
                if "callable" in current_fixture["ids"]:
                    result["fixtures"][name][index]["ids"]["callable"] = mapped_function(
                        current_fixture["ids"]["callable"], original_fixture["ids"]["callable"]
                    )
        assert result == old, now["nodeid"]
    assert mapped_definitions == set(before["definitions"])
    for old_map, current_map in (
        (before["module_origins"], after["module_origins"]),
        (executed["source_origins_after"], current["source_origins_after"]),
    ):
        assert set(current_map) == set(old_map) | {NEW_MODULE}
        assert current_map[NEW_MODULE]["path"] == NEW_PATH
        for name, old in old_map.items():
            assert mapped_source(current_map[name]) == old, name
    old_inputs = executed["source_inputs_after"]
    current_inputs = current["source_inputs_after"]
    assert set(current_inputs) == set(old_inputs) | {NEW_PATH}
    for relative, expected in old_inputs.items():
        original = prior_bytes(relative)
        assert digest(cache[relative][0]) == current_inputs[relative]
        assert digest(original) == expected, relative
    result = {
        "schema": "hol-guard-native-original-python-currentness.v1", "passed": True,
        "prior_source_sha": CONFIG["prior_python"]["source_sha"], "current_source_sha": CONFIG["source_sha"],
        "prior_collect_sha256": CONFIG["prior_python"]["collect"]["sha256"],
        "prior_run_sha256": CONFIG["prior_python"]["run"]["sha256"],
        "prior_junit_sha256": digest(xml_raw), "original_cases": 73, "original_phases": 219,
        "original_passed_nodes": passed, "original_failed_nodes": failed, "new_nodes": NEW_NODES,
        "current_collection_cases": 75, "all73_original_collection_rows_equal_through_exact_inverse": True,
        "original66_passing_bodies_reexecuted": False, "historical66_source_compatible": True,
        "source_provider_and_loaded_module_binding": source_rows,
        "prior_binary_attribution": before["binaries"], "current_binary_attribution": after["binaries"],
        "binary_record_excluded_from_historical_source_comparison": (
            "Python synthetic controls do not require or qualify native artifacts; both actual records retained."
        ),
        "raw_current_collection_preserved": True, "fixture_params_marks_and_callable_metadata_preserved": True,
        "no_new_original66_runtime_or_full_environment_credit": True,
        "original_failed_workflow_preserved": True, "qualification_complete": False,
    }
    write_json(REPORT / "historical-python-currentness.json", result)
    return result
