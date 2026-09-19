"""Admit the exact formatter output and source-selected queue closure without imports."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SOURCE, sha256, write_json

def git_tree(files: dict[str, dict[str, object]]) -> str:
    root = {}
    for path, record in files.items():
        parts = path.split("/")
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
        assert parts[-1] not in directory
        directory[parts[-1]] = (record["mode"], record["git_blob"])

    def encode(directory):
        body = bytearray()
        entries = sorted(directory.items(), key=lambda item: (
            item[0] + ("/" if isinstance(item[1], dict) else "")).encode("utf-8"))
        for name, value in entries:
            mode, identity = ("40000", encode(value)) if isinstance(value, dict) else value
            body.extend(mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(identity))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()

    return encode(root)



def pinned_json(field: str) -> dict:
    expected = CONFIG[field]
    raw = (HERE / expected["path"]).read_bytes()
    assert len(raw) == expected["bytes"] and sha256(raw) == expected["sha256"], field
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected["git_blob"]
    return json.loads(raw)


def _paths(root: Path, patterns: list[str], excludes: list[str] | None = None) -> set[str]:
    excluded = {path for pattern in excludes or [] for path in root.glob(pattern) if path.is_file()}
    return {
        path.relative_to(root).as_posix()
        for pattern in patterns
        for path in root.glob(pattern)
        if path.is_file() and path not in excluded
    }



def repaired_anchor(observed: dict) -> tuple[dict, dict]:
    pinned = CONFIG["source_repair_packet"]
    raw = pinned["content"].encode("utf-8")
    assert len(raw) == pinned["bytes"] and sha256(raw) == pinned["sha256"]
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pinned["git_blob"]
    proof = json.loads(raw)
    assert proof["parent_commit"] == CONFIG["source_parent"] == CONFIG["formatter_output_source"]["commit"]
    assert proof["parent_tree"] == CONFIG["source_parent_tree"] == CONFIG["formatter_output_source"]["tree"]
    assert proof["expected_tree"] == CONFIG["source_tree"]
    path = proof["after"]["path"]
    assert proof["changed_paths"] == [path] and path == "tests/test_python_capability_cleanup_gate.py"
    before, after = proof["before"], proof["after"]
    actual = (SOURCE / path).read_bytes()
    assert actual == after["content"].encode("utf-8")
    assert sha256(actual) == after["sha256"] == observed[path]["sha256"]
    reverted = actual.decode("utf-8")
    for operation in reversed(proof["operations"]):
        assert reverted.count(operation["after"]) == 1
        reverted = reverted.replace(operation["after"], operation["before"])
    assert reverted == before["content"] and sha256(reverted.encode()) == before["sha256"]
    old_ast = ast.parse(reverted, type_comments=True)
    new_ast = ast.parse(actual.decode("utf-8"), type_comments=True)
    functions = [node for node in old_ast.body if isinstance(node, ast.FunctionDef)
                 and node.name == "test_cleanup_contract_covers_every_scoped_hook_capability"]
    assert len(functions) == 1
    for old, new in ((106, 108), (5, 7)):
        constants = [node for node in ast.walk(functions[0])
                     if isinstance(node, ast.Constant) and type(node.value) is int and node.value == old]
        assert len(constants) == 1
        constants[0].value = new
    assert ast.dump(old_ast, include_attributes=False) == ast.dump(new_ast, include_attributes=False)
    contract = json.loads((SOURCE / "docs/guard/contracts/python-capability-ownership.v1.json").read_bytes())
    scope = _paths(SOURCE, contract["scope_globs"])
    owners = {}
    for capability in contract["capabilities"]:
        members = _paths(SOURCE, capability["patterns"], capability.get("exclude_patterns"))
        for member in members:
            assert member not in owners
            owners[member] = capability["id"]
    assert scope == set(owners) and len(scope) == 108
    counts = {name: sum(owner == name for owner in owners.values()) for name in sorted(set(owners.values()))}
    assert counts == {"hook_control_and_transport": 82, "python_reference_oracle": 17,
                      "hook_evidence_persistence": 7, "legacy_python_resident_transport": 2}
    selected = proof["source_selected_count_proof"]
    assert sorted(scope) == selected["scope_paths"] and counts == selected["capabilities"]
    for group in selected["owner_paths"]:
        assert sorted(path for path, owner in owners.items() if owner == group["id"]) == group["paths"]
    anchor = dict(observed)
    anchor[path] = {key: before[key] for key in ("git_blob", "sha256", "bytes", "mode")}
    assert git_tree(anchor) == CONFIG["source_parent_tree"]
    return anchor, {"passed": True, "path": path, "before_sha256": before["sha256"],
                    "after_sha256": after["sha256"], "whole_file_inverse": True,
                    "only_two_expected_integer_constants_changed_in_full_ast": True,
                    "scope_files": 108, "capabilities": counts,
                    "scope": "Actual Path.glob source inventory and syntax; GATE.run remains a separate command."}


def prove() -> dict:
    assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
    assert sys.version.split()[0] == CONFIG["python_version"]
    before = json.loads((REPORT / "source-before.json").read_bytes())
    assert before["source_sha"] == CONFIG["source_sha"] and before["source_tree"] == CONFIG["source_tree"]
    observed = before["files"]
    anchor, repair = repaired_anchor(observed)
    proof = pinned_json("formatter")
    binding = CONFIG["formatter"]
    assert proof["source_commit"] == binding["source_sha"]
    assert proof["input_tree"] == binding["input_tree"]
    assert proof["post_format_tree"] == binding["post_format_tree"] == CONFIG["source_parent_tree"]
    assert proof["harness_commit"] == binding["harness_sha"]
    assert (proof["run_id"], proof["run_attempt"]) == (binding["run_id"], binding["run_attempt"])
    assert proof["harvest_passed"] is True and proof["qualification_complete"] is False
    outcome = proof["job_outcome"]
    assert outcome["passed"] is True and outcome["source_unchanged"] is True and outcome["error"] is None
    assert outcome["all_original_owned_groups_retired"] is True
    assert [row["name"] for row in outcome["steps"]] == binding["expected_commands"]
    assert all(row["passed"] is True and row["returncode"] == 0 and not row["timed_out"]
               and row["group_cleanup"]["passed"] is True for row in outcome["steps"])
    assert proof["environment_before"] == proof["environment_after"]
    assert proof["environment_before"]["project_imports"] == []
    original, formatted = proof["full_input_files"], proof["full_post_format_files"]
    assert len(original) == len(formatted) == CONFIG["tracked_files"]
    assert set(original) == set(formatted) and formatted == anchor
    assert git_tree(original) == binding["input_tree"] and git_tree(formatted) == CONFIG["source_parent_tree"]
    assert git_tree(observed) == CONFIG["source_tree"]
    scope = CONFIG["partition_input_files"]
    assert set(proof["files"]) == set(scope) - {repair["path"]} and len(scope) == 20
    changed = sorted(path for path in original if original[path] != formatted[path])
    assert changed == proof["changed_paths"] and len(changed) == 10
    assert set(changed) <= set(CONFIG["historical_format_paths"])
    bridges = {row["path"]: row for row in proof["bridges"]}
    assert len(bridges) == len(proof["bridges"]) == 12 and set(bridges) == set(CONFIG["historical_format_paths"])
    syntax = {}
    for path, expected in scope.items():
        raw = (SOURCE / path).read_bytes()
        if path != repair["path"]:
            assert raw == proof["files"][path]["content"].encode("utf-8"), path
        assert sha256(raw) == expected["sha256"] == observed[path]["sha256"]
        assert len(raw) == expected["bytes"] and observed[path]["git_blob"] == expected["git_blob"]
        if path in bridges:
            bridge = bridges[path]
            assert bridge["before_sha256"] == original[path]["sha256"]
            assert bridge["after_sha256"] == formatted[path]["sha256"]
            for key in ("passed", "canonical_tokens_equal", "comments_and_statement_token_anchors_equal",
                        "full_ast_equal_including_type_comments_and_type_ignore_line_fields",
                        "within_500_physical_lines"):
                assert bridge[key] is True, (path, key)
            parsed = ast.parse(raw.decode("utf-8"), filename=str(SOURCE / path), type_comments=True)
            lines = len(raw.decode("utf-8").splitlines())
            assert lines <= 500, (path, lines)
            syntax[path] = {"sha256": sha256(raw), "physical_lines": lines,
                            "full_current_ast_sha256": sha256(ast.dump(parsed, include_attributes=False).encode()),
                            "syntax_parsed_without_import": True}
        elif path == repair["path"]:
            parsed = ast.parse(raw.decode("utf-8"), filename=str(SOURCE / path), type_comments=True)
            lines = len(raw.decode("utf-8").splitlines())
            assert lines <= 500
            syntax[path] = {"sha256": sha256(raw), "physical_lines": lines,
                            "full_current_ast_sha256": sha256(ast.dump(parsed, include_attributes=False).encode()),
                            "syntax_parsed_without_import": True, "two_literal_correction_proved": True}
        else:
            assert original[path] == formatted[path] == observed[path], path
    queue = proof["queue_source_contract"]
    assert queue["passed"] is True and queue["all_checked_source_bytes_unchanged"] is True
    assert queue["product_imports"] is False and queue["runtime_tests_executed"] is False
    assert queue["whole_byte_inverse"]["complete_original_byte_inverse"] is True
    methods = queue["method_ast_and_full_file_symtable"]
    assert methods["live_qualifications"] == 32 and methods["receiver_annotations"] == 4
    assert len(methods["methods"]) == 4 and len(queue["actual_adjacent_deque_hooks"]) == 5
    closure = pinned_json("queue_closure")
    assert closure["source"] == CONFIG["formatter_output_source"]
    assert len(closure["files"]) == 45
    for path, record in closure["files"].items():
        raw = (SOURCE / path).read_bytes()
        assert raw == record["content"].encode("utf-8")
        assert sha256(raw) == record["sha256"] == observed[path]["sha256"]
        assert observed[path]["git_blob"] == record["git_blob"]
    definitions = closure["selectors"]["definitions"]
    assert len(definitions) == CONFIG["queue_closure"]["expected_source_definitions"] == 43
    assert len({row["selector"] for row in definitions}) == len(definitions)
    assert sum(row["expected_case_count"] for row in definitions) == 58
    assert closure["selectors"]["counts"]["actual_collection"] is False
    assert sum(row["expected_cases"] for row in CONFIG["cohorts"]) == CONFIG["expected_total_cases"] == 169
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    return {"passed": True, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "complete_current_source_map_equal": True, "historical_formatter_evidence": binding,
            "two_literal_source_correction": repair,
            "historical_queue_proof": {"live_qualifications": 32, "methods": 4, "queue_sites": 5},
            "historical_proof_distinction": "The raw queue checker executed before formatting; the current bytes "
                "are bound by the actual strict formatter bridges and fresh whole-source identity.",
            "current_python_syntax": syntax, "queue_closure_files": 45,
            "queue_closure_rebound_unchanged_into_corrected_child": True,
            "source_selected_queue_definitions": 43, "source_selected_queue_expected_cases": 58,
            "source_selected_total_expected_cases": 169, "actual_collection": False,
            "qualification_complete": False, "product_imports": []}


def main() -> int:
    result = {"passed": False, "source_sha": CONFIG["source_sha"], "qualification_complete": False}
    try:
        result = prove()
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    write_json(REPORT / "source-contract.json", result)
    print(json.dumps({"passed": result["passed"], "error": result.get("error")}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
