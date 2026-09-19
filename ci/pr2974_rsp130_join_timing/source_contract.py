"""Prove exact RSP-130 source scope without importing project modules."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, REPORT, SOURCE, sha256, write_json
from format_bridge import prove


def only_function(module: ast.Module, name: str) -> ast.FunctionDef:
    matches = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(matches) == 1, name
    return matches[0]


def dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def main() -> int:
    output = Path(sys.argv[1])
    result = {"schema": "pr2974-rsp130-join-source-contract.v1", "passed": False,
              "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
              "qualification_complete": False, "project_imports": [], "files": []}
    try:
        assert sys.version.split()[0] == CONFIG["python_version"]
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules)
        packet_path = Path(__file__).resolve().with_name("source-preparation.json")
        packet_bytes = packet_path.read_bytes()
        assert sha256(packet_bytes) == CONFIG["source_proof"]["preparation_sha256"]
        evidence = Path(__file__).resolve().with_name("formatter-evidence.json").read_bytes()
        assert sha256(evidence) == CONFIG["formatter_evidence_sha256"]
        packet = json.loads(packet_bytes)
        before = {item["path"]: item for item in packet["prototype_source"]["before_files"]}
        after = packet["prototype_source"]["files"]
        edits = packet["prototype_source"]["inverse_steps"]
        for record in after:
            relative = record["path"]
            current = (SOURCE / relative).read_bytes()
            current_pin = CONFIG["candidate_files"][relative]
            assert len(current) == current_pin["bytes"] and sha256(current) == current_pin["sha256"]
            unformatted = record["text"].encode("utf-8")
            assert len(unformatted) == record["bytes"] and sha256(unformatted) == record["sha256"]
            bridge = prove(unformatted, current, relative, REPORT / "final-format-bridges")
            assert bridge["passed"], relative
            result.setdefault("format_bridges", []).append(bridge)
            parent = (BASELINE / relative).read_bytes()
            assert parent.decode("utf-8") == before[relative]["text"]
            assert sha256(parent) == before[relative]["sha256"]
            restored = record["text"]
            for edit in reversed([row for row in edits if row["path"] == relative]):
                assert restored.count(edit["after"]) == 1, relative
                restored = restored.replace(edit["after"], edit["before"], 1)
            assert restored.encode("utf-8") == parent, relative
            old_ast = ast.parse(parent.decode("utf-8"), filename=relative, type_comments=True)
            current_ast = ast.parse(current.decode("utf-8"), filename=relative, type_comments=True)
            inverse_ast = ast.parse(restored, filename=relative, type_comments=True)
            assert dump(inverse_ast) == dump(old_ast)
            result["files"].append({
                "path": relative, "before_sha256": sha256(parent), "after_sha256": sha256(current),
                "unformatted_full_inverse_bytes_equal": True, "full_inverse_ast_equal_after_explicit_format_bridge": True,
                "before_ast_sha256": hashlib.sha256(dump(old_ast).encode()).hexdigest(),
                "candidate_ast_sha256": hashlib.sha256(dump(current_ast).encode()).hexdigest(),
            })
            if relative.endswith("/aibom_cli.py"):
                old = only_function(old_ast, "sync_aibom_snapshots")
                new = only_function(current_ast, "sync_aibom_snapshots")
                positions = [
                    index for index, node in enumerate(old.body)
                    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                    and node.target.id == "content_sources_by_snapshot"
                ]
                assert len(positions) == 1
                index = positions[0]
                original = old.body[index:index + 2]
                assert isinstance(original[1], ast.For)
                assignment, branch = new.body[index:index + 2]
                expected_assignment = ast.parse(
                    "indexed_content_sources = _indexed_primary_content_sources("
                    "snapshots, primary_content_sources, tuple_factory=tuple)"
                ).body[0]
                assert dump(assignment) == dump(expected_assignment)
                assert isinstance(branch, ast.If)
                assert dump(branch.test) == dump(ast.parse("indexed_content_sources is None", mode="eval").body)
                assert list(map(dump, branch.body)) == list(map(dump, original))
                assert list(map(dump, branch.orelse)) == list(map(dump, ast.parse(
                    "content_sources_by_snapshot = indexed_content_sources"
                ).body))
                reconstructed = copy.deepcopy(new)
                reconstructed.body[index:index + 2] = copy.deepcopy(original)
                assert dump(reconstructed) == dump(old)
                assert isinstance(old.body[index - 1], ast.Assign)
                assert "_batch_inventory_events" in dump(old.body[index - 1])
                result["caller"] = {
                    "complete_signature_body_reconstructed": True,
                    "original_inline_fallback_ast_equal": True,
                    "all_statements_before_after_join_equal": True,
                    "join_after_original_batch_callback": True,
                    "original_key_load_formula": "2*S*P+S",
                    "candidate_key_load_formula_to_measure": "S+P",
                }
            else:
                helper = only_function(current_ast, "_indexed_primary_content_sources")
                prepared_helper = only_function(
                    ast.parse(packet["prototype_source"]["helper"], type_comments=True),
                    "_indexed_primary_content_sources",
                )
                assert dump(helper) == dump(prepared_helper)
                assert not any(isinstance(node, (ast.Global, ast.Nonlocal)) for node in ast.walk(helper))
                result["helper"] = {
                    "prepared_full_ast_equal": True, "no_global_or_nonlocal_write": True,
                    "semantic_scope": "Admitted plain-key API only; actual finite/operation execution remains required.",
                }
        proposed_tests = packet["test_source"]
        actual_tests = (SOURCE / proposed_tests["path"]).read_bytes()
        current_test_pin = CONFIG["candidate_files"][proposed_tests["path"]]
        assert sha256(actual_tests) == current_test_pin["sha256"]
        assert len(actual_tests) == current_test_pin["bytes"]
        original_tests = proposed_tests["text"].encode("utf-8")
        assert sha256(original_tests) == proposed_tests["sha256"]
        assert len(original_tests) == proposed_tests["bytes"]
        bridge = prove(original_tests, actual_tests, proposed_tests["path"], REPORT / "final-format-bridges")
        assert bridge["passed"]
        result["format_bridges"].append(bridge)
        assert len(result["format_bridges"]) == 3
        parsed_tests = ast.parse(actual_tests.decode("utf-8"), type_comments=True)
        result["new_tests"] = {
            "path": proposed_tests["path"], "bytes": len(actual_tests),
            "sha256": sha256(actual_tests),
            "full_ast_sha256": hashlib.sha256(dump(parsed_tests).encode()).hexdigest(),
            "expected_cases": 22, "actual_collection": None, "bodies_executed": False,
        }
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules)
        result["passed"] = True
        result["formatting_evidence_sha256"] = CONFIG["formatter_evidence_sha256"]
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        write_json(output, result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
