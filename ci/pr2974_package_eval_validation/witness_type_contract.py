"""Validate the exact source-witness type repair and the retained first failure."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
import typing


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def restore_witness(current: bytes, here: Path) -> bytes:
    record = json.loads((here / "witness-type-repair.json").read_bytes())
    before = record["before"]["content"].encode("utf-8")
    after = record["after"]["content"].encode("utf-8")
    assert current == after and digest(current) == record["after"]["sha256"]
    assert digest(before) == record["before"]["sha256"]
    assert len(before) == record["before"]["bytes"] and len(after) == record["after"]["bytes"]
    inverse = current.decode("utf-8")
    assert len(record["edits"]) == 3
    for edit in reversed(record["edits"]):
        assert inverse.count(edit["after"]) == 1
        inverse = inverse.replace(edit["after"], edit["before"], 1)
    assert inverse.encode("utf-8") == before

    class Restore(ast.NodeTransformer):
        def __init__(self):
            self.imports = self.annotations = self.casts = 0

        def visit_Module(self, node):
            kept = []
            for value in node.body:
                if isinstance(value, ast.ImportFrom) and value.module == "typing":
                    assert value.level == 0 and len(value.names) == 1
                    assert value.names[0].name == "cast" and value.names[0].asname is None
                    self.imports += 1
                else:
                    kept.append(self.visit(value))
            node.body = kept
            return node

        def visit_AnnAssign(self, node):
            assert isinstance(node.target, ast.Name) and node.target.id == "pending"
            assert node.simple == 1 and node.value is not None
            assert ast.dump(node.annotation) == ast.dump(ast.parse("list[ast.AST]", mode="eval").body)
            self.annotations += 1
            return ast.copy_location(ast.Assign(targets=[node.target], value=node.value, type_comment=None), node)

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "cast":
                assert len(node.args) == 2 and not node.keywords
                assert isinstance(node.args[0], ast.Constant) and node.args[0].value == "evaluator.GuardArtifact"
                self.casts += 1
                return self.visit(node.args[1])
            return self.generic_visit(node)

    original_ast = ast.parse(before, type_comments=True)
    current_ast = ast.parse(current, type_comments=True)
    assert not original_ast.type_ignores and not current_ast.type_ignores
    normalizer = Restore()
    restored = normalizer.visit(copy.deepcopy(current_ast))
    assert (normalizer.imports, normalizer.annotations, normalizer.casts) == (1, 1, 1)
    assert ast.dump(restored, include_attributes=False) == ast.dump(original_ast, include_attributes=False)
    provider_source = inspect.getsource(typing.cast)
    assert inspect.getmodule(typing.cast) is typing
    assert Path(typing.cast.__code__.co_filename).resolve() == Path(typing.__file__).resolve()
    assert ast.dump(ast.parse(provider_source), include_attributes=False) == ast.dump(
        ast.parse(record["typing_cast"]["function_source"]), include_attributes=False)
    value = object()
    assert typing.cast("evaluator.GuardArtifact", value) is value
    return before


def verify_first_failure(config: dict, here: Path) -> dict:
    raw = (here / "first-finite-failure.json").read_bytes()
    assert digest(raw) == config["first_finite_failure_sha256"]
    previous = json.loads(raw)
    assert previous["source_sha"] == config["report_source_sha"]
    assert previous["source_tree"] == config["report_source_tree"]
    assert previous["harness_sha"] == "07c0560d03abcdff90b58fb9400f1f751cba4a00"
    assert previous["run"]["id"] == 35443949519 and previous["run"]["job_id"] == 105899559233
    assert previous["run"]["actual_driver_outcome"] == previous["run"]["workflow_conclusion"] == "failure"
    assert previous["finite_collection_executed"] is False and previous["finite_test_bodies_executed"] == 0
    assert previous["known_original_corpus_performance_contract"] == "failed"
    assert previous["no_corpus_execution_in_this_run"] is True
    assert previous["source_unchanged"] and previous["baseline_source_unchanged"]
    assert previous["environment_before_after_equal"] and previous["all_owned_original_groups_retired"]
    diagnostics = previous["diagnostics"]
    assert diagnostics["summary"]["filesAnalyzed"] == 21 and diagnostics["summary"]["errorCount"] == 3
    errors = diagnostics["generalDiagnostics"]
    assert len(errors) == 3 and all(row["severity"] == "error" for row in errors)
    assert all(row["file"].endswith("/" + config["source_route_witness"]) for row in errors)
    assert [row["range"]["start"]["line"] for row in errors] == [55, 202, 225]
    assert [row["rule"] for row in errors] == ["reportArgumentType", "reportArgumentType", "reportAttributeAccessIssue"]
    commands = previous["actual_commands"]
    assert len(commands) == 17
    assert [row["name"] for row in commands if not row["passed"]] == ["scoped-error-level-types"]
    assert all(not row["timed_out"] and row["group_cleanup"]["passed"] for row in commands)
    return {"run": previous["run"], "receipt_sha256": digest(raw), "type_errors": 3,
            "prior_collection_or_body_credit": False, "known_corpus_performance_contract": "failed"}
