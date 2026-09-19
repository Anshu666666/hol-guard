"""Admit exact formatter output and finite selectors without project imports."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import CONFIG, REPORT, SOURCE, write_json


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ast_text(raw: bytes, path: str) -> str:
    return ast.dump(ast.parse(raw.decode("utf-8"), filename=path, type_comments=True),
                    include_attributes=False)


def require_identity(value: object, length: int) -> None:
    assert isinstance(value, str) and len(value) == length
    assert all(character in "0123456789abcdef" for character in value)


def main() -> int:
    result = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
              "passed": False, "python_sources": {}, "qualification_complete": False,
              "scope": "Exact immutable formatter output, syntax and first finite selector admission."}
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        assert sys.version.split()[0] == CONFIG["python_version"]
        for key in ("source_sha", "source_tree", "source_parent"):
            require_identity(CONFIG[key], 40)
        assert CONFIG["source_parent"] == CONFIG["formatter_input"]["commit"]
        assert CONFIG["source_parent_tree"] == CONFIG["formatter_input"]["tree"]
        record = CONFIG["formatter_projection"]
        require_identity(record["sha256"], 64)
        require_identity(record["git_blob"], 40)
        path = HERE / record["path"]
        raw = path.read_bytes()
        assert len(raw) == record["bytes"] and digest(raw) == record["sha256"]
        assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == record["git_blob"]
        projection = json.loads(raw)
        assert projection["schema"] == "pr2974-rsp129-request-format-log-projection-v1"
        assert projection["source_commit"] == CONFIG["formatter_input"]["commit"]
        assert projection["input_tree"] == CONFIG["formatter_input"]["tree"]
        assert projection["harness_commit"] == CONFIG["formatter_input"]["harness"]
        assert str(projection["run_id"]) == str(CONFIG["formatter_input"]["run_id"])
        assert str(projection["run_attempt"]) == "1"
        assert projection["post_format_tree"] == CONFIG["source_tree"]
        assert projection["harvest_passed"] is True
        outcome = projection["job_outcome"]
        assert outcome["passed"] is True and outcome["source_unchanged"] is True
        assert outcome["harness_sha"] == CONFIG["formatter_input"]["harness"]
        assert outcome["source_sha"] == CONFIG["formatter_input"]["commit"]
        assert outcome["source_tree"] == CONFIG["formatter_input"]["tree"]
        assert str(outcome["run_id"]) == str(CONFIG["formatter_input"]["run_id"])
        assert str(outcome["run_attempt"]) == "1"
        assert outcome["all_original_owned_groups_retired"] is True
        assert [row["name"] for row in outcome["steps"]] == CONFIG["formatter_input"]["commands"]
        assert len(outcome["steps"]) == 7 and all(
            row["passed"] is True and row["returncode"] == 0 and row["timed_out"] is False
            and row["group_cleanup"]["passed"] is True for row in outcome["steps"]
        )
        assert projection["environment_before"] == projection["environment_after"]
        assert projection["environment_before"]["distributions"] == {"ruff": CONFIG["ruff_version"]}
        current = json.loads((REPORT / "source-before.json").read_bytes())
        assert current["source_sha"] == CONFIG["source_sha"] and current["source_tree"] == CONFIG["source_tree"]
        assert current["files"] == projection["full_post_format_files"]
        assert len(current["files"]) == len(projection["full_input_files"]) == CONFIG["tracked_files"] == 4629
        inputs = CONFIG["preformat_source_files"]
        assert set(inputs) == set(CONFIG["partition_input_files"]) == set(projection["files"])
        assert len(inputs) == 7 and len(CONFIG["format_paths"]) == 6
        assert CONFIG["format_paths"] == sorted(path for path in inputs if path.endswith(".py"))
        complete = projection["complete_scope_evidence"]
        assert set(complete["inputs"]) == set(inputs)
        assert complete["project_test_bodies_executed"] is False
        bridge_rows = {row["path"]: row for row in projection["bridges"]}
        assert len(bridge_rows) == len(projection["bridges"]) == 6
        assert set(bridge_rows) == set(CONFIG["format_paths"])
        changed = sorted(path for path in current["files"]
                         if current["files"][path] != projection["full_input_files"][path])
        assert changed == projection["changed_paths"] and set(changed) <= set(CONFIG["format_paths"])
        for relative, expected in inputs.items():
            assert projection["full_input_files"][relative] == expected
            original = complete["inputs"][relative]
            before = original["before_content"].encode("utf-8")
            assert len(before) == original["before_bytes"] == expected["bytes"]
            assert digest(before) == original["before_sha256"] == expected["sha256"]
            after = (SOURCE / relative).read_bytes()
            final = projection["files"][relative]
            assert after == final["content"].encode("utf-8")
            assert len(after) == final["bytes"] == current["files"][relative]["bytes"]
            assert digest(after) == final["sha256"] == current["files"][relative]["sha256"]
            assert final["git_blob"] == current["files"][relative]["git_blob"]
            assert original["format_selected"] is (relative in CONFIG["format_paths"])
            if relative not in CONFIG["format_paths"]:
                assert before == after and original["strict_bridge"] is None
                continue
            bridge, summary = original["strict_bridge"], bridge_rows[relative]
            assert bridge["path"] == summary["path"] == relative
            assert bridge["passed"] is summary["passed"] is True
            for value in (bridge, summary):
                assert value["before_sha256"] == expected["sha256"]
                assert value["after_sha256"] == final["sha256"]
                assert value["full_ast_equal_including_type_comments_and_type_ignore_line_fields"] is True
                assert value["canonical_tokens_equal"] is True
                assert value["comments_and_statement_token_anchors_equal"] is True
            before_ast, current_ast = ast_text(before, relative), ast_text(after, relative)
            assert before_ast == current_ast
            assert digest(current_ast.encode()) == bridge["full_ast_sha256"]["after"]
            assert bridge["full_ast_sha256"]["before"] == bridge["full_ast_sha256"]["after"]
            assert summary["within_500_physical_lines"] is True and len(after.decode().splitlines()) <= 500
            result["python_sources"][relative] = {
                "sha256": digest(after), "bytes": len(after), "module_ast_sha256": digest(current_ast.encode()),
                "physical_lines": len(after.decode().splitlines()), "full_preformat_ast_equal": True}
        declarations = {}
        for cohort in CONFIG["cohorts"]:
            assert len(cohort["modules"]) == 1 and cohort["selectors"] == cohort["modules"]
            relative = cohort["modules"][0]
            tree = ast.parse((SOURCE / relative).read_text(), filename=relative, type_comments=True)
            actual = [node.name for node in tree.body
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")]
            expected = [row["name"] for row in cohort["definitions"]]
            assert actual == expected and len(actual) == len(set(actual)), relative
            assert sum(row["expected_cases"] for row in cohort["definitions"]) == cohort["expected_cases"]
            assert cohort["selection_counts"] == [
                {"selector": relative + "::" + row["name"], "expected_cases": row["expected_cases"]}
                for row in cohort["definitions"]]
            declarations[cohort["name"]] = actual
        assert len(CONFIG["cohorts"]) == 3
        assert sum(row["expected_cases"] for row in CONFIG["cohorts"]) == CONFIG["expected_total_cases"] == 88
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules)
        result.update(passed=True, formatter_projection_sha256=record["sha256"],
                      formatter_input=CONFIG["formatter_input"], exact_post_format_tree=True,
                      complete_current_source_map_matches=True, declared_test_definitions=declarations,
                      prospective_cases=88, actual_cases_collected=False, actual_bodies_executed=False)
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    write_json(REPORT / "source-contract.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
