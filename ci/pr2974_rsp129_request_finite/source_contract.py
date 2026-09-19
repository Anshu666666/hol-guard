"""Admit an exact one-file correction over actual formatter output before imports."""

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
from common import CONFIG, REPORT, SOURCE, commit_headers, write_json


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
              "scope": "Exact one-file source correction, verified formatter ancestor and first finite selector admission."}
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        assert sys.version.split()[0] == CONFIG["python_version"]
        for key in ("source_sha", "source_tree", "source_parent"):
            require_identity(CONFIG[key], 40)
        assert CONFIG["source_parent"] == CONFIG["formatter_source"]["commit"]
        assert CONFIG["source_parent_tree"] == CONFIG["formatter_source"]["tree"]
        assert commit_headers(CONFIG["source_parent"], SOURCE) == {
            "tree": CONFIG["formatter_source"]["tree"],
            "parents": [CONFIG["formatter_input"]["commit"]],
        }
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
        assert projection["post_format_tree"] == CONFIG["formatter_source"]["tree"]
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
        repair_record = CONFIG["source_repair"]
        repair_raw = (HERE / repair_record["path"]).read_bytes()
        assert len(repair_raw) == repair_record["bytes"] and digest(repair_raw) == repair_record["sha256"]
        assert hashlib.sha1(b"blob " + str(len(repair_raw)).encode() + b"\0" + repair_raw).hexdigest() == repair_record["git_blob"]
        repair = json.loads(repair_raw)
        assert repair["schema"] == "rsp129_first_finite_exact_source_correction_v1"
        assert repair["source_parent"] == CONFIG["source_parent"]
        assert repair["source_parent_tree"] == CONFIG["source_parent_tree"]
        assert repair["expected_source_tree"] == CONFIG["source_tree"]
        assert repair["source_leaf_count"] == 4629 and repair["unchanged_other_leaves"] == 4628
        assert repair["original_terminal"] == CONFIG["original_failed_attempt"]["terminal"]
        assert repair["original_run_id"] == CONFIG["original_failed_attempt"]["run_id"]
        assert repair["original_job_id"] == CONFIG["original_failed_attempt"]["job_id"]
        change = repair["complete_one_file_change"]
        changed_path = change["path"]
        assert changed_path == "scripts/native_slo_workspace_decision.py"
        before_identity, after_identity = change["before_identity"], change["after_identity"]
        restored_text = (SOURCE / changed_path).read_text(encoding="utf-8")
        assert restored_text == change["after"] and len(change["edits"]) == 4
        assert digest(restored_text.encode()) == after_identity["sha256"]
        for edit in reversed(change["edits"]):
            offset = edit["offset"]
            assert type(offset) is int and offset >= 0
            assert restored_text[offset:offset + len(edit["after"])] == edit["after"]
            restored_text = restored_text[:offset] + edit["before"] + restored_text[offset + len(edit["after"]):]
        assert restored_text == change["before"]
        restored = restored_text.encode()
        assert digest(restored) == before_identity["sha256"] and len(restored) == before_identity["bytes"]
        restored_blob = hashlib.sha1(b"blob " + str(len(restored)).encode() + b"\0" + restored).hexdigest()
        assert restored_blob == before_identity["git_blob"]
        ancestor_files = dict(current["files"])
        assert ancestor_files[changed_path] == {
            key: after_identity[key] for key in ("git_blob", "sha256", "bytes")
        } | {"mode": "100644"}
        ancestor_files[changed_path] = {
            key: before_identity[key] for key in ("git_blob", "sha256", "bytes")
        } | {"mode": "100644"}
        assert ancestor_files == projection["full_post_format_files"]
        assert restored == projection["files"][changed_path]["content"].encode("utf-8")
        root_fixture = CONFIG["ancestral_root_fixture"]
        assert root_fixture["path"] == "conftest.py"
        root_raw = (SOURCE / "conftest.py").read_bytes()
        assert digest(root_raw) == root_fixture["sha256"] == current["files"]["conftest.py"]["sha256"]
        assert len(root_raw) == root_fixture["bytes"]
        assert current["files"]["conftest.py"]["git_blob"] == root_fixture["git_blob"]
        root_tree = ast.parse(root_raw.decode("utf-8"), filename="conftest.py", type_comments=True)
        root_autouse = [node for node in root_tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "_spawn_package_shim_sqlite_lock_holder"]
        assert len(root_autouse) == 1
        assert len(root_autouse[0].decorator_list) == 1
        decorator = root_autouse[0].decorator_list[0]
        assert isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
        assert isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "pytest"
        assert decorator.func.attr == "fixture" and not decorator.args
        assert len(decorator.keywords) == 1 and decorator.keywords[0].arg == "autouse"
        assert isinstance(decorator.keywords[0].value, ast.Constant) and decorator.keywords[0].value.value is True
        assert root_autouse[0].args.posonlyargs == [] and [
            arg.arg for arg in root_autouse[0].args.args] == ["request", "monkeypatch"]
        assert set(CONFIG["expected_autouse_fixtures"]) == {
            "_spawn_package_shim_sqlite_lock_holder", "_default_unit_tests_to_python_rollback",
            "_explicit_python_differential_oracle", "_reset_guard_sync_resolver_override",
            "_isolate_lifecycle_authority_home", "_isolate_trust_attestation_env",
            "_isolate_daemon_background_refresh_workers", "_policy_integrity_keyring_for_selected_tests",
        }
        assert len(CONFIG["expected_autouse_fixtures"]) == 8
        result["source_repair"] = {
            "path": changed_path, "exact_four_edit_inverse": True,
            "before_sha256": before_identity["sha256"], "after_sha256": after_identity["sha256"],
            "full_formatter_ancestor_map_matches": True, "all_4628_other_leaves_unchanged": True,
            "fresh_current_source_ast_required": True, "unchanged_root_fixture_sha256": digest(root_raw),
            "original_failed_attempt": CONFIG["original_failed_attempt"],
        }
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
        changed = sorted(path for path in ancestor_files
                         if ancestor_files[path] != projection["full_input_files"][path])
        assert changed == projection["changed_paths"] and set(changed) <= set(CONFIG["format_paths"])
        for relative, expected in inputs.items():
            assert projection["full_input_files"][relative] == expected
            original = complete["inputs"][relative]
            before = original["before_content"].encode("utf-8")
            assert len(before) == original["before_bytes"] == expected["bytes"]
            assert digest(before) == original["before_sha256"] == expected["sha256"]
            current_after = (SOURCE / relative).read_bytes()
            assert digest(current_after) == current["files"][relative]["sha256"]
            assert len(current_after) == current["files"][relative]["bytes"]
            after = restored if relative == changed_path else current_after
            final = projection["files"][relative]
            assert after == final["content"].encode("utf-8")
            assert len(after) == final["bytes"] == ancestor_files[relative]["bytes"]
            assert digest(after) == final["sha256"] == ancestor_files[relative]["sha256"]
            assert final["git_blob"] == ancestor_files[relative]["git_blob"]
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
            current_source_ast = ast_text(current_after, relative)
            assert len(current_after.decode().splitlines()) <= 500
            result["python_sources"][relative] = {
                "sha256": digest(current_after), "bytes": len(current_after),
                "module_ast_sha256": digest(current_source_ast.encode()),
                "physical_lines": len(current_after.decode().splitlines()),
                "full_preformat_ast_equal": current_source_ast == before_ast,
                "full_formatter_ancestor_ast_equal_after_exact_source_inverse": True,
                "current_source_parsed": True}
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
                      formatter_input=CONFIG["formatter_input"], exact_formatter_ancestor_tree=True,
                      exact_current_source_inverse=True,
                      complete_current_source_map_matches=True, declared_test_definitions=declarations,
                      prospective_cases=88, actual_cases_collected=False, actual_bodies_executed=False)
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    write_json(REPORT / "source-contract.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
