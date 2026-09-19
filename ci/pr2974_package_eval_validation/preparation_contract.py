"""Bind exact formatter bytes, diagnostic comments and the retained partial corpus result."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def verify_preparation(config, here: Path, source: Path) -> dict:
    for relative, expected in config["provenance_inputs"].items():
        assert digest((here / relative).read_bytes()) == expected, relative
    packet = json.loads((here / "formatter-packet.json").read_bytes())
    assert packet["source_commit"] == "f011fe44ab1985797b281d4bfcae2189b72264a6"
    assert packet["input_tree"] == "161c098f857340d9ff5c2b2c33d49b399cb539f1"
    assert packet["post_format_tree"] == "e792454e43e8a694a9ed6442bbacb43920a0f346"
    assert packet["harness_commit"] == "9486b49e0e274baac20fb90b44706cc400ddc318"
    assert packet["run_id"] == "35435396339" and packet["run_attempt"] == "1"
    assert packet["harvest_passed"] is True
    outcome = packet["job_outcome"]
    assert outcome["passed"] and outcome["source_unchanged"] and outcome["error"] is None
    assert len(outcome["steps"]) == 7
    assert all(row["passed"] and row["returncode"] == 0 and not row["timed_out"] for row in outcome["steps"])
    assert set(packet["files"]) == set(config["partition_input_files"]) == set(config["format_paths"])
    bridges = {row["path"]: row for row in packet["bridges"]}
    assert len(packet["files"]) == len(bridges) == 23
    annotation = json.loads((here / "facade-annotation-inverse.json").read_bytes())
    assert annotation["source_path"] == config["facade_path"]
    assert annotation["actual_run"] == 35440128214 and annotation["actual_job"] == 105889382891
    assert annotation["changed_import_lines"] == len(annotation["edits"]) == 72
    assert annotation["actual_diagnostics"] == 79
    assert len({row["row"] for row in annotation["edits"]}) == 72
    assert sum(len(row["diagnostics"]) for row in annotation["edits"]) == 79
    inverse_rows = []
    for relative, prior in packet["files"].items():
        before = prior["content"].encode("utf-8")
        assert len(before) == prior["bytes"] and digest(before) == prior["sha256"]
        assert blob(before) == prior["git_blob"] and prior["mode"] == "100644"
        bridge = bridges[relative]
        assert bridge["before_sha256"] == prior["input_sha256"]
        assert bridge["after_sha256"] == prior["sha256"]
        assert all(bridge[key] is True for key in (
            "passed", "within_500_physical_lines", "canonical_tokens_equal",
            "comments_and_statement_token_anchors_equal",
            "full_ast_equal_including_type_comments_and_type_ignore_line_fields",
        ))
        current = (source / relative).read_bytes()
        expected = config["partition_input_files"][relative]
        assert len(current) == expected["bytes"] and digest(current) == expected["sha256"], relative
        assert blob(current) == expected["git_blob"] and expected["mode"] == "100644", relative
        inverse = current
        if relative == config["facade_path"]:
            lines = current.decode("utf-8").splitlines(keepends=True)
            prior_lines = before.decode("utf-8").splitlines(keepends=True)
            assert len(lines) == len(prior_lines) == annotation["physical_lines"] == 471
            for row in annotation["edits"]:
                assert row["after"] == row["before"] + "  # noqa: F401"
                assert all(item["code"] == "F401" and item["location"]["row"] == row["row"]
                           for item in row["diagnostics"])
                index = row["row"] - 1
                assert lines[index] == row["after"] + "\n"
                assert prior_lines[index] == row["before"] + "\n"
                lines[index] = row["before"] + "\n"
            inverse = "".join(lines).encode("utf-8")
        assert inverse == before, relative
        assert ast.dump(ast.parse(current, type_comments=True), include_attributes=False) == ast.dump(
            ast.parse(before, type_comments=True), include_attributes=False), relative
        assert len(current.splitlines()) <= 500, relative
        inverse_rows.append({
            "path": relative, "current_sha256": digest(current), "current_git_blob": blob(current),
            "prior_formatted_sha256": prior["sha256"], "exact_comment_inverse": True,
            "full_ast_including_type_comments_equal": True, "physical_lines": len(current.splitlines()),
        })
    corpus_raw = (here / "corpus-provenance.json").read_bytes()
    assert digest(corpus_raw) == config["corpus_provenance_sha256"]
    corpus = json.loads(corpus_raw)
    assert corpus["input_source"] == config["repaired_source_sha"]
    assert corpus["final_source"] == config["source_sha"] and corpus["final_tree"] == config["source_tree"]
    assert corpus["actual_run"] == {
        "id": 35441322798, "job_id": 105892486411, "attempt": 1, "event": "push",
        "head_sha": "e399247f4d2ce23918764c1d83004385db79754f",
        "head_branch": "codex/pr2974-package-eval-corpus-fixed-20260919",
        "workflow_name": "PR2974 package evaluator corpus harvest",
    }
    assert corpus["actual_first_run_conclusion"] == "failure" and corpus["actual_harvest_passed"] is False
    assert corpus["performance_contract_status"] == "failed"
    assert corpus["overall_qualification_complete"] is False and corpus["merge_ready"] is False
    assert corpus["final_combined_source_requires_fresh_report_and_original_metrics"] is True
    original_files = corpus["original_files"]
    for relative, record in original_files.items():
        raw = record["content"].encode("utf-8")
        assert record["encoding"] == "utf-8" and len(raw) == record["bytes"]
        assert digest(raw) == record["sha256"], relative

    def original(relative):
        return json.loads(original_files[relative]["content"])

    actual = original("job-outcome.json")
    assert actual["run_id"] == "35441322798" and actual["run_attempt"] == "1"
    assert actual["harness_sha"] == corpus["actual_run"]["head_sha"]
    assert actual["source_sha"] == config["repaired_source_sha"]
    assert actual["passed"] is False and actual["immutable_input_unchanged"] is True
    assert actual["all_original_owned_groups_retired"] is True
    assert actual["staged_tree"] == config["source_tree"]
    assert actual["staged_changed_paths"] == [config["report_path"]]
    assert len({row["name"] for row in actual["steps"]}) == len(actual["steps"])
    steps = {row["name"]: row for row in actual["steps"]}
    assert [row["name"] for row in actual["steps"] if not row["passed"]] == ["corpus-contracts"]
    for operation in ("write", "check"):
        step = steps["corpus-" + operation]
        result = original("corpus-" + operation + "-result.json")
        assert step["passed"] and step["returncode"] == 0 and not step["timed_out"]
        assert step["timeout_seconds"] == 75 and step["group_cleanup"]["passed"]
        assert result == corpus["generated_report"]
        assert corpus["corpus_" + operation]["command_passed"] is True
    lint = original("source-lint-result.json")
    assert lint["passed"] is True and lint["diagnostic_count"] == 0
    assert lint["source_before_after_equal"] and lint["ruff_binary_before_after_equal"]
    assert lint["paths"] == config["format_paths"] == corpus["source_lint"]["paths"]
    assert json.loads(original_files["ruff-check-json.log"]["content"]) == []
    assert len(lint["checks"]) == 4 and all(row["passed"] for row in lint["checks"])
    assert original_files["environment-before.json"]["content"] == original_files["environment-after.json"]["content"]
    snapshot = original("corpus-contract-snapshot.json")
    expected_nodes = ["tests/test_guard_command_decision_diff.py::" + name
                      for name in config["corpus_test_functions"]]
    failed_node = expected_nodes[-1]
    assert len(expected_nodes) == 6 and failed_node.endswith(
        "::test_fresh_process_report_is_environment_independent_and_bounded")
    assert snapshot["terminal"] and snapshot["exit_code"] == 1 and snapshot["passed"] is False
    assert snapshot["observed_source_files_unchanged"] and not snapshot["origin_errors"]
    assert [row["nodeid"] for row in snapshot["collection"]] == expected_nodes
    assert all(row["outcome"] == "passed" for row in snapshot["collect_reports"])
    grouped = {node: [] for node in expected_nodes}
    for row in snapshot["body_reports"]:
        assert row["nodeid"] in grouped and row["wasxfail"] is None
        grouped[row["nodeid"]].append(row)
    for node, rows in grouped.items():
        assert [row["phase"] for row in rows] == ["setup", "call", "teardown"]
        assert [row["outcome"] for row in rows] == (
            ["passed", "failed", "passed"] if node == failed_node else ["passed"] * 3)
    assert "62.57964566200002" in grouped[failed_node][1]["longrepr"]
    assert corpus["contracts"]["passed"] == 5 and corpus["contracts"]["failed"] == 1
    assert corpus["contracts"]["failed_nodeid"] == failed_node
    assert all(corpus["contracts"][key] == 0 for key in ("errors", "skipped", "xfail", "xpass"))
    junit = ET.fromstring(original_files["corpus-contract-junit.xml"]["content"])
    suites = [junit] if junit.tag == "testsuite" else list(junit.findall("testsuite"))
    assert suites and sum(int(row.attrib["tests"]) for row in suites) == 6
    assert sum(int(row.attrib["failures"]) for row in suites) == 1
    assert sum(int(row.attrib["errors"]) for row in suites) == 0
    assert sum(int(row.attrib["skipped"]) for row in suites) == 0
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [
        ("tests.test_guard_command_decision_diff", name) for name in config["corpus_test_functions"]]
    for index, case in enumerate(cases):
        assert len(case.findall("failure")) == (1 if index == 5 else 0)
        assert not case.findall("error") and not case.findall("skipped")
    raw_report = (source / config["report_path"]).read_bytes()
    generated = corpus["generated_report"]
    assert raw_report == original_files["generated-decision-diff-report.json"]["content"].encode("utf-8")
    assert len(raw_report) == generated["bytes"] == 56740
    assert digest(raw_report) == generated["sha256"] == config["final_report"]["sha256"]
    assert blob(raw_report) == generated["git_blob"] == config["final_report"]["git_blob"]
    report = json.loads(raw_report)
    expected_sources = {}
    for row in config["corpus_sources"]:
        assert row["binding_id"] == "source-" + digest(row["path"].encode())[:24]
        raw = (source / row["path"]).read_bytes()
        assert digest(raw) == row["sha256"] and blob(raw) == row["git_blob"]
        assert row["binding_id"] not in expected_sources
        expected_sources[row["binding_id"]] = row["sha256"]
    assert len(expected_sources) == len(config["corpus_sources"]) == 452
    assert report["bindings"]["sources_sha256"] == expected_sources
    assert report["corpus"] == config["expected_corpus"]
    assert report["oracle_reconciliation"]["known_gap_equality"] is True
    assert report["oracle_reconciliation"]["known_gaps"] == {}
    assert report["oracle_reconciliation"]["reconciled_count"] == 51000
    assert report["oracle_reconciliation"]["unreconciled_count"] == 0
    assert report["current_vs_proposed"]["lowered_count"] == 0
    assert report["current_vs_proposed"]["disposition_changed_count"] == 0
    assert report["legacy_to_current"]["lowered_count"] == 0
    assert corpus["only_source_delta_from_repaired_input"] == [config["report_path"]]
    return {
        "source_inverse_rows": inverse_rows, "corpus_provenance_sha256": digest(corpus_raw),
        "actual_scoped_lint_passed_on_identical_python_bytes": True,
        "actual_report_write_and_check_passed": True,
        "original_corpus_contracts": {"passed": 5, "failed": 1},
        "known_corpus_performance_contract": "failed", "overall_qualification_complete": False,
    }
