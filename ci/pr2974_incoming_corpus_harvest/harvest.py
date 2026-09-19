"""Generate only the source-bound corpus report in a separate owned staging tree."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, REPORT_RELATIVE, SCRATCH, SEED, SOURCE, Run, seed_witness, sha256, staging_witness, write_json
from environment_setup import finish_environment, prepare_environment


def verify_report(raw: bytes, original: bytes, staged: dict) -> dict:
    assert len(raw) <= 1024 * 1024, "Generated report is oversized"
    value = json.loads(raw)
    assert raw == (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    expected_sources = {row["binding_id"]: row["sha256"] for row in CONFIG["corpus_sources"]}
    assert len(expected_sources) == len(CONFIG["corpus_sources"]) == CONFIG["source_manifest_count"] == 452
    assert value["bindings"]["sources_sha256"] == expected_sources
    expected = json.loads(original)
    assert len(expected["bindings"]["sources_sha256"]) == CONFIG["original_source_manifest_count"] == 452
    expected["bindings"]["sources_sha256"] = expected_sources
    assert value == expected, "Only the actual evaluator source bindings may change"
    assert sha256(raw) == CONFIG["derived_expected_report_sha256"]
    assert value["corpus"] == CONFIG["expected_corpus"]
    assert value["oracle_reconciliation"]["known_gap_equality"] is True
    assert value["oracle_reconciliation"]["known_gaps"] == {}
    assert value["oracle_reconciliation"]["reconciled_count"] == 51000
    assert value["oracle_reconciliation"]["unreconciled_count"] == 0
    assert value["current_vs_proposed"]["lowered_count"] == 0
    assert value["current_vs_proposed"]["disposition_changed_count"] == 0
    assert value["legacy_to_current"]["lowered_count"] == 0
    assert staged["changed_paths"] == [REPORT_RELATIVE]
    assert staged["files"][REPORT_RELATIVE]["sha256"] == sha256(raw)
    return {"report_path": REPORT_RELATIVE, "bytes": len(raw), "sha256": sha256(raw),
            "git_blob": staged["files"][REPORT_RELATIVE]["git_blob"],
            "source_binding_count": len(expected_sources), "corpus_cases": 51000,
            "actual_generated_report": True, "derived_oracle_was_only_compared": True,
            "changed_paths": staged["changed_paths"], "staged_tree": staged["staged_tree"],
            "no_source_seed_oracle_contract_or_budget_edits": True,
            "requires_new_immutable_source_commit": True}


def verify_contracts() -> dict:
    snapshot_path = REPORT / "corpus-contract-snapshot.json"
    value = json.loads(snapshot_path.read_bytes())
    expected = ["tests/test_guard_command_decision_diff.py::" + name
                for name in CONFIG["corpus_test_functions"]]
    assert len(expected) == 8
    assert CONFIG["corpus_test_functions"] == (CONFIG["original_corpus_test_functions"]
                                               + CONFIG["incoming_scheduler_test_functions"])
    assert len(CONFIG["original_corpus_test_functions"]) == 6
    assert len(CONFIG["incoming_scheduler_test_functions"]) == 2
    assert expected[5] == "tests/test_guard_command_decision_diff.py::test_fresh_process_report_is_environment_independent_and_bounded"
    assert value["terminal"] and value["exit_code"] == 0 and value["passed"]
    assert value["observed_source_files_unchanged"] is True and not value["origin_errors"]
    assert [row["nodeid"] for row in value["collection"]] == expected
    assert value["collect_reports"] and all(row["outcome"] == "passed" for row in value["collect_reports"])
    grouped = {node: [] for node in expected}
    for row in value["body_reports"]:
        assert row["nodeid"] in grouped and row["wasxfail"] is None
        grouped[row["nodeid"]].append(row)
    for rows in grouped.values():
        assert [row["phase"] for row in rows] == ["setup", "call", "teardown"]
        assert [row["outcome"] for row in rows] == ["passed", "passed", "passed"]
    raw = (REPORT / "corpus-contract-junit.xml").read_bytes()
    tree = ET.fromstring(raw)
    suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
    assert suites and sum(int(suite.attrib["tests"]) for suite in suites) == 8
    for field in ("failures", "errors", "skipped"):
        assert sum(int(suite.attrib[field]) for suite in suites) == 0
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [
        ("tests.test_guard_command_decision_diff", name) for name in CONFIG["corpus_test_functions"]]
    assert all(case.find("failure") is None and case.find("error") is None and case.find("skipped") is None
               for case in cases)
    children = value["metric_children"]
    assert len(children) == 2
    expected_environments = [("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8")]
    generated_raw = (SOURCE / REPORT_RELATIVE).read_bytes()
    framed_digest = sha256(len(generated_raw).to_bytes(8, "big") + generated_raw)
    for index, child in enumerate(children):
        assert child["returned"] and child["status"] == "returned" and child["returncode"] == 0
        assert child["timeout_seconds"] == 75 and child["stderr"]["bytes"] == 0
        assert tuple(child["selected_environment"][name] for name in ("PYTHONHASHSEED", "TZ", "LC_ALL")) == expected_environments[index]
        metrics = child["metrics"]
        assert metrics["report_framed_sha256"] == framed_digest
        assert float(metrics["elapsed_seconds"]) < 60 and float(metrics["rss_mib"]) < 512
    write_json(REPORT / "complete-original-metric-results.json", children)
    return {"passed": 8, "failed": 0, "errors": 0, "skipped": 0, "xfail": 0, "xpass": 0,
            "original_contracts_passed": 6, "incoming_scheduler_contracts_passed": 2,
            "actual_setup_call_teardown_records": 24,
            "metric_proxy_test_node": expected[5],
            "all_setup_call_teardown_records_verified": True,
            "snapshot_sha256": sha256(snapshot_path.read_bytes()),
            "junit_sha256": sha256(raw), "junit_bytes": len(raw),
            "existing_test_bodies_and_fixtures_used": True,
            "evaluation_budget_seconds": 60, "evaluation_rss_budget_mib": 512,
            "original_metric_child_timeout_seconds": 75,
            "no_budget_override_or_retry": True}


def main() -> int:
    run = Run("incoming-scheduler-corpus-harvest")
    environment = None
    original = None
    generated = None
    try:
        run.before = seed_witness("before")
        run.require(not SOURCE.exists() and not SOURCE.is_symlink(), "Refuse existing source staging")
        run.require(run.command("create-staging-checkout", [
            "git", "clone", "--no-hardlinks", "--no-checkout", str(SEED), str(SOURCE),
        ], cwd=SCRATCH, timeout=90), "Staging clone failed")
        run.require(run.command("checkout-exact-staging-source", [
            "git", "checkout", "--detach", CONFIG["source_sha"],
        ], cwd=SOURCE, timeout=90), "Staging checkout failed")
        staging_witness("before", run.before, allow_report_change=False)
        original = (SOURCE / REPORT_RELATIVE).read_bytes()
        assert sha256(original) == CONFIG["source_inputs"][REPORT_RELATIVE]
        (REPORT / "original-decision-diff-report.json").write_bytes(original)
        environment = prepare_environment(run)
        env, primary, _ = environment
        seed = json.loads((SOURCE / CONFIG["seed_path"]).read_bytes())
        assert seed["evaluation_budget_seconds"] == 60
        assert seed["evaluation_rss_budget_mib"] == 512
        assert CONFIG["write_check_timeout_seconds"] == 75
        generator = SOURCE / "tests/guard_command_decision_diff.py"
        for operation in ("write", "check"):
            name = "corpus-" + operation
            actual_env = dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / (name + "-source-origins.json")))
            command_passed = run.command(name, [
                str(primary), "-B", "-I", str(HERE / "source_entry.py"), str(generator), "--" + operation,
            ], cwd=SOURCE, timeout=CONFIG["write_check_timeout_seconds"], env=actual_env)
            raw = (SOURCE / REPORT_RELATIVE).read_bytes()
            (REPORT / ("post-" + operation + "-decision-diff-report.json")).write_bytes(raw)
            write_json(REPORT / (name + "-attempt.json"), {
                "command_passed": command_passed, "post_attempt_report_sha256": sha256(raw),
                "post_attempt_report_bytes": len(raw), "generated_report_verified": False,
                "qualification_complete": False})
            staged = staging_witness("after-" + operation, run.before, allow_report_change=True)
            run.require(command_passed, "Original corpus --" + operation + " failed; no retry")
            observed = verify_report(raw, original, staged)
            if generated is None:
                generated = observed
                (REPORT / "generated-decision-diff-report.json").write_bytes(raw)
            else:
                assert observed == generated, "Read-only --check changed the generated report"
            write_json(REPORT / (name + "-result.json"), observed)
        contracts_passed = run.command("corpus-contracts", [
            str(primary), "-B", "-I", str(HERE / "corpus_contract.py"),
        ], cwd=SOURCE, timeout=300, env=env)
        run.require(contracts_passed, "Six original and two incoming scheduler contracts failed; retain exact failures")
        contracts = verify_contracts()
        write_json(REPORT / "corpus-contracts-result.json", contracts)
        final_stage = staging_witness("after-contracts", run.before, allow_report_change=True)
        assert verify_report((SOURCE / REPORT_RELATIVE).read_bytes(), original, final_stage) == generated
        write_json(REPORT / "harvest-result.json", {
            "passed": True, "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
            "generated_report": generated, "contracts": contracts,
            "final_staged_tree": final_stage["staged_tree"],
            "actual_required_commands_executed": ["--write", "--check", "six-original-and-two-incoming-scheduler-contracts"],
            "all452_source_bindings_verified": True, "original_report_preserved": True,
            "immutable_final_source_validation": False,
            "requires_immutable_report_descendant_and_fresh_check_plus_eight_contracts": True,
            "qualification_complete": False})
    except BaseException as error:
        run.error = repr(error)
        write_json(REPORT / "harvest-error.json", {
            "error": run.error, "actual_generation_complete": generated is not None,
            "final_source_validation": False, "qualification_complete": False})
    finally:
        if environment is not None:
            try:
                finish_environment(run, environment[0], environment[1])
            except BaseException as error:
                run.error = run.error or repr(error)
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
