"""Check the actual committed combined report and six original bounded contracts."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import traceback
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, REPORT_RELATIVE, SCRATCH, SEED, SOURCE, Run, seed_witness, sha256, staging_witness, write_json
from environment_setup import finish_environment, prepare_environment


def verify_final_report(raw: bytes, staged: dict) -> dict:
    assert len(raw) <= 1024 * 1024, "Final committed report is oversized"
    assert sha256(raw) == CONFIG["expected_final_report_sha256"], "Final report byte identity"
    assert raw == (SOURCE / REPORT_RELATIVE).read_bytes(), "Retained report differs from source"
    value = json.loads(raw)
    assert raw == (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), "Report canonical encoding"
    expected = {row["binding_id"]: row["sha256"] for row in CONFIG["corpus_sources"]}
    assert len(expected) == len(CONFIG["corpus_sources"]) == CONFIG["source_manifest_count"] == 452
    assert value["bindings"]["sources_sha256"] == expected, "Final452 source bindings"
    assert value["corpus"] == CONFIG["expected_corpus"], "Original corpus identity"
    for name, digest in value["bindings"]["fixtures_sha256"].items():
        assert "/" not in name and "\\" not in name and name not in {".", ".."}
        assert sha256((SOURCE / "tests/fixtures/guard-command-corpus" / name).read_bytes()) == digest
    assert value["oracle_reconciliation"]["known_gap_equality"] is True
    assert value["oracle_reconciliation"]["known_gaps"] == {}
    assert value["oracle_reconciliation"]["reconciled_count"] == 51000
    assert value["oracle_reconciliation"]["unreconciled_count"] == 0
    assert value["current_vs_proposed"]["lowered_count"] == 0
    assert value["current_vs_proposed"]["disposition_changed_count"] == 0
    assert value["legacy_to_current"]["lowered_count"] == 0
    assert staged["changed_paths"] == [] and staged["staged_tree"] == CONFIG["source_tree"]
    assert staged["files"][REPORT_RELATIVE]["sha256"] == sha256(raw)
    assert staged["files"][REPORT_RELATIVE]["git_blob"] == CONFIG["expected_final_report_git_blob"]
    return {"report_path": REPORT_RELATIVE, "bytes": len(raw), "sha256": sha256(raw),
            "git_blob": CONFIG["expected_final_report_git_blob"], "source_binding_count": 452,
            "corpus_cases": 51000, "committed_report_read_only": True,
            "source_commit": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "changed_paths": [], "no_report_generation_or_replacement": True}


def verify_contracts() -> dict:
    snapshot_path = REPORT / "corpus-contract-snapshot.json"
    value = json.loads(snapshot_path.read_bytes())
    expected = ["tests/test_guard_command_decision_diff.py::" + name
                for name in CONFIG["corpus_test_functions"]]
    assert len(expected) == 6
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
    assert suites and sum(int(suite.attrib["tests"]) for suite in suites) == 6
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
    return {"passed": 6, "failed": 0, "errors": 0, "skipped": 0, "xfail": 0, "xpass": 0,
            "all_setup_call_teardown_records_verified": True,
            "snapshot_sha256": sha256(snapshot_path.read_bytes()),
            "junit_sha256": sha256(raw), "junit_bytes": len(raw),
            "existing_test_bodies_and_fixtures_used": True,
            "evaluation_budget_seconds": 60, "evaluation_rss_budget_mib": 512,
            "original_metric_child_timeout_seconds": 75,
            "no_budget_override_or_retry": True}



def main() -> int:
    run = Run("final-combined-corpus-validation")
    environment = None
    try:
        run.before = seed_witness("before")
        run.require(not SOURCE.exists() and not SOURCE.is_symlink(), "Refuse existing source staging")
        run.require(run.command("create-staging-checkout", [
            "git", "clone", "--no-hardlinks", "--no-checkout", str(SEED), str(SOURCE),
        ], cwd=SCRATCH, timeout=90), "Staging clone failed")
        run.require(run.command("checkout-exact-staging-source", [
            "git", "checkout", "--detach", CONFIG["source_sha"],
        ], cwd=SOURCE, timeout=90), "Staging checkout failed")
        before = staging_witness("before", run.before, allow_report_change=False)
        original = (SOURCE / REPORT_RELATIVE).read_bytes()
        (REPORT / "input-decision-diff-report.json").write_bytes(original)
        expected_report = verify_final_report(original, before)
        environment = prepare_environment(run)
        env, primary, _ = environment
        seed = json.loads((SOURCE / CONFIG["seed_path"]).read_bytes())
        assert seed["evaluation_budget_seconds"] == 60 and seed["evaluation_rss_budget_mib"] == 512
        assert CONFIG["write_check_timeout_seconds"] == 75
        generator = SOURCE / "tests/guard_command_decision_diff.py"
        actual_env = dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / "corpus-check-source-origins.json"))
        check_passed = run.command("corpus-check", [
            str(primary), "-B", "-I", str(HERE / "source_entry.py"), str(generator), "--check",
        ], cwd=SOURCE, timeout=75, env=actual_env)
        raw = (SOURCE / REPORT_RELATIVE).read_bytes()
        (REPORT / "post-check-decision-diff-report.json").write_bytes(raw)
        write_json(REPORT / "corpus-check-attempt.json", {
            "command_passed": check_passed, "report_sha256": sha256(raw),
            "report_bytes": len(raw), "qualification_complete": False})
        after_check = staging_witness("after-check", run.before, allow_report_change=False)
        run.require(check_passed, "Original corpus --check failed; no retry")
        assert raw == original and verify_final_report(raw, after_check) == expected_report
        write_json(REPORT / "corpus-check-result.json", expected_report)
        contracts_passed = run.command("corpus-contracts", [
            str(primary), "-B", "-I", str(HERE / "corpus_contract.py"),
        ], cwd=SOURCE, timeout=300, env=env)
        raw = (SOURCE / REPORT_RELATIVE).read_bytes()
        (REPORT / "post-contracts-decision-diff-report.json").write_bytes(raw)
        after_contracts = staging_witness("after-contracts", run.before, allow_report_change=False)
        run.require(contracts_passed, "Original six corpus contracts failed; retain exact failures")
        contracts = verify_contracts()
        write_json(REPORT / "corpus-contracts-result.json", contracts)
        assert raw == original and verify_final_report(raw, after_contracts) == expected_report
        write_json(REPORT / "final-validation-result.json", {
            "passed": True, "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
            "committed_report": expected_report, "contracts": contracts,
            "actual_required_commands_executed": ["--check", "six-original-contracts"],
            "all452_source_bindings_verified": True, "all_tracked_source_bytes_unchanged": True,
            "immutable_final_source_validation": True, "report_write_command_executed": False,
            "collector_preserved_byte_for_byte": True,
            "collector_mutable_report_staging_marker_is_original_owned_copy_metadata": True,
            "qualification_complete": False})
    except BaseException as error:
        run.error = repr(error)
        write_json(REPORT / "final-validation-error.json", {
            "error": run.error, "traceback": traceback.format_exc(),
            "immutable_final_source_validation": False, "qualification_complete": False})
    finally:
        if environment is not None:
            try:
                finish_environment(run, environment[0], environment[1])
            except BaseException as error:
                run.error = run.error or repr(error)
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
