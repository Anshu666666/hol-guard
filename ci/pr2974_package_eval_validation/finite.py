"""Rebind the passing17-case evidence, then execute the12 affected package controls."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from witness_scope_contract import verify_existing_currentness


def read_snapshot(path: Path, *, execution: bool) -> dict:
    value = json.loads(path.read_bytes())
    assert value["terminal"] and value["exit_code"] == 0 and value["collection_complete"], path
    assert value["passed"] is True and value["observed_source_files_unchanged"] is True, path
    assert not value["errors"] and not value["refused_execution"], path
    assert all(row["outcome"] == "passed" for row in value["collect_reports"]), path
    nodes = [row["nodeid"] for row in value["raw_origins"]]
    assert len(nodes) == len(set(nodes)) == len(value["comparison"]) == value["actual_cases"], path
    assert value["test_execution_credit"] is execution, path
    if execution:
        assert value["execution_collection_matches_prior"] is True, path
    else:
        assert value["mode"] == "collection_only" and not value["body_reports"], path
    return value


def junit_key(nodeid: str) -> tuple[str, str]:
    plain, separator, parameter = nodeid.partition("[")
    parts = plain.split("::")
    assert parts[0].endswith(".py") and len(parts) >= 2, nodeid
    classname = ".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]])
    return classname, parts[-1] + (separator + parameter if separator else "")


def execution_result(snapshot: dict, junit: Path, expected: int, lane: str) -> dict:
    nodes = [row["nodeid"] for row in snapshot["raw_origins"]]
    by_node = {node: [] for node in nodes}
    for row in snapshot["body_reports"]:
        assert row["nodeid"] in by_node, row
        assert row["wasxfail"] is None, row
        by_node[row["nodeid"]].append(row)
    for node, rows in by_node.items():
        assert [row["phase"] for row in rows] == ["setup", "call", "teardown"], rows
        assert [row["outcome"] for row in rows] == ["passed"] * 3, rows
    raw = junit.read_bytes()
    tree = ET.fromstring(raw)
    suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
    assert suites and sum(int(row.attrib["tests"]) for row in suites) == expected
    assert sum(int(row.attrib["failures"]) for row in suites) == 0
    assert sum(int(row.attrib["errors"]) for row in suites) == 0
    assert sum(int(row.attrib["skipped"]) for row in suites) == 0
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [junit_key(node) for node in nodes]
    for node, case in zip(nodes, cases, strict=True):
        assert case.find("failure") is None and case.find("error") is None
        assert not case.findall("skipped"), node
    return {
        "selected_cases": expected, "passed_cases": expected, "skipped_cases": 0,
        "failed_cases": 0, "error_cases": 0, "xfail_cases": 0, "xpass_cases": 0,
        "declared_skips": [], "all_setup_call_teardown_reports_checked": True,
        "junit_path": junit.name, "junit_sha256": sha256(raw), "junit_bytes": len(raw),
        "ordered_case_ids": nodes,
    }


def retain_observed_sources(run: Run, side: str, root: Path, snapshot: dict) -> None:
    records = {}
    observed = list(snapshot.get("source_files", {}).values())
    for relative in ("tests/conftest.py", "tests/bundle_first_cloud.py", "tests/guard_test_invariants.py",
                     "pyproject.toml", "uv.lock"):
        path = root / relative
        raw = path.read_bytes()
        observed.append({"path": str(path), "sha256": sha256(raw), "bytes": len(raw)})
    for record in observed:
        path = Path(record["path"]).resolve(strict=True)
        raw = path.read_bytes()
        assert len(raw) == record["bytes"] and sha256(raw) == record["sha256"], path
        if path.is_relative_to(root):
            relative = path.relative_to(root).as_posix()
            original = (run.baseline_before if side == "baseline" else run.before)["files"][relative]
            assert original["sha256"] == record["sha256"], relative
            destination = Path(side) / relative
        else:
            destination = Path("external") / (record["sha256"] + path.suffix)
        target = REPORT / "observed-source-bytes" / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            assert target.read_bytes() == raw
        else:
            target.write_bytes(raw)
        records[str(path)] = {"retained_path": target.relative_to(REPORT).as_posix(),
                              "sha256": record["sha256"], "bytes": len(raw)}
    manifest = REPORT / ("observed-source-retention-" + side + ".json")
    previous = json.loads(manifest.read_bytes()) if manifest.is_file() else {}
    for path, record in records.items():
        assert path not in previous or previous[path] == record
        previous[path] = record
    write_json(manifest, previous)



def run_finite(run: Run, env: dict[str, str], primary: Path) -> None:
    snapshots = {}
    summaries = []

    def observe(side: str, group: str, *, execute: bool = False) -> tuple[Path, dict]:
        root = BASELINE if side == "baseline" else SOURCE
        name = side + "-" + group + ("-execution" if execute else "-collection")
        snapshot = REPORT / (name + ".json")
        junit = REPORT / (name + ".xml")
        prior = REPORT / ("candidate-" + group + "-collection.json")
        basetemp = Path(env["VALIDATION_TEST_TMP"]) / name
        assert env["VALIDATION_TEST_TMP"] == env["TMPDIR"]
        assert basetemp.resolve().is_relative_to(Path(env["TMPDIR"]).resolve(strict=True))
        args = [
            str(primary), "-I", "-B", str(HERE / "collect_package_contract.py"),
            "--root", str(root), "--manifest", str(HERE / "collection-manifest.json"),
            "--source-proof", str(REPORT / "package-eval-source-contract.json"),
            "--corpus-provenance", str(HERE / "corpus-provenance.json"),
            "--side", side, "--lane", "package_eval", "--cases", group,
            "--snapshot", str(snapshot), "--basetemp", str(basetemp),
        ]
        if execute:
            args += ["--run", "--junit", str(junit), "--prior-snapshot", str(prior)]
        passed = run.command(name, args, cwd=root, timeout=900 if execute else 480, env=env)
        if snapshot.is_file():
            retain_observed_sources(run, side, root, json.loads(snapshot.read_bytes()))
        run.require(passed, name + " failed; original output and terminal snapshot remain retained")
        value = read_snapshot(snapshot, execution=execute)
        if group == "candidate-only":
            assert value["actual_cases"] == CONFIG["expected_added_cases"] == 12
            assert value["actual_selector_counts"] == CONFIG["added_selector_counts"]
        else:
            assert len(value["actual_selector_counts"]) == CONFIG["expected_existing_function_selectors"] == 17
            assert value["actual_cases"] == 17
            assert value["actual_selector_counts"] == {selector: 1 for selector in CONFIG["existing_selectors"]}
        if execute:
            result = execution_result(value, junit, value["actual_cases"], "package_eval")
            result["snapshot_sha256"] = sha256(snapshot.read_bytes())
            result["group"] = group
            summaries.append(result)
        return snapshot, value

    baseline_path, baseline = observe("baseline", "existing")
    candidate_path, candidate = observe("candidate", "existing")
    equal = (baseline["comparison"] == candidate["comparison"]
             and baseline["actual_selector_counts"] == candidate["actual_selector_counts"]
             and baseline.get("repeated_root_import_evidence", {}) == candidate.get("repeated_root_import_evidence", {}))
    write_json(REPORT / "baseline-candidate-collection-comparison.json", {
        "baseline_commit": CONFIG["baseline_sha"], "candidate_commit": CONFIG["source_sha"],
        "candidate_tree": CONFIG["source_tree"], "function_selectors": CONFIG["existing_selectors"],
        "actual_existing_cases": baseline["actual_cases"],
        "actual_baseline_selector_counts": baseline["actual_selector_counts"],
        "actual_candidate_selector_counts": candidate["actual_selector_counts"],
        "baseline_snapshot_sha256": sha256(baseline_path.read_bytes()),
        "candidate_snapshot_sha256": sha256(candidate_path.read_bytes()),
        "ordered_nodes_parameters_marks_fixtures_autouse_globals_equal": equal,
        "test_path_normalization": None,
        "product_normalization": "160 exact original function exports through verified live facade/provider identities",
        "raw_origins_and_asts_retained": True, "qualification_complete": False,
    })
    run.require(equal, "Actual original/candidate collection contracts differ")
    currentness = verify_existing_currentness(CONFIG, HERE, run.before, candidate)
    write_json(REPORT / "previous-existing17-currentness.json", currentness)
    _, added = observe("candidate", "candidate-only")
    snapshots["existing"] = candidate["actual_cases"]
    snapshots["candidate-only"] = added["actual_cases"]
    observe("candidate", "candidate-only", execute=True)
    assert sum(snapshots.values()) == 29
    assert sum(row["selected_cases"] for row in summaries) == 12
    write_json(REPORT / "finite-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_function_selectors": 17, "actual_existing_cases": baseline["actual_cases"],
        "actual_candidate_collection_groups": snapshots, "new_boundary_cases": 7, "new_source_witness_cases": 5,
        "candidate_collected_cases": sum(snapshots.values()),
        "candidate_selected_cases": sum(row["selected_cases"] for row in summaries),
        "retained_existing17_currentness": currentness,
        "existing_body_execution_in_this_run": False,
        "candidate_passed_cases": sum(row["passed_cases"] for row in summaries),
        "candidate_skipped_cases": 0, "candidate_failed_cases": 0,
        "groups": summaries, "baseline_bodies_executed": False, "passed": True,
        "known_corpus_performance_contract": "failed",
        "corpus_provenance_sha256": CONFIG["corpus_provenance_sha256"],
        "overall_qualification_complete": False, "merge_ready": False,
        "final_combined_source_requires_fresh_report_and_original_metrics": True,
        "qualification_complete": False,
    })
