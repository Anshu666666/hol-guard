"""Compare real collection contracts and execute only the fixed finite candidate recipe."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, baseline_witness, sha256, source_witness, write_json
from environment_setup import finish_environment, owned_test_temp_identity, prepare_environment


def read_snapshot(path: Path, expected: int, *, execution: bool, product: bool) -> dict:
    value = json.loads(path.read_bytes())
    assert value["terminal"] and value["exit_code"] == 0 and value["collection_complete"], path
    assert value["actual_cases"] == expected and len(value["comparison"]) == expected, path
    assert not value["errors"] and not value["refused_execution"], path
    assert all(row["outcome"] == "passed" for row in value["collect_reports"]), path
    nodes = [row["nodeid"] for row in value["raw_origins"]]
    assert len(nodes) == expected and len(set(nodes)) == expected, path
    assert value["observed_source_files_unchanged"] is True, path
    if product:
        assert value["passed"] is True, path
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
    allowed = CONFIG["surface_expected_skip_node"] if lane == "surface" else None
    skips = []
    for node, rows in by_node.items():
        phases = [row["phase"] for row in rows]
        outcomes = [row["outcome"] for row in rows]
        if node == allowed:
            assert phases == ["setup", "teardown"] and outcomes == ["skipped", "passed"], rows
            assert CONFIG["surface_expected_skip_reason"] in rows[0]["longrepr"], rows
            skips.append(node)
        else:
            assert phases == ["setup", "call", "teardown"] and outcomes == ["passed"] * 3, rows
    assert skips == ([allowed] if allowed else []), skips
    raw = junit.read_bytes()
    tree = ET.fromstring(raw)
    suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
    assert suites and sum(int(row.attrib["tests"]) for row in suites) == expected
    assert sum(int(row.attrib["failures"]) for row in suites) == 0
    assert sum(int(row.attrib["errors"]) for row in suites) == 0
    assert sum(int(row.attrib["skipped"]) for row in suites) == len(skips)
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [junit_key(node) for node in nodes]
    for node, case in zip(nodes, cases, strict=True):
        assert case.find("failure") is None and case.find("error") is None
        skipped = case.findall("skipped")
        if node == allowed:
            assert len(skipped) == 1
            assert skipped[0].attrib["message"] == CONFIG["surface_expected_skip_reason"]
        else:
            assert not skipped, node
    return {
        "selected_cases": expected, "passed_cases": expected - len(skips), "skipped_cases": len(skips),
        "failed_cases": 0, "error_cases": 0, "xfail_cases": 0, "xpass_cases": 0,
        "declared_skips": skips, "all_setup_call_teardown_reports_checked": True,
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


def run_lane(run: Run, lane: str, env: dict[str, str], primary: Path) -> None:
    product = lane in {"protect", "codex"}
    existing = CONFIG["expected_existing_cases"][lane]
    summaries = []
    collections = {}
    test_root = Path(env["TMPDIR"])
    owned_test_temp_identity(test_root)

    def observe(side: str, group: str, expected: int, *, execute: bool = False) -> tuple[Path, dict]:
        root = BASELINE if side == "baseline" else SOURCE
        name = side + "-" + group + ("-execution" if execute else "-collection")
        snapshot = REPORT / (name + ".json")
        junit = REPORT / (name + ".xml")
        prior = REPORT / ("candidate-" + group + "-collection.json")
        if product:
            args = [
                str(primary), "-I", "-B", str(HERE / "collect_product_contract.py"),
                "--root", str(root), "--manifest", str(HERE / "product-collection-manifest.json"),
                "--reconstruction-receipt", str(HERE / "format-reconstruction-receipt.json"),
                "--repaired-candidate-root", str(SOURCE),
                "--side", side, "--lane", lane, "--cases", group,
                "--snapshot", str(snapshot), "--basetemp", str(test_root / name),
            ]
            if execute:
                args += ["--run", "--junit", str(junit), "--prior-snapshot", str(prior)]
        else:
            original = "tests/test_guard_" + ("command_extensions" if lane == "command" else "surface_server") + ".py"
            paths = [original] if side == "baseline" else CONFIG[lane + "_paths"]
            args = [
                str(primary), "-I", "-B", str(HERE / "collect_contract.py"),
                "--root", str(root), "--baseline-source", str(BASELINE / original),
                "--original-module", original[:-3].replace("/", "."), "--snapshot", str(snapshot),
                "--expected", str(expected), "--basetemp", str(test_root / name),
            ]
            if execute:
                args += ["--run", "--junit", str(junit), "--prior-collection", str(prior)]
            args += paths
        passed = run.command(name, args, cwd=root, timeout=900 if execute else 480, env=env)
        if snapshot.is_file():
            retain_observed_sources(run, side, root, json.loads(snapshot.read_bytes()))
        run.require(passed, name + " did not pass; original log and terminal snapshot are retained")
        value = read_snapshot(snapshot, expected, execution=execute, product=product)
        if execute:
            result = execution_result(value, junit, expected, lane)
            result["snapshot_sha256"] = sha256(snapshot.read_bytes())
            summaries.append(result)
        return snapshot, value

    baseline_path, baseline = observe("baseline", "existing", existing)
    candidate_path, candidate = observe("candidate", "existing", existing)
    equal = baseline["comparison"] == candidate["comparison"]
    comparison = {
        "baseline_commit": CONFIG["baseline_sha"], "candidate_commit": CONFIG["source_sha"],
        "candidate_tree": CONFIG["source_tree"], "lane": lane, "expected_existing_cases": existing,
        "baseline_snapshot_sha256": sha256(baseline_path.read_bytes()),
        "candidate_snapshot_sha256": sha256(candidate_path.read_bytes()),
        "ordered_nodes_parameters_marks_fixtures_globals_equal": equal,
        "normalization": ("exact verified definition relocation map; eight source/value-bound fixture sites for Surface"
                          if not product else "explicit verified facade aliases and one verified Codex source-file identity"),
        "actual_raw_origins_retained_separately": True, "qualification_complete": False,
    }
    write_json(REPORT / "baseline-candidate-collection-comparison.json", comparison)
    run.require(equal, "Actual baseline and candidate collection contracts differ")
    collections["existing"] = existing
    observe("candidate", "existing", existing, execute=True)
    if lane == "protect":
        observe("candidate", "candidate-only", 10)
        collections["candidate-only"] = 10
        observe("candidate", "candidate-only", 10, execute=True)

    seams = []
    if lane == "codex":
        for case in CONFIG["codex_seam_cases"]:
            output = REPORT / ("codex-seam-" + case + ".json")
            passed = run.command("codex-seam-" + case, [
                str(primary), "-I", "-B", str(HERE / "codex_partition_seams.py"),
                "--root", str(SOURCE), "--scratch", str(test_root / ("seam-" + case)),
                "--snapshot", str(output), "--case", case,
            ], timeout=120, env=env)
            run.require(passed, "Separate Codex seam control failed: " + case)
            value = json.loads(output.read_bytes())
            run.require(value["passed"] is True, "Codex seam terminal evidence did not pass")
            seams.append({"case": case, "snapshot_sha256": sha256(output.read_bytes())})
    total = sum(row["selected_cases"] for row in summaries)
    assert total == CONFIG["expected_project_cases"][lane]
    write_json(REPORT / "finite-result.json", {
        "lane": lane, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "baseline_existing_cases": existing, "candidate_collection_groups": collections,
        "candidate_selected_cases": total, "candidate_passed_cases": sum(row["passed_cases"] for row in summaries),
        "candidate_skipped_cases": sum(row["skipped_cases"] for row in summaries),
        "groups": summaries, "separate_harness_controls": seams,
        "separate_harness_control_count": len(seams), "passed": True, "qualification_complete": False,
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", choices=("protect", "codex", "command", "surface"), required=True)
    args = parser.parse_args()
    run = Run("finite-" + args.lane)
    environment = None
    try:
        run.before = source_witness("before")
        run.baseline_before = baseline_witness("before")
        environment = prepare_environment(run)
        env, primary, _ = environment
        run_lane(run, args.lane, env, primary)
    except BaseException as error:
        run.error = repr(error)
    finally:
        if environment is not None:
            try:
                finish_environment(run, environment[0], environment[1])
            except BaseException as error:
                run.error = run.error or repr(error)
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
