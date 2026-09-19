"""Validate the exact guarded join prototype without timing or selecting it."""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json, source_witness
from environment_setup import prepare_environment, finish_environment
from finite_contract import collected, execution


def observe(run, env, primary, name: str, root: Path, selectors: list[str], *, prior: Path | None = None):
    snapshot = REPORT / (name + ".json")
    junit = REPORT / (name + "-junit.xml")
    child_env = dict(env, LSC_TEST_ROOT=str(root), LSC_PRODUCT_ROOT=str(root / "src"),
                     LSC_TEST_REPORT=str(snapshot), LSC_COLLECTION_ONLY="0" if prior else "1")
    if prior is not None:
        child_env["LSC_PRIOR_COLLECTION"] = str(prior)
    args = [
        str(primary), "-I", "-B", str(HERE / "pytest_capture.py"),
        "--rootdir", str(root), "-c", str(root / "pyproject.toml"),
        "-q", "-m", "", "--tb=long", "-o", "cache_dir=" + str(SCRATCH / "pytest-cache" / name),
        "--basetemp", str(SCRATCH / "tmp" / name),
    ]
    args += ["--collect-only"] if prior is None else ["--junitxml", str(junit)]
    args += selectors
    passed = run.command(name, args, cwd=root, env=child_env, timeout=180 if prior else 120)
    if prior is None:
        run.require(passed, "Collection failed; original snapshot and log remain retained")
    return snapshot, junit


def source_bindings(run, path: Path, side: str) -> dict:
    data = json.loads(path.read_bytes())
    files = run.before["baseline_files" if side == "baseline" else "files"]
    environment = json.loads((REPORT / "environment-before.json").read_bytes())
    verified = []

    def definition(record: dict):
        if "builtin" in record:
            return
        location = record["path"]
        if location.startswith("@tests/"):
            relative = location.removeprefix("@tests/")
            assert record["whole_file_sha256"] == files[relative]["sha256"], relative
        elif location.startswith("@environment/"):
            relative = location.removeprefix("@environment/")
            assert record["whole_file_sha256"] == environment["dependency_files"][relative]["sha256"], relative
        else:
            raise AssertionError("Fixture/test callable outside immutable source or owned dependency closure: " + location)
        verified.append({"path": location, "whole_file_sha256": record["whole_file_sha256"]})

    for case in data["cases"]:
        definition(case["function"])
        for definitions in case["fixture_definitions"].values():
            for item in definitions:
                definition(item["function"])
    assert data["product_module_origins"], "No actual production origins"
    for name, origin in data["product_module_origins"].items():
        relative = "src/" + origin["path"]
        assert origin["sha256"] == files[relative]["sha256"], (name, relative)
    result = {
        "snapshot": path.name, "side": side, "source_sha": CONFIG[side]["sha"],
        "source_tree": CONFIG[side]["tree"], "snapshot_sha256": sha256(path.read_bytes()),
        "verified_definition_source_files": verified,
        "raw_product_module_origins": data["product_module_origins"],
        "all_definitions_and_product_origins_bound": True, "qualification_complete": False,
    }
    write_json(REPORT / (path.stem + "-source-binding.json"), result)
    return data


def exact_selector_counts(data: dict, declarations: list[dict]) -> list[dict]:
    nodes = [row["nodeid"] for row in data["cases"]]
    groups = []
    consumed = []
    for declaration in declarations:
        selector = declaration["selector"]
        matches = [node for node in nodes if node == selector or node.startswith(
            selector + ("::" if selector.endswith(".py") else "["))]
        assert len(matches) == declaration["expected_cases"], (selector, matches)
        consumed.extend(matches)
        groups.append({"selector": selector, "count": len(matches), "nodes": matches})
    assert consumed == nodes and len(set(consumed)) == len(consumed)
    return groups


def source_gates(run, env, primary) -> None:
    proof = json.loads((REPORT / "source-contract.json").read_bytes())
    assert proof["passed"] is True and len(proof["format_bridges"]) == 3
    for relative in CONFIG["candidate_files"]:
        path = REPORT / "source-payload/current" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((SOURCE / relative).read_bytes())
    paths = sorted(CONFIG["candidate_files"])
    run.require(run.command("ruff-format-check-three", [
        str(primary.parent / "ruff"), "format", "--check", "--", *paths,
    ], env=env, timeout=90), "Source formatting check failed")
    run.require(run.command("ruff-check-three", [
        str(primary.parent / "ruff"), "check", "--", *paths,
    ], env=env, timeout=90), "Scoped Ruff check failed")
    passed = run.command("types-two-production-files", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary), "--level", "error",
        "--outputjson", *CONFIG["production_paths"],
    ], env=env, timeout=180)
    raw = (REPORT / "types-two-production-files.log").read_bytes()
    summary = json.loads(raw)["summary"]
    write_json(REPORT / "types-summary.json", {"summary": summary, "raw_sha256": sha256(raw)})
    run.require(passed and summary["errorCount"] == 0, "Scoped production types failed")


def main() -> int:
    run = Run("rsp130-guarded-join-45-cases-six-operation-cells")
    errors, results = [], {}
    env, primary = None, None
    try:
        run.before = source_witness("before")
        # The source proof itself imports only stdlib and the neighboring harness.
        run.require(run.command("source-admission-before-environment", [
            sys.executable, "-I", "-B", str(HERE / "source_contract.py"), str(REPORT / "source-contract.json"),
        ], cwd=SCRATCH, env=None, timeout=60), "Source admission failed before project import")
        env, primary, _create_venv = prepare_environment(run)
        source_gates(run, env, primary)
        existing = CONFIG["finite"]["existing_selectors"]
        selectors = [row["selector"] for row in existing]
        baseline_path, _ = observe(run, env, primary, "baseline-existing-collection", BASELINE, selectors)
        candidate_path, _ = observe(run, env, primary, "candidate-existing-collection", SOURCE, selectors)
        new_path, _ = observe(run, env, primary, "candidate-new-collection", SOURCE, [CONFIG["new_test_path"]])
        baseline, candidate, new = collected(baseline_path), collected(candidate_path), collected(new_path)
        assert len(baseline["cases"]) == len(candidate["cases"]) == 23 and len(new["cases"]) == 22
        source_bindings(run, baseline_path, "baseline")
        source_bindings(run, candidate_path, "candidate")
        source_bindings(run, new_path, "candidate")
        baseline_groups = exact_selector_counts(baseline, existing)
        candidate_groups = exact_selector_counts(candidate, existing)
        assert baseline["cases"] == candidate["cases"], "Existing ordered case/parameter/fixture contract differs"
        assert baseline_groups == candidate_groups
        write_json(REPORT / "collection-comparison.json", {
            "existing_cases": 23, "new_cases": 22, "total_cases": 45,
            "baseline_snapshot_sha256": sha256(baseline_path.read_bytes()),
            "candidate_snapshot_sha256": sha256(candidate_path.read_bytes()),
            "new_snapshot_sha256": sha256(new_path.read_bytes()),
            "existing_ordered_rows_equal": True, "selector_groups": baseline_groups,
            "all_collection_admitted_before_any_body": True, "qualification_complete": False,
        })
        for name, prior, selected in (
            ("existing-execution", candidate_path, selectors),
            ("new-execution", new_path, [CONFIG["new_test_path"]]),
        ):
            try:
                snapshot, junit = observe(run, env, primary, name, SOURCE, selected, prior=prior)
                source_bindings(run, snapshot, "candidate")
                results[name] = execution(snapshot, prior, junit, no_skips=True)
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        if not errors:
            probe = REPORT / "operation-counts.json"
            run.require(run.command("six-separate-operation-cells", [
                str(primary), "-I", "-B", str(HERE / "operation_probe.py"),
                "--baseline-file", str(BASELINE / "src/codex_plugin_scanner/guard/aibom_cli.py"),
                "--candidate-root", str(SOURCE), "--output", str(probe),
                "--manifest", str(HERE / "probe-manifest.json"),
            ], env=env, timeout=120), "Actual operation-count cells failed")
            result = json.loads(probe.read_bytes())
            assert result["passed"] is True and result["sources_unchanged"] is True and len(result["cells"]) == 6
            results["operation_cells"] = result
    except BaseException as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append("Environment finalizer: " + repr(error))
        write_json(REPORT / "finite-results.json", {
            "results": results, "errors": errors, "expected_existing": 23, "expected_new": 22,
            "expected_total": 45, "expected_operation_cells": 6,
            "baseline_bodies_executed": False, "timing_measurement": False,
            "operation_counts_are_not_latency_or_process_tree_measurements": True,
            "optimization_selected": False, "qualification_complete": False,
        })
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
