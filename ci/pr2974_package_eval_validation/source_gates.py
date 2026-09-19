"""Check current package source and types while retaining the prior corpus metric failure."""
from __future__ import annotations

import json
from pathlib import Path

from common import CONFIG, HERE, REPORT, SOURCE, Run, write_json


def run_source_gates(run: Run, env: dict[str, str], primary: Path) -> None:
    prefix = [str(primary), "-I", "-B"]
    paths = CONFIG["format_paths"]
    assert len(paths) == 23 and len(CONFIG["production_paths"]) == 20
    assert len(CONFIG["type_paths"]) == 21
    lines = {path: len((SOURCE / path).read_bytes().splitlines()) for path in paths}
    write_json(REPORT / "physical-line-bounds.json", {
        "files": lines, "limit": 500, "passed": all(count <= 500 for count in lines.values()),
    })
    run.require(all(count <= 500 for count in lines.values()), "A package source exceeds 500 physical lines")
    write_json(REPORT / "prior-scoped-lint-currentness.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "actual_original_run": 35441322798, "actual_original_job": 105892486411,
        "corpus_provenance_sha256": CONFIG["corpus_provenance_sha256"],
        "exact_22_python_bytes_match_actual_zero_diagnostic_lint": True,
        "changed_witness_requires_fresh_lint": True,
        "verified_by_preparation_contract": True, "new_scoped_lint_execution": False,
        "qualification_complete": False,
    })
    run.require(run.command("changed-witness-ruff-check", [
        *prefix, "-m", "ruff", "check", "--output-format", "json", CONFIG["source_route_witness"],
    ], timeout=90, env=env), "Current lexical-scope-repaired source witness failed Ruff")
    current_lint = json.loads((REPORT / "changed-witness-ruff-check.log").read_bytes())
    write_json(REPORT / "changed-witness-ruff-check.json", current_lint)
    run.require(current_lint == [], "Current lexical-scope-repaired source witness has Ruff diagnostics")
    run.require(run.command("changed-witness-format-check", [
        *prefix, "-m", "ruff", "format", "--check", CONFIG["source_route_witness"],
    ], timeout=90, env=env), "Current lexical-scope-repaired source witness failed format check")
    run.require(run.command("type-interpreter-origin", [
        *prefix, str(HERE / "type_environment.py"), str(REPORT / "type-interpreter-origin.json"),
    ], timeout=60, env=env), "Owned type interpreter/dependency source binding failed")
    run.command("scoped-error-level-types", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary), "--level", "error", "--outputjson", *CONFIG["type_paths"],
    ], timeout=300, env=env)
    try:
        diagnostics = json.loads((REPORT / "scoped-error-level-types.log").read_bytes())
        write_json(REPORT / "scoped-error-level-types.json", diagnostics)
        assert diagnostics["summary"]["errorCount"] == 0, "Scoped package type errors"
    except Exception as error:
        write_json(REPORT / "scoped-types-observation-error.json", {"error": repr(error)})
        run.error = run.error or repr(error)
    run.command("existing-guard-dead-code-gate", [
        *prefix, "-m", "ruff", "check", "src/codex_plugin_scanner/guard/", "--select=F401,F811,F841",
    ], timeout=180, env=env)
    gates = [
        ("python-capability-cleanup", "scripts/ci/python_capability_cleanup_gate.py", []),
        ("python-hook-semantic-callgraph", "scripts/ci/python_hook_semantic_callgraph_gate.py", []),
        ("rust-io-ownership", "scripts/ci/rust_io_ownership_gate.py", []),
        ("rust-authority-ownership", "scripts/ci/rust_authority_ownership_gate.py",
         ["--base-ref", CONFIG["baseline_sha"]]),
        ("rust-pretool-no-python", "scripts/ci/rust_pretool_no_python_gate.py", []),
    ]
    for name, relative, extra in gates:
        gate_env = dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / (name + "-loaded-source.json")))
        run.command(name, [
            *prefix, str(HERE / "source_entry.py"), str(SOURCE / relative),
            "--root", str(SOURCE), "--json", str(REPORT / (name + ".json")), *extra,
        ], timeout=240, env=gate_env)
    name = "rust-migration-tree-hygiene"
    run.command(name, [
        *prefix, str(HERE / "source_entry.py"), str(SOURCE / "scripts/ci/rust_migration_tree_hygiene.py"),
        "--root", str(SOURCE), "--self-test",
    ], timeout=180, env=dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / (name + "-loaded-source.json"))))
    name = "package-unversioned-route"
    run.require(run.command(name, [
        *prefix, str(HERE / "source_entry.py"), str(SOURCE / CONFIG["source_route_witness"]),
        "--source-root", str(SOURCE), "--output", str(REPORT / (name + ".json")),
    ], timeout=180, env=dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / (name + "-loaded-source.json")))),
        "Current package source-route witness failed")
    route = json.loads((REPORT / (name + ".json")).read_bytes())
    assert route["assertions_passed"] is True
    assert route["source"] == route["final_source"]
    assert route["source"]["commit"] == CONFIG["source_sha"] and not route["source"]["source_status"]
    assert route["harness_sha256"] == CONFIG["partition_input_files"][CONFIG["source_route_witness"]]["sha256"]
    assert route["evaluator_sha256"] == CONFIG["partition_input_files"][CONFIG["facade_path"]]["sha256"]
    assert route["api_only_persistence_exercised"] is False
    assert [row["case"] for row in route["full_evaluator_cases"]] == [
        "bare_registry_direct", "lockfile_resolved_direct", "exact_transitive"]
    records = route["evaluator_bound_lookup_sources"]
    expected = {
        "_evaluate_with_bundle": "src/codex_plugin_scanner/guard/runtime/package_eval_bundle.py",
        "_transitive_lockfile_results": "src/codex_plugin_scanner/guard/runtime/package_eval_transitive.py",
    }
    assert [row["facade_binding"] for row in records] == list(expected)
    for row in records:
        path = expected[row["facade_binding"]]
        assert row["source_path"] == path
        assert row["source_sha256"] == CONFIG["partition_input_files"][path]["sha256"]
        assert row["lookup_calls"] and all(call["expression"] == "_eval.evaluate_cached_supply_chain_bundle"
                                         for call in row["lookup_calls"])
    write_json(REPORT / "corpus-binding-currentness.json", {
        "candidate": CONFIG["source_sha"], "candidate_tree": CONFIG["source_tree"],
        "baseline": CONFIG["baseline_sha"], "bound_source_files": 452,
        "corpus_provenance_sha256": CONFIG["corpus_provenance_sha256"],
        "actual_current_bytes_verified_by_full_source_witness": True,
        "final_report": CONFIG["final_report"], "new_regeneration_or_metric_execution": False,
        "prior_original_contracts": {"passed": 5, "failed": 1},
        "known_corpus_performance_contract": "failed", "qualification_complete": False,
        "final_combined_source_requires_fresh_report_and_original_metrics": True,
    })
    passed = not run.error and all(row["passed"] for row in run.steps)
    write_json(REPORT / "source-gates-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "scoped_python_files": 23, "scoped_production_type_files": 20, "scoped_source_witness_type_files": 1, "physical_line_bounds": lines,
        "all_commands_passed": passed, "qualification_complete": False,
    })
    run.require(passed, "Required source gates failed; retained exact source and original diagnostics")
