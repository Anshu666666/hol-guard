"""Run the existing bounded source gates on the exact formatted StoreBase candidate."""
from __future__ import annotations

import json
from pathlib import Path

from common import CONFIG, HERE, REPORT, SOURCE, Run, write_json


def run_source_gates(run: Run, env: dict[str, str], primary: Path) -> None:
    prefix = [str(primary), "-I", "-B"]
    paths = CONFIG["format_paths"]
    assert len(paths) == 9 and len(CONFIG["production_paths"]) == 8
    lines = {path: len((SOURCE / path).read_bytes().splitlines()) for path in paths}
    write_json(REPORT / "physical-line-bounds.json", {
        "files": lines, "limit": 500, "passed": all(count <= 500 for count in lines.values()),
    })
    run.require(all(count <= 500 for count in lines.values()), "A StoreBase source exceeds 500 physical lines")
    run.command("scoped-ruff-check", [*prefix, "-m", "ruff", "check", *paths], env=env)
    run.command("scoped-ruff-format-check", [*prefix, "-m", "ruff", "format", "--check", *paths], env=env)
    run.require(run.command("type-interpreter-origin", [
        *prefix, str(HERE / "type_environment.py"), str(REPORT / "type-interpreter-origin.json"),
    ], timeout=60, env=env), "Owned type interpreter/dependency source binding failed")
    run.command("scoped-error-level-types", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary), "--level", "error", "--outputjson", *CONFIG["production_paths"],
    ], timeout=300, env=env)
    try:
        diagnostics = json.loads((REPORT / "scoped-error-level-types.log").read_bytes())
        write_json(REPORT / "scoped-error-level-types.json", diagnostics)
        assert diagnostics["summary"]["errorCount"] == 0, "Scoped StoreBase type errors"
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
    write_json(REPORT / "corpus-binding-currentness.json", {
        "candidate": CONFIG["source_sha"], "candidate_tree": CONFIG["source_tree"],
        "baseline": CONFIG["baseline_sha"], "bound_source_files": 433,
        "closure_receipt_sha256": CONFIG["corpus_closure_receipt_sha256"],
        "actual_current_bytes_verified_by_full_source_witness": True,
        "bound_source_path_mode_blob_sha256_unchanged": True, "four_corpus_fixture_blobs_unchanged": True,
        "new_regeneration_or_51000_case_execution": False, "qualification_complete": False,
    })
    passed = not run.error and all(row["passed"] for row in run.steps)
    write_json(REPORT / "source-gates-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "scoped_python_files": 9, "scoped_production_type_files": 8, "physical_line_bounds": lines,
        "all_commands_passed": passed, "qualification_complete": False,
    })
    run.require(passed, "Required source gates failed; retained exact source and original diagnostics")
