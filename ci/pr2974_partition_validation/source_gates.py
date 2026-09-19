"""Run the existing source gates and ordinary package checks on the immutable candidate."""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SOURCE, Run, baseline_witness, sha256, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from packages import run_packages


def run_source_gates(run: Run, env: dict[str, str], primary: Path, create_venv) -> None:
    prefix = [str(primary), "-I", "-B"]
    paths = CONFIG["format_paths"]
    assert len(paths) == 33 and len(CONFIG["production_paths"]) == 13
    lines = {path: len((SOURCE / path).read_bytes().splitlines()) for path in paths}
    write_json(REPORT / "physical-line-bounds.json", {
        "files": lines, "limit": 500, "passed": all(count <= 500 for count in lines.values()),
    })
    run.require(all(count <= 500 for count in lines.values()), "A partition exceeds 500 physical lines")
    run.command("scoped-ruff-check", [*prefix, "-m", "ruff", "check", *paths], env=env)
    run.command("scoped-ruff-format-check", [*prefix, "-m", "ruff", "format", "--check", *paths], env=env)
    run.command("scoped-error-level-types", [
        str(primary.parent / "basedpyright"), "--level", "error", "--outputjson", *CONFIG["production_paths"],
    ], timeout=300, env=env)
    type_log = REPORT / "scoped-error-level-types.log"
    try:
        diagnostics = json.loads(type_log.read_bytes())
        write_json(REPORT / "scoped-error-level-types.json", diagnostics)
        assert diagnostics["summary"]["errorCount"] == 0, "Scoped type errors"
    except Exception as error:
        write_json(REPORT / "scoped-types-observation-error.json", {"error": repr(error)})
        run.error = run.error or repr(error)
    run.command("existing-guard-dead-code-gate", [
        *prefix, "-m", "ruff", "check", "src/codex_plugin_scanner/guard/", "--select=F401,F811,F841",
    ], timeout=180, env=env)

    for lane in ("command", "surface"):
        original = "tests/test_guard_" + ("command_extensions" if lane == "command" else "surface_server") + ".py"
        args = [
            *prefix, str(HERE / "assert_partition_source.py"), "--lane", lane,
            "--baseline", str(BASELINE / original), "--candidate-root", str(SOURCE),
            "--output", str(REPORT / (lane + "-source-inverse.json")),
        ]
        if lane == "surface":
            args += ["--baseline-guide", str(BASELINE / "docs/guard/all-harness-hook-review.md")]
        run.command(lane + "-source-inverse", args, env=env)

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
    gate_env = dict(env, VALIDATION_SOURCE_ORIGINS_REPORT=str(REPORT / (name + "-loaded-source.json")))
    run.command(name, [
        *prefix, str(HERE / "source_entry.py"), str(SOURCE / "scripts/ci/rust_migration_tree_hygiene.py"),
        "--root", str(SOURCE), "--self-test",
    ], timeout=180, env=gate_env)
    write_json(REPORT / "corpus-binding-currentness.json", {
        "candidate": CONFIG["source_sha"], "candidate_tree": CONFIG["source_tree"],
        "baseline": CONFIG["baseline_sha"], "bound_source_files": 433,
        "closure_receipt_sha256": CONFIG["corpus_closure_receipt_sha256"],
        "actual_current_bytes_verified_by_full_source_witness": True,
        "bound_source_path_mode_blob_sha256_unchanged": True,
        "four_corpus_fixture_blobs_unchanged": True,
        "new_regeneration_or_51000_case_execution": False,
        "retained_prior_corpus_evidence_is_separate": True,
        "qualification_complete": False,
    })
    run_packages(run, env, primary, create_venv)
    write_json(REPORT / "source-gates-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "scoped_python_files": len(paths), "scoped_production_type_files": len(CONFIG["production_paths"]),
        "physical_line_bounds": lines,
        "historical_format_bridge_receipt_sha256": CONFIG["format_reconstruction_receipt_sha256"],
        "current_source_repair_contract_sha256": CONFIG["source_repair_contract_sha256"],
        "package_members_sha256": sha256((REPORT / "package-members.json").read_bytes()),
        "all_commands_passed": all(row["passed"] for row in run.steps),
        "qualification_complete": False,
    })


def main() -> int:
    run = Run("source-gates-and-packages")
    environment = None
    try:
        run.before = source_witness("before")
        run.baseline_before = baseline_witness("before")
        environment = prepare_environment(run)
        run_source_gates(run, *environment)
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
