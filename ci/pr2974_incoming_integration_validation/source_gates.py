"""Retain current lint, formatting, type and ownership diagnostics without source edits."""

from __future__ import annotations

from pathlib import Path

from common import CONFIG, HERE, REPORT, SOURCE, Run, write_json
from preparation_contract import verify_preparation


def source_gates(run: Run, env: dict[str, str], primary: Path) -> None:
    write_json(REPORT / "prepared-source-proof.json", verify_preparation(CONFIG, HERE, SOURCE))
    paths = CONFIG["python_source_paths"]
    assert len(paths) == len(set(paths)) == CONFIG["python_source_file_count"]
    run.command("python-ruff-check", [
        str(primary), "-B", "-I", "-m", "ruff", "check", "--output-format", "json", *paths,
    ], timeout=120, env=env)
    run.command("python-ruff-format-check", [
        str(primary), "-B", "-I", "-m", "ruff", "format", "--check", "--diff", *paths,
    ], timeout=120, env=env)
    run.command("python-production-types", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary),
        "--level", "error", "--outputjson", *CONFIG["python_production_paths"],
    ], timeout=300, env=env)
    for stem, relative in CONFIG["ownership_gates"].items():
        current = dict(env)
        current["VALIDATION_SOURCE_ORIGINS_REPORT"] = str(REPORT / (stem + "-origins.json"))
        args = [
            str(primary), "-B", "-I", str(HERE / "source_entry.py"), str(SOURCE / relative),
            "--root", str(SOURCE), "--json", str(REPORT / (stem + ".json")),
        ]
        if stem == "rust-authority-ownership":
            args += ["--base-ref", CONFIG["original_source_sha"]]
        run.command(stem, args, timeout=180, env=current)
    write_json(REPORT / "source-gate-scope.json", {
        "source_sha": CONFIG["source_sha"], "python_source_paths": paths,
        "python_production_paths": CONFIG["python_production_paths"],
        "incoming_inventory_and_conftest_included": True,
        "source_mutating_formatter_or_lint_fix_executed": False,
        "formatter_proposals_are_separate_stdin_outputs": True,
        "qualification_complete": False,
    })
