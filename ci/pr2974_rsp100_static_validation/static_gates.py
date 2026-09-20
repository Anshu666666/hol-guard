"""Attempt every independent read-only prerequisite before admitting test bodies."""

from __future__ import annotations

import json
import os
from pathlib import Path

from common import CONFIG, HERE, REPORT, Run, write_json


def source_gates(run: Run, env: dict[str, str], primary: Path) -> bool:
    first = len(run.steps)
    run.command("python-parse", [str(primary), "-I", "-B", str(HERE / "parse_source.py")], timeout=120, env=env)
    run.command("python-ruff-check", [
        str(primary), "-I", "-B", "-m", "ruff", "check", "--no-cache", "--output-format", "json",
        *CONFIG["python_source_paths"],
    ], timeout=120, env=env)
    run.command("python-ruff-format-check", [
        str(primary), "-I", "-B", "-m", "ruff", "format", "--check", "--diff",
        *CONFIG["python_source_paths"],
    ], timeout=120, env=env)
    for mode in ("new_helpers", "current_existing", "parent_existing"):
        run.command(mode + "-types", [str(primary), "-I", "-B", str(HERE / "type_diagnostics.py"), mode],
                    timeout=300, env=env)
    comparison = {"current_source_sha": CONFIG["source_sha"], "parent_source_sha": CONFIG["baseline_sha"],
                  "matched_messages_are_not_an_exemption": True, "current_errors_remain_blocking": True,
                  "warnings_retained": True, "complete": False, "qualification_complete": False}
    try:
        rows = {}
        for mode in ("current_existing", "parent_existing"):
            value = json.loads((REPORT / (mode + "-types.stdout.json")).read_text())
            root = Path(os.environ["VALIDATION_BASELINE" if mode == "parent_existing" else "VALIDATION_SOURCE"])
            rows[mode] = [
                {**row, "relative_file": Path(row["file"]).relative_to(root).as_posix()}
                for row in value["generalDiagnostics"]
            ]
        def key(row):
            return (row["relative_file"], row["severity"], row["message"], row.get("rule"))
        remaining = list(rows["parent_existing"])
        matched, unmatched = [], []
        for current in rows["current_existing"]:
            index = next((i for i, parent in enumerate(remaining) if key(parent) == key(current)), None)
            if index is None:
                unmatched.append(current)
            else:
                matched.append({"current": current, "parent": remaining.pop(index)})
        comparison.update(complete=True, diagnostics=rows, matched_message_pairs=matched,
                          unmatched_current_diagnostics=unmatched, unmatched_parent_diagnostics=remaining,
                          comparison_key="relative file, severity, message, rule; both exact spans retained")
    except Exception as error:
        comparison["error"] = {"type": type(error).__name__, "message": str(error)}
    write_json(REPORT / "type-baseline-comparison.json", comparison)
    passed = comparison["complete"] and all(row["passed"] for row in run.steps[first:])
    write_json(REPORT / "static-prerequisites.json", {
        "source_sha": CONFIG["source_sha"], "paths": CONFIG["python_source_paths"],
        "all_commands_attempted_independently": True, "current_type_exemptions": [],
        "source_mutating_fixes_executed": False, "passed": passed,
        "tests_admitted": False, "finite_workloads_omitted": True, "qualification_complete": False,
    })
    return passed
