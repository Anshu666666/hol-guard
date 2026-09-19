"""Check the exact87 changed Python and60 production files before corpus mutation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from common import CONFIG, REPORT, SOURCE, Run, sha256, staging_witness, write_json


def run_source_lint(run: Run, env: dict[str, str], primary: Path) -> None:
    paths = CONFIG["lint_paths"]
    assert len(paths) == CONFIG["lint_file_count"] == 87
    assert paths == sorted(CONFIG["partition_files"])
    assert all(path.endswith(".py") for path in paths)
    before = staging_witness("before-lint", run.before, allow_report_change=False)
    binary = primary.parent / "ruff"
    info = binary.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not binary.is_symlink()
    assert CONFIG["installed_versions"]["ruff"] == CONFIG["ruff_version"] == "0.15.17"
    binary_before = binary.read_bytes()
    write_json(REPORT / "ruff-binary.json", {
        "path": str(binary), "sha256": sha256(binary_before), "uid": info.st_uid,
        "mode": oct(stat.S_IMODE(info.st_mode)), "locked_version": CONFIG["ruff_version"],
    })
    run.require(run.command("ruff-version", [str(binary), "--version"], cwd=SOURCE, env=env, timeout=30),
                "The owned Ruff version command failed")
    assert (REPORT / "ruff-version.log").read_text().split() == ["ruff", CONFIG["ruff_version"]]
    commands = [
        ("ruff-check-json", [str(binary), "check", "--no-cache", "--no-fix",
                             "--output-format", "json", "--", *paths]),
        ("ruff-check-text", [str(binary), "check", "--no-cache", "--no-fix",
                             "--output-format", "full", "--", *paths]),
        ("ruff-format-check", [str(binary), "format", "--no-cache", "--check", "--", *paths]),
        ("ruff-format-diff", [str(binary), "format", "--no-cache", "--diff", "--", *paths]),
    ]
    observations = []
    for name, args in commands:
        passed = run.command(name, args, cwd=SOURCE, env=env, timeout=180)
        row = run.steps[-1]
        observations.append({
            "name": name, "passed": passed, "returncode": row.get("returncode"),
            "timed_out": row.get("timed_out"), "command": args,
            "group_cleanup": row.get("group_cleanup"), "log_sha256": row.get("log_sha256"),
            "log_bytes": row.get("log_bytes"),
        })
    after = staging_witness("after-lint", run.before, allow_report_change=False)
    assert before == after, "Read-only Ruff checks changed the complete source"
    assert binary.read_bytes() == binary_before, "The owned Ruff executable changed"
    raw = (REPORT / "ruff-check-json.log").read_bytes()
    values = json.loads(raw)
    assert isinstance(values, list) and all(isinstance(row, dict) for row in values)
    codes = {}
    for row in values:
        code = str(row.get("code"))
        codes[code] = codes.get(code, 0) + 1
    passed = len(observations) == 4 and all(row["passed"] for row in observations) and not values
    write_json(REPORT / "source-lint-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "paths": paths, "checks": observations, "diagnostic_count": len(values), "codes": codes,
        "complete_diagnostic_json_sha256": sha256(raw), "source_before_after_equal": True,
        "ruff_binary_before_after_equal": True, "no_autofix_or_rule_changes": True,
        "original_configuration_sha256": CONFIG["source_inputs"]["pyproject.toml"],
        "original_lock_sha256": CONFIG["source_inputs"]["uv.lock"],
        "passed": passed, "qualification_complete": False,
    })
    run.require(passed, "Read-only source lint or formatting failed; no corpus write is permitted")


def run_source_types(run: Run, env: dict[str, str], primary: Path) -> None:
    paths = CONFIG["type_paths"]
    assert len(paths) == CONFIG["type_file_count"] == 60
    assert paths == sorted(path for path in CONFIG["partition_files"]
                           if path.startswith("src/") and path.endswith(".py"))
    before = staging_witness("before-types", run.before, allow_report_change=False)
    binary = primary.parent / "basedpyright"
    info = binary.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not binary.is_symlink()
    assert CONFIG["installed_versions"]["basedpyright"] == CONFIG["basedpyright_version"] == "1.39.8"
    binary_before = binary.read_bytes()
    write_json(REPORT / "basedpyright-binary.json", {
        "path": str(binary), "sha256": sha256(binary_before), "uid": info.st_uid,
        "mode": oct(stat.S_IMODE(info.st_mode)), "locked_version": CONFIG["basedpyright_version"],
        "explicit_pythonpath": str(primary),
    })
    args = [str(binary), "--pythonpath", str(primary), "--level", "error", "--outputjson", *paths]
    passed = run.command("source-types", args, cwd=SOURCE, env=env, timeout=240)
    row = run.steps[-1]
    after = staging_witness("after-types", run.before, allow_report_change=False)
    assert before == after, "Read-only type analysis changed the complete source"
    assert binary.read_bytes() == binary_before, "The owned type-check executable changed"
    raw = (REPORT / "source-types.log").read_bytes()
    value = json.loads(raw)
    assert isinstance(value, dict) and isinstance(value.get("generalDiagnostics"), list)
    summary = value["summary"]
    no_errors = summary["errorCount"] == 0 and not any(
        item.get("severity") == "error" for item in value["generalDiagnostics"])
    write_json(REPORT / "source-types-result.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "paths": paths, "command": args, "passed": passed and no_errors,
        "summary": summary, "diagnostics_sha256": sha256(raw),
        "returncode": row.get("returncode"), "timed_out": row.get("timed_out"),
        "group_cleanup": row.get("group_cleanup"), "source_before_after_equal": True,
        "binary_before_after_equal": True, "explicit_owned_interpreter": str(primary),
        "qualification_complete": False,
    })
    run.require(passed and no_errors, "Scoped source types failed; no corpus write is permitted")
