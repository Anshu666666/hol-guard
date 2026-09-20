"""Retain complete current or parent type output and its original return code."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    config = json.loads((HERE / "manifest.json").read_text())
    report = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    mode = sys.argv[1]
    assert mode in {"new_helpers", "current_existing", "parent_existing"}
    baseline = mode == "parent_existing"
    root = Path(os.environ["VALIDATION_BASELINE" if baseline else "VALIDATION_SOURCE"]).resolve(strict=True)
    paths = config["python_new_helper_paths" if mode == "new_helpers" else "python_existing_production_paths"]
    python = Path(os.environ["VALIDATION_PYTHON"]).resolve(strict=True)
    argv = [str(python.parent / "basedpyright"), "--pythonpath", str(python),
            "--project", str(root / "pyproject.toml"), "--outputjson", *paths]
    stdout, stderr = report / (mode + "-types.stdout.json"), report / (mode + "-types.stderr.txt")
    receipt = {"mode": mode, "argv": argv, "cwd": str(root), "paths": paths,
               "runtime_python": sys.version, "project_python_version": "3.10",
               "outer_owned_command_deadline_seconds": 300, "nested_timeout_not_added": True,
               "original_returncode": None, "baseline_diagnostics_only": baseline,
               "type_check_passed": False, "diagnostic_execution_complete": False,
               "warnings_filtered": False, "qualification_complete": False}
    receipt_path = report / (mode + "-types-command.json")
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    with stdout.open("xb") as out, stderr.open("xb") as err:
        completed = subprocess.run(argv, cwd=root, env=dict(os.environ), stdout=out, stderr=err, check=False)
    receipt["original_returncode"] = completed.returncode
    raw, error_raw = stdout.read_bytes(), stderr.read_bytes()
    assert len(raw) <= 32 * 1024 * 1024 and len(error_raw) <= 32 * 1024 * 1024
    receipt["stdout"] = {"file": stdout.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    receipt["stderr"] = {"file": stderr.name, "bytes": len(error_raw), "sha256": hashlib.sha256(error_raw).hexdigest()}
    value = json.loads(raw)
    diagnostics = value["generalDiagnostics"]
    summary = value["summary"]
    assert type(diagnostics) is list
    errors = [row for row in diagnostics if row["severity"] == "error"]
    warnings = [row for row in diagnostics if row["severity"] == "warning"]
    assert summary["errorCount"] == len(errors) and summary["warningCount"] == len(warnings)
    assert completed.returncode == (1 if errors else 0)
    receipt.update(diagnostic_execution_complete=True, type_check_passed=not errors,
                   error_count=len(errors), warning_count=len(warnings), summary=summary)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    # Parent errors remain original errors in the separate receipt. This command
    # certifies their complete capture, and supplies no exemption for current errors.
    return 0 if baseline else completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
