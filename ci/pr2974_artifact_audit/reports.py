"""Verify the original reports without executing their recorded commands."""

from __future__ import annotations

import json

from common import CONFIG, REPORT, digest, frame, json_summary, write_json

EXPECTED_STEPS = {
    "gitleaks": ["isolate-range", "object-integrity", "gitleaks-version", "go-build-info",
                "gitleaks-default-full-range"],
    "finite": ["uv-version", "create-validation-environment", "frozen-project-install",
               "dependency-compatibility", "environment-before", "cli-collection", "cli-affected-tests",
               "runtime-collection", "runtime-affected-tests", "ruff-five-files", "ruff-format-five-files",
               "create-build-environment", "build-backend-install", "build-backend-compatibility",
               "build-backend-inventory", "build-wheel-and-sdist", "capability-artifact-gate-wheel",
               "capability-artifact-gate-sdist", "environment-after"],
}


def json_value(data: bytes):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, "Duplicate JSON key"
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=unique)


def parsed(payloads: dict[str, bytes], name: str):
    assert name in payloads, "Missing original report: " + name
    return json_value(payloads[name])


def audit_reports(label: str, payloads: dict[str, bytes], witness: dict[str, object]) -> dict[str, object]:
    assert all("/" not in name for name in payloads), "Unexpected original report directory"
    manifest = parsed(payloads, "artifact-manifest.json")
    assert set(payloads) == set(manifest) | {"artifact-manifest.json", "job-outcome.json"}
    for name, row in manifest.items():
        assert digest(payloads[name]) == row, "Original report manifest mismatch: " + name
    expected = dict(witness, harness_sha=CONFIG["original_harness_sha"])
    before = parsed(payloads, "source-before.json")
    after = parsed(payloads, "source-after.json")
    assert before == after == expected, "Original source witness does not match immutable Git bytes"
    assert payloads["source-before.json"] == payloads["source-after.json"]
    outcome = parsed(payloads, "job-outcome.json")
    assert outcome["job"] == ("gitleaks-full-range" if label == "gitleaks" else "finite-and-package")
    assert outcome["source_sha"] == CONFIG["source_sha"] and outcome["source_tree"] == CONFIG["source_tree"]
    assert outcome["harness_sha"] == CONFIG["original_harness_sha"]
    assert outcome["run_id"] == str(CONFIG["original_run_id"]) and outcome["run_attempt"] == "1"
    assert outcome["status"] == "finished" and outcome["passed"] is True and outcome["error"] is None
    assert outcome["source_unchanged"] is True and outcome["qualification_complete"] is False
    assert outcome["no_complete_descendant_cleanup_certificate"] is True
    assert outcome["workflow_gate_passed"] is True
    assert outcome["workflow_step_outcomes"] == dict.fromkeys(
        ["HARNESS_CHECKOUT", "SOURCE_CHECKOUT", "TOOL_SETUP", "TOOL_INSTALL", "DRIVER_OUTCOME"], "success")
    steps = parsed(payloads, "steps.json")
    assert outcome["steps"] == steps
    assert [step["name"] for step in steps] == EXPECTED_STEPS[label]
    commands = {}
    for step in steps:
        assert step["status"] == "finished" and step["returncode"] == 0
        assert step["timed_out"] is False and step["passed"] is True
        assert "launch_or_wait_error" not in step
        assert isinstance(step["command"], list) and all(isinstance(arg, str) for arg in step["command"])
        assert step["duration_seconds"] >= 0 and step["timeout_seconds"] > 0
        log = payloads[step["name"] + ".log"]
        assert digest(log) == {"sha256": step["log_sha256"], "bytes": step["log_bytes"]}
        commands[step["name"]] = step
    result = {"all_report_members_verified": True, "files": len(payloads),
              "source_files": len(witness["files"]), "original_command_count": len(steps),
              "original_failed_commands": 0, "original_timed_out_commands": 0,
              "source_before_after_and_current_git_equal": True,
              "original_outcome_sha256": digest(payloads["job-outcome.json"])["sha256"]}
    write_json(REPORT / (label + "-report-audit.json"), result)
    return {"summary": result, "commands": commands, "outcome": outcome}


def emit_original(label: str, payloads: dict[str, bytes]) -> None:
    catalog = {}
    for name, data in sorted(payloads.items()):
        row = digest(data)
        if name.endswith(".json"):
            value = json_value(data)
            if len(data) <= 65536:
                frame(label + "/" + name, data)
                row["complete_original_text_emitted"] = True
            else:
                row["complete_original_text_emitted"] = False
                row["json_kind"] = type(value).__name__
                row["top_level_count"] = len(value) if isinstance(value, (dict, list)) else None
                if isinstance(value, dict) and "files" in value:
                    row["source_files"] = len(value["files"])
                if isinstance(value, dict) and "nodeids" in value:
                    row["actual_collected_nodes"] = len(value["nodeids"])
                    row["actual_product_origins"] = len(value.get("product_module_origins", {}))
                json_summary(label + "/" + name, row)
        catalog[name] = row
    # The full original scanner output is redacted by its recorded command.
    # If unexpectedly enormous, fail explicitly and retain the ZIP; never call a truncation complete.
    if label == "gitleaks" and "gitleaks-default-full-range.log" in payloads:
        frame(label + "/gitleaks-default-full-range.log", payloads["gitleaks-default-full-range.log"],
              limit=8 * 1024 * 1024)
    write_json(REPORT / (label + "-original-report-catalog.json"), catalog)
    json_summary(label + "-original-report-catalog", catalog)
