"""Recheck retained original45 data against the same immutable source; execute no tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from common import CONFIG, HERE, REPORT, sha256, write_json
from finite_contract import collected, execution


def read_pinned(name: str, key: str) -> dict:
    path = HERE / name
    raw = path.read_bytes()
    pin = CONFIG[key]
    assert len(raw) == pin["bytes"] and sha256(raw) == pin["sha256"], name
    return json.loads(raw)


def admit_previous(run) -> dict:
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    first = read_pinned("original-terminal.json", "original_terminal")
    packet = read_pinned("original-functional.json", "original_functional")
    assert packet["source_sha"] == first["source_sha"] == CONFIG["source_sha"]
    assert first["source_tree"] == CONFIG["source_tree"]
    assert packet["original_harness"] == first["harness_sha"] == CONFIG["original_harness"]
    assert packet["original_run"] == CONFIG["original_run"] and packet["original_job"] == CONFIG["original_job"]
    assert first["complete_original_frame_and_case_audit"] is True
    old = first["original_outcome"]
    assert old["passed"] is False and old["source_unchanged"] is True
    assert old["all_original_owned_groups_retired"] is True
    failed = [row for row in old["steps"] if not row["passed"]]
    assert len(old["steps"]) == 16 and len(failed) == 1
    assert failed[0]["name"] == "six-separate-operation-cells" and failed[0]["returncode"] == 1
    assert not any(row["timed_out"] for row in old["steps"])
    audit = first["independent_data_audit"]
    assert audit["actual_candidate_body_passes"] == 45 and audit["actual_ordered_passing_phases"] == 135
    assert audit["full_baseline_candidate_existing_rows_equal"] and audit["source_and_environment_unchanged"]
    assert audit["source_contract"]["passed"] and audit["types"]["summary"]["errorCount"] == 0
    original_cell = audit["operation_result"]
    assert original_cell["passed"] is False and original_cell["sources_unchanged"] is True
    assert len(original_cell["cells"]) == 1
    assert original_cell["cells"][0]["original"]["snapshot_id_load_attr"] == 0
    assert original_cell["cells"][0]["expected_original_key_loads"] == 1
    destination = REPORT / "original-functional"
    assert not destination.exists()
    destination.mkdir(mode=0o700)
    expected_names = {
        "baseline-existing-collection.json", "candidate-existing-collection.json",
        "candidate-new-collection.json", "existing-execution.json", "new-execution.json",
        "existing-execution-junit.xml", "new-execution-junit.xml",
    }
    assert set(packet["files"]) == expected_names
    for name, row in packet["files"].items():
        raw = row["text"].encode("utf-8")
        assert len(raw) == row["bytes"] and sha256(raw) == row["sha256"]
        pin = first["original_member_manifest"][name]
        assert row["bytes"] == pin["bytes"] and row["sha256"] == pin["sha256"]
        (destination / name).write_bytes(raw)
    baseline = collected(destination / "baseline-existing-collection.json")
    current = collected(destination / "candidate-existing-collection.json")
    new = collected(destination / "candidate-new-collection.json")
    assert len(baseline["cases"]) == len(current["cases"]) == 23 and len(new["cases"]) == 22
    assert baseline["cases"] == current["cases"]
    results = {}
    for group, prior, count in (
        ("existing-execution", "candidate-existing-collection.json", 23),
        ("new-execution", "candidate-new-collection.json", 22),
    ):
        result = execution(destination / (group + ".json"), destination / prior,
                           destination / (group + "-junit.xml"), no_skips=True)
        assert result == first["finite_results"]["results"][group]
        assert result["tests"] == result["passed"] == count
        results[group] = result
    for path, pin in CONFIG["candidate_files"].items():
        assert run.before["files"][path] == pin
    result = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_run": CONFIG["original_run"], "original_harness": CONFIG["original_harness"],
        "original_overall_status": "failure", "original_failure_preserved": True,
        "original_functional_results": results, "historical_passes": 45,
        "historical_phases": 135, "bodies_reexecuted": 0,
        "actual_original_full_rows_and_junit_reconciled": True,
        "same_immutable_candidate_source_bound": True, "qualification_complete": False,
    }
    write_json(REPORT / "prior-functional-admission.json", result)
    return result


def bind_previous_dependencies(run) -> dict:
    env = json.loads((REPORT / "environment-before.json").read_bytes())
    files = run.before["files"]
    rows = []
    for name in ("candidate-existing-collection.json", "candidate-new-collection.json"):
        data = json.loads((REPORT / "original-functional" / name).read_bytes())
        for case in data["cases"]:
            definitions = [case["function"]]
            for fixtures in case["fixture_definitions"].values():
                definitions.extend(row["function"] for row in fixtures)
            for definition in definitions:
                if "builtin" in definition:
                    continue
                location = definition["path"]
                if location.startswith("@tests/"):
                    pin = files[location.removeprefix("@tests/")]
                elif location.startswith("@environment/"):
                    pin = env["dependency_files"][location.removeprefix("@environment/")]
                else:
                    raise AssertionError("Unexpected historical definition origin: " + location)
                assert pin["sha256"] == definition["whole_file_sha256"], location
                rows.append({"path": location, "sha256": pin["sha256"]})
            for origin in data["product_module_origins"].values():
                assert files["src/" + origin["path"]]["sha256"] == origin["sha256"]
    result = {
        "historical_definition_records": rows,
        "fresh_owned_environment_versions": env["installed_versions"],
        "historical_fixture_source_bytes_match_current_source_or_fresh_dependencies": True,
        "historical_bodies_reexecuted": False, "qualification_complete": False,
    }
    write_json(REPORT / "prior-fixture-currentness.json", result)
    return result
