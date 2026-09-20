"""Run a fixed current-source Rust unit gate before installed diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from native_package import ARTIFACTS
from native_unit_protocol import admit_list, admit_run, original_log, retain_evidence
from rust_environment import file_record

PLAN_PATH = HERE / "native-unit-plan.json"


def admitted_plan() -> dict:
    raw = PLAN_PATH.read_bytes()
    assert 0 < len(raw) <= 65536
    assert sha256(raw) == CONFIG["native_unit_plan_sha256"]
    plan = json.loads(raw)
    assert plan["schema"] == "pr2974.native-noncommand-unit-gate.v1"
    assert plan["total_test_entries"] == 24 and plan["python_consumer_cases"] == 3
    assert plan["compile_timeout_seconds"] == 600
    assert plan["list_timeout_seconds"] == 30 and plan["module_timeout_seconds"] == 60
    assert plan["consumer_timeout_seconds"] == 60
    assert plan["separate_from_poststart29"] is True
    assert plan["default_features_unchanged"] is True and plan["qualification_complete"] is False
    modules = plan["modules"]
    assert [row["name"] for row in modules] == [
        "command-controls", "runtime-noncommand",
        "runtime-deadlines", "runtime-retry",
    ]
    assert [len(row["expected_tests"]) for row in modules] == [9, 3, 9, 3]
    all_names = []
    for row in modules:
        body = (SOURCE / row["source_path"]).read_bytes()
        assert sha256(body) == row["source_sha256"] == CONFIG["source_inputs"][row["source_path"]]
        blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        assert blob == row["source_git_blob"]
        assert row["expected_tests"] == sorted(set(row["expected_tests"]))
        assert all(name.startswith(row["filter"]) for name in row["expected_tests"])
        all_names.extend(row["expected_tests"])
    assert len(all_names) == len(set(all_names)) == 24
    evidence = plan["evidence"]
    assert evidence["records"] == 3 and evidence["labels"] == ["WebFetch", "Read", "MCP"]
    assert evidence["per_record_utf8_limit_bytes"] == 65536
    assert evidence["emitting_test"] in modules[1]["expected_tests"]
    assert "HOL_GUARD_RETRY_OWNER_CHILD" not in os.environ
    assert "HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE" not in os.environ
    return plan


def test_artifact(name: str, specification: dict, target: Path,
                  steps: list[dict]) -> dict:
    raw, log = original_log(name, steps)
    matches = []
    finished = []
    for line in raw.decode("utf-8").splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        if row.get("reason") == "build-finished":
            finished.append(row.get("success"))
        if row.get("reason") != "compiler-artifact":
            continue
        if row.get("manifest_path") != str(SOURCE / specification["manifest"]):
            continue
        description = row["target"]
        if description.get("kind") != specification["kind"]:
            continue
        if description.get("name") != specification["target_name"]:
            continue
        if row["profile"]["test"] is not True:
            continue
        assert description["src_path"] == str(SOURCE / specification["src_path"])
        assert row["features"] == specification["features"]
        assert row["profile"]["opt_level"] == "3" and row["fresh"] is False
        executable = Path(row["executable"])
        assert executable.is_absolute() and not executable.is_symlink()
        assert executable.resolve(strict=True).is_relative_to(target)
        matches.append({
            **file_record(executable), "source_sha": CONFIG["source_sha"],
            "source_tree": CONFIG["source_tree"], "toolchain": CONFIG["rust_toolchain"],
            "cargo_target_directory": str(target), "cargo_message": row,
            "features": row["features"], "build_profile": "release",
            "test_binary": True, "default_features_unchanged": True,
            "build_command_name": name, "original_build_log": log,
        })
    assert finished == [True] and len(matches) == 1
    return matches[0]


def retain_binary(name: str, binary: dict) -> dict:
    path = ARTIFACTS / ("native-unit-" + name)
    assert ARTIFACTS.is_dir() and not path.exists() and not path.is_symlink()
    with Path(binary["path"]).open("rb") as source, path.open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    path.chmod(0o755)
    record = file_record(path)
    assert record["sha256"] == binary["sha256"] and record["bytes"] == binary["bytes"]
    return {**binary, "retained_artifact_path": str(path), "retained_binary": record}


def run_native_units(run: Run, env: dict[str, str], programs: dict[str, str]) -> dict:
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "plan_sha256": CONFIG["native_unit_plan_sha256"], "planned_test_entries": 24,
        "stages": [], "binaries": {}, "errors": [], "passed": False,
        "python_consumer_cases_planned": 3, "python_consumer_executed": False,
        "separate_from_poststart29": True, "initial_compilation_measured": False,
        "historical_native_pass_rebound_to_current_source": False,
        "qualification_complete": False,
    }
    output = REPORT / "native-unit-gate.json"
    write_json(output, state)
    try:
        assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
        plan = admitted_plan()
        assert "HOL_GUARD_RETRY_OWNER_CHILD" not in env
        assert "HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE" not in env
        target = SCRATCH / "rust-target-poststart-current-units"
        assert not target.exists() and not target.is_symlink()
        target.mkdir(mode=0o700)
        for name, specification in plan["binaries"].items():
            command = "native-unit-" + name + "-build"
            stage = {"name": command, "kind": "fresh_test_build", "started": True, "passed": False}
            state["stages"].append(stage)
            write_json(output, state)
            passed = run.command(command, [
                programs["cargo"], "test", "--locked", "--release", "-p", specification["package"],
                *specification["target_args"], "--no-run", "--target-dir", str(target),
                "--message-format=json",
            ], cwd=SOURCE / "rust", timeout=600, env=env)
            run.require(passed, "Fresh current-source Rust unit compilation failed")
            binary = test_artifact(command, specification, target, run.steps)
            state["binaries"][name] = retain_binary(name, binary)
            stage["passed"] = True
            write_json(output, state)
        for module in plan["modules"]:
            binary = state["binaries"][module["binary"]]
            executable = binary["retained_artifact_path"]
            assert file_record(Path(executable)) == binary["retained_binary"]
            list_name = "native-unit-" + module["name"] + "-list"
            stage = {"name": module["name"], "kind": "unit_module", "started": True,
                     "list_passed": False, "body_attempted": False, "passed": False}
            state["stages"].append(stage)
            write_json(output, state)
            passed = run.command(list_name, [
                executable, module["filter"], "--list", "--format", "pretty", "--color", "never",
            ], cwd=SCRATCH, timeout=30, env=env)
            raw, list_log = original_log(list_name, run.steps)
            stage["original_list_log"] = list_log
            run.require(passed, "Exact native unit collection command failed")
            stage["list"] = admit_list(raw, module["expected_tests"])
            stage["list_passed"] = True
            stage["body_attempted"] = True
            write_json(output, state)
            run_name = "native-unit-" + module["name"] + "-run"
            passed = run.command(run_name, [
                executable, module["filter"], "--format", "pretty", "--color", "never",
                "--test-threads=1", "--nocapture",
            ], cwd=SCRATCH, timeout=60, env=env)
            raw, body_log = original_log(run_name, run.steps)
            stage["original_run_log"] = body_log
            evidence = plan["evidence"] if module["name"] == "runtime-noncommand" else None
            if evidence is not None:
                state["native_evidence"] = retain_evidence(raw, evidence, body_log, binary)
                write_json(output, state)
            run.require(passed, "Current-source native unit body or owned cleanup failed")
            stage["result"] = admit_run(raw, module["expected_tests"], evidence)
            if evidence is not None:
                run.require(state["native_evidence"]["complete"], "Native record retention incomplete")
            stage["passed"] = True
            write_json(output, state)
        assert sum(stage.get("result", {}).get("passed_count", 0)
                   for stage in state["stages"]) == 24
        assert state["native_evidence"]["record_count"] == 3
        assert state["native_evidence"]["complete"] is True
        assert all(stage["passed"] for stage in state["stages"])
        state["passed"] = True
    except BaseException:
        state["errors"].append({"scope": "native_unit_gate", "traceback": traceback.format_exc()})
        raise
    finally:
        pending = sys.exc_info()[0] is not None
        for name, binary in state["binaries"].items():
            try:
                retained = file_record(Path(binary["retained_artifact_path"]))
                original = file_record(Path(binary["path"]))
                assert retained == binary["retained_binary"]
                assert all(original[key] == binary[key]
                           for key in ("path", "sha256", "bytes", "uid", "mode"))
                binary["after_original"] = original
                binary["after_retained"] = retained
                binary["unchanged_after_all_attempted_modules"] = True
            except BaseException:
                state["errors"].append({
                    "scope": "unit_binary_final:" + name, "traceback": traceback.format_exc(),
                })
        state["passed"] = state["passed"] and not state["errors"]
        write_json(output, state)
        if not pending:
            run.require(state["passed"], "Native unit gate or final binary identity did not pass")
    return state
