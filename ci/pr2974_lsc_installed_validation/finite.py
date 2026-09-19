"""Run fresh exact-source checks, affected tests and clean-wheel seam controls."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json
from environment_setup import finish_environment, prepare_environment, secure_launchers
from packages import run_packages


def collected(path: Path) -> dict:
    data = json.loads(path.read_text())
    assert data["pytest_exit_code"] == 0 and data["error"] is None, str(path)
    assert data["collection_only"] and data["collection_bound_before_execution"], str(path)
    assert data["test_call_entries"] == data["fixture_setup_entries"] == 0 and not data["phase_reports"]
    cases = data["cases"]
    assert 0 < len(cases) <= 2000 and len({case["nodeid"] for case in cases}) == len(cases)
    return data


def junit_key(nodeid: str) -> tuple[str, str]:
    plain, separator, parameter = nodeid.partition("[")
    parts = plain.split("::")
    assert parts[0].endswith(".py") and len(parts) >= 2, nodeid
    classname = ".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]])
    return classname, parts[-1] + (separator + parameter if separator else "")


def execution(path: Path, prior: Path, junit: Path, *, no_skips: bool) -> dict:
    data = json.loads(path.read_text())
    collection = collected(prior)
    assert not data["collection_only"] and data["collection_bound_before_execution"]
    assert data["cases"] == collection["cases"]
    root = ET.parse(junit).getroot()
    cases = root.findall(".//testcase")
    nodes = [case["nodeid"] for case in data["cases"]]
    expected_keys = [junit_key(node) for node in nodes]
    actual_keys = [(case.get("classname"), case.get("name")) for case in cases]
    ordered_identity_equal = actual_keys == expected_keys
    by_node = {node: [] for node in nodes}
    unexpected_phases = []
    for row in data["phase_reports"]:
        if row["nodeid"] in by_node:
            by_node[row["nodeid"]].append(row)
        else:
            unexpected_phases.append(row)
    case_bindings = []
    for index, node in enumerate(nodes):
        phases = by_node[node]
        case = cases[index] if index < len(cases) else None
        expected_outcomes = {
            "failure": sum(row["when"] == "call" and row["outcome"] == "failed" for row in phases),
            "error": sum(row["when"] != "call" and row["outcome"] == "failed" for row in phases),
            "skipped": sum(row["outcome"] == "skipped" for row in phases)}
        actual_outcomes = (
            {kind: len(case.findall(kind)) for kind in ("failure", "error", "skipped")}
            if case is not None else None)
        same_identity = index < len(actual_keys) and actual_keys[index] == expected_keys[index]
        case_bindings.append({
            "nodeid": node, "expected_xml_identity": expected_keys[index],
            "actual_xml_identity": actual_keys[index] if index < len(actual_keys) else None,
            "identity_equal": same_identity, "phase_outcomes": [
                {"phase": row["when"], "outcome": row["outcome"], "wasxfail": row["wasxfail"]}
                for row in phases],
            "expected_xml_outcome_elements": expected_outcomes,
            "actual_xml_outcome_elements": actual_outcomes,
            "xml_outcomes_match_node_phases": same_identity and actual_outcomes == expected_outcomes})
    counts = {"tests": len(cases), "failed": sum(item.find("failure") is not None for item in cases),
              "errored": sum(item.find("error") is not None for item in cases),
              "skipped": sum(item.find("skipped") is not None for item in cases)}
    observed = {
        "snapshot": path.name, "prior_collection": prior.name, "junit": junit.name,
        "pytest_exit_code": data["pytest_exit_code"], "observer_error": data["error"],
        "collection_count": len(data["cases"]), "execution_collection_equals_prior": data["cases"] == collection["cases"],
        "ordered_junit_identities_equal": ordered_identity_equal,
        "expected_junit_identities_unique": len(set(expected_keys)) == len(expected_keys),
        "actual_junit_identities_unique": len(set(actual_keys)) == len(actual_keys),
        "junit_node_bindings": case_bindings, "unexpected_phase_nodes": unexpected_phases,
        "junit_counts": counts, "phase_counts": {
            phase: {outcome: sum(row["when"] == phase and row["outcome"] == outcome
                                for row in data["phase_reports"])
                    for outcome in ("passed", "failed", "skipped")}
            for phase in ("setup", "call", "teardown")},
        "nonpassing_phase_nodes": [{"nodeid": row["nodeid"], "phase": row["when"], "outcome": row["outcome"]}
                                  for row in data["phase_reports"] if row["outcome"] != "passed"],
        "no_skips_required": no_skips, "qualification_complete": False}
    write_json(REPORT / (path.stem + "-reconciliation.json"), observed)
    assert ordered_identity_equal, "JUnit case identities differ from ordered collection"
    assert len(set(expected_keys)) == len(expected_keys) and len(set(actual_keys)) == len(actual_keys)
    assert not unexpected_phases
    assert all(row["xml_outcomes_match_node_phases"] for row in case_bindings)
    assert data["pytest_exit_code"] == 0 and data["error"] is None, str(path)
    assert counts["tests"] == len(data["cases"])
    assert counts["failed"] == counts["errored"] == 0, counts
    if no_skips:
        assert counts["skipped"] == 0, counts
    reports = {}
    for row in data["phase_reports"]:
        assert row["nodeid"] in set(nodes)
        phases = reports.setdefault(row["nodeid"], {})
        assert row["when"] not in phases
        phases[row["when"]] = row
    assert set(reports) == set(nodes)
    phase_passed = phase_skipped = 0
    for node in nodes:
        phases = reports[node]
        assert [row["when"] for row in by_node[node]] in (
            ["setup", "call", "teardown"], ["setup", "teardown"])
        assert phases["teardown"]["outcome"] == "passed"
        assert all(row["outcome"] != "failed" and row["wasxfail"] is None for row in phases.values())
        if phases["setup"]["outcome"] == "skipped":
            assert "call" not in phases
            phase_skipped += 1
        elif phases["call"]["outcome"] == "skipped":
            phase_skipped += 1
        else:
            assert phases["setup"]["outcome"] == phases["call"]["outcome"] == "passed"
            phase_passed += 1
    assert phase_skipped == counts["skipped"]
    assert phase_passed + phase_skipped == counts["tests"]
    return counts | {"passed": phase_passed, "all_cases_without_skip": phase_skipped == 0,
                     "ordered_junit_and_node_phase_outcomes_equal": True}


def pytest_command(run, env, python, name, root, product, tests, *, prior=None, installed=False):
    snapshot = REPORT / (name + ".json")
    junit = REPORT / (name + "-junit.xml")
    child_env = dict(env, LSC_TEST_ROOT=str(root), LSC_PRODUCT_ROOT=str(product),
                     LSC_TEST_REPORT=str(snapshot), LSC_COLLECTION_ONLY="0" if prior else "1")
    if prior:
        child_env["LSC_PRIOR_COLLECTION"] = str(prior)
    args = [str(python), "-I", "-B", str(HERE / "pytest_capture.py")]
    if installed:
        args += ["--noconftest", "-c", "/dev/null", "--rootdir", str(root)]
    args += ["-q", "-m", "", "--tb=short", "-o", "cache_dir=" + str(SCRATCH / "pytest-cache" / name),
             "--basetemp", str(SCRATCH / "tmp" / name)]
    if prior:
        args += ["--junitxml", str(junit)]
    else:
        args += ["--collect-only"]
    args += tests
    ok = run.command(name, args, cwd=root, env=child_env, timeout=900 if prior else 300)
    if prior is None:
        assert ok, name + " collection failed; original snapshot/log retained"
    return snapshot, junit


def installed_seams(run, env, wheel, create_venv, *, after_collection=None):
    venv = create_venv("installed-environment")
    python = venv / "bin/python"
    install_env = dict(env, UV_PROJECT_ENVIRONMENT=str(venv),
                       LSC_INSTALLED_VENV=str(venv), LSC_INSTALLED_WHEEL=str(wheel))
    uv = os.environ["VALIDATION_UV"]
    run.require(run.command("installed-frozen-dependencies", [
        uv, "--no-config", "sync", "--frozen", "--extra", "dev", "--python", str(python),
    ], env=install_env, timeout=420), "Clean environment frozen dependency setup failed")
    secure_launchers(venv)
    run.require(run.command("installed-project-wheel", [
        uv, "--no-config", "pip", "install", "--python", str(python), "--reinstall", "--no-deps", str(wheel),
    ], cwd=SCRATCH, env=install_env, timeout=180), "Clean wheel installation failed")
    run.require(run.command("installed-dependency-compatibility", [
        uv, "--no-config", "pip", "check", "--python", str(python),
    ], cwd=SCRATCH, env=install_env), "Clean environment dependency compatibility failed")
    before = REPORT / "installed-before.json"
    run.require(run.command("installed-before", [
        str(python), "-I", "-B", str(HERE / "installed_check.py"), str(before),
    ], cwd=SCRATCH, env=install_env), "Installed wheel binding failed")
    result = None
    stage_failure = None
    try:
        information = json.loads(before.read_text())
        test_root = SCRATCH / "tmp" / "installed-test-source"
        test_root.mkdir()
        original = SOURCE / CONFIG["seam_test"]
        copied = test_root / original.name
        copied.write_bytes(original.read_bytes())
        assert sha256(copied.read_bytes()) == CONFIG["partition_files"][CONFIG["seam_test"]]["sha256"]
        product = Path(information["product_root"])
        collection, _ = pytest_command(run, install_env, python, "installed-seam-collection",
                                       test_root, product, [copied.name], installed=True)
        assert len(collected(collection)["cases"]) == 25
        if after_collection is not None:
            after_collection(collection)
        snapshot, junit = pytest_command(run, install_env, python, "installed-seam-execution",
                                         test_root, product, [copied.name], prior=collection, installed=True)
        result = execution(snapshot, collection, junit, no_skips=True)
    except BaseException as error:
        stage_failure = error
        raise
    finally:
        finalizer_failure = None
        try:
            after = REPORT / "installed-after.json"
            run.require(run.command("installed-after", [
                str(python), "-I", "-B", str(HERE / "installed_check.py"), str(after),
            ], cwd=SCRATCH, env=install_env), "Final installed package binding failed")
            assert before.read_bytes() == after.read_bytes(), "Installed dependency or package bytes changed"
        except BaseException as error:
            finalizer_failure = error
        write_json(REPORT / "installed-seam-finalization.json", {
            "stage_error": repr(stage_failure) if stage_failure is not None else None,
            "finalizer_error": repr(finalizer_failure) if finalizer_failure is not None else None,
            "installed_before_file": before.name,
            "installed_before_sha256": sha256(before.read_bytes()),
            "installed_after_file": "installed-after.json",
            "installed_after_sha256": (
                sha256((REPORT / "installed-after.json").read_bytes())
                if (REPORT / "installed-after.json").is_file() else None),
            "installed_before_after_identical": finalizer_failure is None,
            "generic_junit_identity_contract_unchanged": True,
            "qualification_complete": False,
        })
        if finalizer_failure is not None:
            if stage_failure is None:
                raise finalizer_failure
            raise RuntimeError(
                "Installed stage failed: " + repr(stage_failure)
                + "; installed finalizer failed: " + repr(finalizer_failure)
            ) from stage_failure
    assert result is not None
    return result


def main() -> int:
    run = Run("local-supply-chain-source-and-finite")
    errors, results = [], {}
    env, primary, create_venv = None, None, None
    try:
        run.before = source_witness("before")
        run.require(run.command("source-contract", [
            sys.executable, "-I", "-B", str(HERE / "source_contract.py"),
        ], env=dict(os.environ), timeout=180), "Original ordered module and live facade source proof failed")
        selected = json.loads((REPORT / "existing-test-selection.json").read_text())["files"]
        env, primary, create_venv = prepare_environment(run)
        run.command("ruff-partition", [str(primary.parent / "ruff"), "check", *CONFIG["partition_files"]], env=env)
        run.command("ruff-format-partition", [
            str(primary.parent / "ruff"), "format", "--check", *CONFIG["partition_files"]], env=env)
        run.command("types-original-facade", [
            str(primary.parent / "basedpyright"), "--pythonpath", str(primary), "--outputjson", "--level", "error", CONFIG["facade_path"]],
            cwd=BASELINE, env=env, timeout=300)
        run.command("types-candidate-partition", [
            str(primary.parent / "basedpyright"), "--pythonpath", str(primary), "--outputjson", "--level", "error", *CONFIG["production_paths"]],
            env=env, timeout=300)
        baseline, _ = pytest_command(run, env, primary, "baseline-existing-collection",
                                     BASELINE, BASELINE / "src", selected)
        candidate, _ = pytest_command(run, env, primary, "candidate-existing-collection",
                                      SOURCE, SOURCE / "src", selected)
        original_cases, candidate_cases = collected(baseline)["cases"], collected(candidate)["cases"]
        assert original_cases == candidate_cases, "Existing ordered collection/fixture/marker/parameter mismatch"
        write_json(REPORT / "existing-collection-comparison.json", {
            "baseline_count": len(original_cases), "candidate_count": len(candidate_cases),
            "exact_ordered_case_records_equal": True, "fixture_or_test_execution": False})
        seam, _ = pytest_command(run, env, primary, "source-seam-collection",
                                 SOURCE, SOURCE / "src", [CONFIG["seam_test"]])
        assert len(collected(seam)["cases"]) == 25
        try:
            snapshot, junit = pytest_command(run, env, primary, "candidate-existing-execution",
                                             SOURCE, SOURCE / "src", selected, prior=candidate)
            results["existing"] = execution(snapshot, candidate, junit, no_skips=False)
        except Exception as error:
            errors.append("Existing finite cases: " + repr(error))
        try:
            snapshot, junit = pytest_command(run, env, primary, "source-seam-execution",
                                             SOURCE, SOURCE / "src", [CONFIG["seam_test"]], prior=seam)
            results["source_seams"] = execution(snapshot, seam, junit, no_skips=True)
        except Exception as error:
            errors.append("New25 source seam cases: " + repr(error))
        try:
            wheel = run_packages(run, env, primary, create_venv)
            results["installed_seams"] = installed_seams(run, env, wheel, create_venv)
        except Exception as error:
            errors.append("Clean package validation: " + repr(error))
    except Exception as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except Exception as error:
                errors.append("Environment finalizer: " + repr(error))
        write_json(REPORT / "finite-results.json", {
            "results": results, "errors": errors, "new_source_seam_expected": 25,
            "clean_wheel_seam_expected": 25, "existing_skips_retained_and_not_qualification_credit": True,
            "qualification_complete": False})
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
