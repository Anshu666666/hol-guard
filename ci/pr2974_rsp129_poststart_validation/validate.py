"""Gate one installed poststart diagnostic behind fresh finite and source checks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, HERE, REPORT, SCRATCH, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_controls import run as finite_controls
from native_package import ARTIFACTS, build_runtime, environment_check, package_and_install
from rust_environment import finish_rust, prepare_rust
from source_gates import source_gates


def retain_artifact_index() -> dict:
    files = {}
    total = 0
    if ARTIFACTS.exists():
        for path in sorted(ARTIFACTS.rglob("*")):
            if not path.is_file():
                continue
            assert not path.is_symlink() and len(files) < 32
            hasher = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                for raw in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(raw)
                    total += len(raw)
                    assert size <= 1088 * 1024 * 1024 and total <= 3 * 1024 * 1024 * 1024
                    hasher.update(raw)
            files[path.relative_to(ARTIFACTS).as_posix()] = {"bytes": size, "sha256": hasher.hexdigest()}
    record = {"files": files, "total_bytes": total, "qualification_complete": False}
    write_json(REPORT / "installed-artifact-manifest.json", record)
    return record


def main() -> int:
    run = Run("poststart-finite-and-installed-diagnostic")
    env = primary = programs = None
    errors = []
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "finite_cases_planned": 29, "source_gates_passed": False, "finite_controls_passed": False,
        "ordinary_child_reap_control_passed": False,
        "native_build_attempted": False, "native_build_passed": False,
        "installed_package_passed": False, "diagnostic_command_attempted": False,
        "diagnostic_fixture_started": False, "diagnostic_command_passed": False,
        "prerequisite_gate_passed": False, "headline_timing_eligible": False,
        "qualification_complete": False, "errors": errors,
    }
    write_json(REPORT / "poststart-validation-summary.json", state)
    try:
        assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
        run.before = source_witness("before")
        env, primary, create_venv = prepare_environment(run)
        state["source_gates_passed"] = source_gates(run, env, primary)
        state["ordinary_child_reap_control_passed"] = run.command("ordinary-child-reap-control", [
            str(primary), "-I", "-B", str(HERE / "ordinary_child_reap_control.py"),
        ], timeout=30, env=env)
        run.require(state["ordinary_child_reap_control_passed"], "Real ordinary-child reap control failed")
        os.environ.clear()
        os.environ.update(env)
        state["finite_controls_passed"] = finite_controls(run.steps)
        write_json(REPORT / "steps.json", run.steps)
        state["prerequisite_gate_passed"] = (
            state["source_gates_passed"] and state["finite_controls_passed"]
            and state["ordinary_child_reap_control_passed"]
            and all(row["passed"] for row in run.steps)
        )
        write_json(REPORT / "poststart-validation-summary.json", state)
        run.require(state["prerequisite_gate_passed"], "Fresh29/source prerequisites failed; installed stage remains unoffered")
        state["native_build_attempted"] = True
        env, programs = prepare_rust(run, env)
        binary, capabilities = build_runtime(run, env, programs)
        state["native_build_passed"] = True
        installed, _backend, installed_env = package_and_install(run, env, create_venv, binary, capabilities)
        state["installed_package_passed"] = True
        state["diagnostic_command_attempted"] = True
        write_json(REPORT / "poststart-validation-summary.json", state)
        state["diagnostic_command_passed"] = run.command("poststart-installed-diagnostic", [
            str(installed), "-I", "-B", str(HERE / "installed_entry.py"),
        ], cwd=SCRATCH, timeout=300, env=installed_env)
        admission = REPORT / "installed-diagnostic-admission.json"
        if admission.is_file():
            state["diagnostic_fixture_started"] = json.loads(admission.read_bytes()).get("started") is True
        run.require(state["diagnostic_command_passed"], "Original installed diagnostic or owned-group cleanup failed")
    except BaseException:
        errors.append({"scope": "validation", "traceback": traceback.format_exc()})
    finally:
        if env is not None:
            for kind, directory in (
                ("backend", "poststart-build-environment"),
                ("installed", "poststart-installed-environment"),
            ):
                python = SCRATCH / directory / "bin/python"
                before = REPORT / (kind + "-environment-before.json")
                after = REPORT / (kind + "-environment-after.json")
                if python.is_file() and not after.exists():
                    try:
                        environment_check(
                            run, kind + "-environment-after", python, env,
                            kind=kind, archive=False,
                            prior=kind + "-environment-before" if before.is_file() else None,
                        )
                    except BaseException:
                        errors.append({"scope": kind + "_final_inventory", "traceback": traceback.format_exc()})
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException:
                errors.append({"scope": "finite_environment_final", "traceback": traceback.format_exc()})
        if programs is not None:
            try:
                finish_rust(programs)
            except BaseException:
                errors.append({"scope": "rust_environment_final", "traceback": traceback.format_exc()})
        try:
            state["retained_artifacts"] = retain_artifact_index()
        except BaseException:
            errors.append({"scope": "artifact_retention", "traceback": traceback.format_exc()})
        state["all_stages_passed"] = bool(
            state["prerequisite_gate_passed"] and state["native_build_passed"]
            and state["installed_package_passed"] and state["diagnostic_command_passed"] and not errors
        )
        state["initial_compilation_measured"] = False
        state["no_python_process_restart_or_automatic_restore_claim"] = True
        state["later_cleanup_does_not_clear_recorded_failures"] = True
        state["no_complete_escaped_descendant_cleanup_certificate"] = True
        write_json(REPORT / "poststart-validation-summary.json", state)
        if errors or not state["all_stages_passed"]:
            run.error = repr(errors) if errors else "At least one required stage did not pass"
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
