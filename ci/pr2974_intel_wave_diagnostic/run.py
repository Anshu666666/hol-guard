"""One original installed-SLO schedule, preserving every diagnostic failure."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import sys
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import CONFIG, REPORT, SCRATCH, SOURCE, admission, command, digest, retain_frames, source_witness, write_json
from inputs import original_inputs


def require(record, reason):
    assert record["passed"], reason


def environment():
    assert platform.system() == "Darwin" and platform.machine() == "x86_64"
    assert platform.python_version() == CONFIG["python_version"]
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PYTHONDONTWRITEBYTECODE",
                "AUDIT_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        env.pop(key, None)
    env.update(UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy",
               UV_PYTHON_DOWNLOADS="never", UV_NO_PROGRESS="1")
    uv = os.environ["VALIDATION_UV"]
    require(command("uv-version", [uv, "--version"], env=env), "uv version query failed")
    assert (REPORT / "uv-version.log").read_text().split()[:2] == ["uv", CONFIG["uv_version"]]
    node = shutil.which("node")
    assert node
    require(command("node-version", [node, "--version"], env=env), "Node version query failed")
    assert (REPORT / "node-version.log").read_text().strip() == "v" + CONFIG["node_version"]
    write_json(REPORT / "host.json", {
        "python": sys.version, "python_executable": sys.executable,
        "python_bytes": digest(Path(sys.executable).resolve().read_bytes()),
        "uv_path": str(Path(uv).resolve()), "uv_bytes": digest(Path(uv).resolve().read_bytes()),
        "node_path": str(Path(node).resolve()), "node_bytes": digest(Path(node).resolve().read_bytes()),
        "platform": platform.platform(), "uname": list(os.uname()), "cpu_count": os.cpu_count(),
        "intended_settings": {key: env.get(key) for key in
            ("HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "MACOSX_DEPLOYMENT_TARGET", "PLATFORM_TAG")},
        "runner_image": {key: env.get(key) for key in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
        "original_image_version": "20260824.0482.1",
        "same_machine_or_full_prior_environment": "not_established",
        "qualification_complete": False})
    venv = SCRATCH / "environment"
    assert not venv.exists() and not venv.is_symlink()
    require(command("create-owned-environment", [
        sys.executable, "-I", "-B", "-m", "venv", "--copies", "--without-pip", venv,
    ], env=env), "Owned environment creation failed")
    primary = venv / "bin/python"
    env.update(VALIDATION_VENV=str(venv), UV_PROJECT_ENVIRONMENT=str(venv))
    require(command("frozen-dependencies", [
        uv, "--no-config", "sync", "--frozen", "--extra", "dev", "--no-install-project",
        "--python", primary,
    ], env=env, timeout=420), "Frozen dependency installation failed")
    return env, uv, primary


def final_result():
    observation = json.loads((REPORT / "phase-observation.json").read_text())
    result = json.loads((REPORT / "instrumented-original-slo.json").read_text())
    write_json(REPORT / "instrumented-result-scope.json", {
        "scope": "instrumented_original_schedule_not_headline_slo",
        "original_report_preserved": True, "new_slo_report_sha256":
            digest((REPORT / "instrumented-original-slo.json").read_bytes())["sha256"],
        "headline_timing_eligible": False, "qualification_complete": False})
    assert result["schema"] == "hol-guard.native-installed-slo.v1", "Original schedule did not complete"
    assert result["thresholds"] == CONFIG["original_slo"]["thresholds"]
    assert set(result["gates"]) == set(CONFIG["original_slo"]["gates"])
    for name in ("architecture", "build_sha", "installed_package_sha256", "mode", "package_origin",
                 "package_version", "protocol_version", "python_version", "rule_digest",
                 "runtime_sha256", "runtime_version", "system", "target"):
        assert result["runtime"][name] == CONFIG["original_slo"]["runtime"][name], name
    assert observation["original_measure_c16_entries"] == 1 and len(observation["c16_wave_calls"]) == 1
    wave = observation["c16_wave_calls"][0]
    assert wave["instrumented"] and wave["original_wave_returned"] and wave["concurrency"] == 16
    assert wave["worker_matches_session_store"] and wave["same_parent_worker_after_wave"]
    assert wave["same_parent_store_after_wave"] and observation["patches_restored"]
    assert observation["wave"]["patches_restored"]
    assert observation["wave"]["calls"]["complete_at_snapshot"]
    assert observation["wave"]["existing_phase_aggregates"]["discarded_samples"] == 0
    assert observation["wave"]["existing_phase_aggregates"]["discarded_series_updates"] == 0
    assert observation["publication"]["summary"]["complete"]
    assert observation["constructor_reference_discarded"] == 0
    assert observation["constructor_observation"]["complete_at_snapshot"]
    assert observation["stage_entry_exit_calls"]["complete_at_snapshot"]
    return {"new_instrumented_gates": result["gates"], "new_instrumented_passed": result["passed"],
            "first_c16_routes": wave["selected_routes"], "original_c16_p99_ms": 1100.815,
            "original_concurrency_gate": False, "qualification_complete": False}


def main():
    before = None
    env = None
    primary = None
    before_environment = False
    outcome = {"schema": "pr2974.intel-phase-diagnostic-outcome.v1", "passed": False,
               "qualification_complete": False, "headline_timing_eligible": False, "errors": []}
    try:
        before = admission()
        wheel = original_inputs()
        # Preserve the prior eleven actual passes only where every involved helper is byte-identical.
        prior = CONFIG["prior_forwarding_controls"]
        for name, pin in prior["helper_sources"].items():
            assert digest((HERE / name).read_bytes()) == pin, name
        write_json(REPORT / "prior-forwarding-controls.json", {
            **prior, "current_helper_bytes_equal": True, "reexecuted": False,
            "scope": "prior_actual_forwarding_controls_with_exact_source_bridge"})
        controls_env = dict(os.environ)
        controls_env.pop("AUDIT_TOKEN", None)
        require(command("distribution-name-controls", [
            sys.executable, "-I", "-B", HERE / "name_controls.py", REPORT / "name-controls.json",
        ], env=controls_env), "Name admission controls failed")
        env, uv, primary = environment()
        require(command("install-original-wheel", [
            uv, "--no-config", "pip", "install", "--python", primary,
            "--no-deps", "--force-reinstall", wheel,
        ], env=env, timeout=180), "Original wheel installation failed")
        require(command("dependency-compatibility", [
            uv, "--no-config", "pip", "check", "--python", primary,
        ], env=env), "Installed dependency incompatibility")
        require(command("environment-before", [
            primary, "-I", "-B", HERE / "environment.py", REPORT / "environment-before.json",
        ], env=env), "Environment-before witness failed")
        before_environment = True
        original = json.loads((REPORT / "environment-before.json").read_text())
        env["NATIVE_STOP_DIAGNOSTIC_PATH"] = str(REPORT / "instrumented-stop-diagnostic.json")
        # Match original benchmark bytecode behavior; isolation prevents ambient source imports.
        benchmark = command("instrumented-original-slo", [
            primary, "-I", HERE / "observe.py", "--runtime", original["runtime_path"],
            "--warm-iterations", "2", "--cold-iterations", "2", "--recovery-iterations", "2",
            "--readiness-samples", "2", "--launcher-iterations", "2",
            "--json", REPORT / "instrumented-original-slo.json", "--enforce",
        ], env=env, timeout=900)
        outcome["observed_result"] = final_result()
        require(benchmark, "Original thresholds failed or original instrumented schedule did not complete")
        outcome["passed"] = True
    except BaseException as error:
        outcome["errors"].append({"type": type(error).__name__, "message": str(error)})
        (REPORT / "failure.log").write_text(traceback.format_exc())
    finally:
        if env is not None and primary is not None and before_environment:
            try:
                require(command("environment-after", [
                    primary, "-I", "-B", HERE / "environment.py", REPORT / "environment-after.json",
                ], env=env), "Environment-after witness failed")
                assert (REPORT / "environment-before.json").read_bytes() == (REPORT / "environment-after.json").read_bytes()
                outcome["installed_wheel_and_observed_environment_unchanged"] = True
            except BaseException as error:
                outcome["passed"] = False
                outcome["errors"].append({"final_environment": type(error).__name__, "message": str(error)})
        if before is not None:
            try:
                assert source_witness("after") == before
                outcome["tracked_source_unchanged"] = True
            except BaseException as error:
                outcome["passed"] = False
                outcome["errors"].append({"final_source": type(error).__name__, "message": str(error)})
        write_json(REPORT / "outcome.json", outcome)
        try:
            retain_frames()
        except BaseException as error:
            outcome["passed"] = False
            outcome["errors"].append({"frame_retention": type(error).__name__, "message": str(error)})
            write_json(REPORT / "outcome.json", outcome)
            print(json.dumps(outcome, sort_keys=True), flush=True)
    return 0 if outcome["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
