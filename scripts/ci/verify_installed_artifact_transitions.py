"""Exercise real wheel replacements after paired timing, in a third environment.

The paired installations are never changed. The third virtual environment
installs candidate locked dependencies, then each exact local wheel, and
runs fresh isolated workers against one private home. Every replacement waits
for the prior worker's witnessed native generation retirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402

_PHASES = (
    ("clean_baseline", "baseline"),
    ("candidate_upgrade", "candidate"),
    ("candidate_reinstall", "candidate"),
    ("baseline_rollback", "baseline"),
    ("candidate_restore", "candidate"),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for value in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(value)
    return digest.hexdigest()


def artifact_contract(wheel: Path, build_sha: str) -> dict:
    if not isinstance(build_sha, str) or re.fullmatch(r"[0-9a-f]{40}", build_sha) is None:
        raise ValueError("qualification_transition_build_identity_invalid")
    return {
        "build_sha": build_sha,
        "wheel_sha256": sha256(wheel),
        "installed_package_sha256": wheel_package_digest(wheel),
    }


def _run(arguments: tuple[str, ...], root: Path):
    environment = dict(os.environ)
    clear_proof_environment(environment)
    for key in ("PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON"):
        environment.pop(key, None)
    # uv sync must target only this disposable prefix, never the paired
    # candidate project's default environment.
    if Path(arguments[0]).name in {"uv", "uv.exe"}:
        environment["UV_PROJECT_ENVIRONMENT"] = str(root / "installation")
    return run_isolated_hook_process(
        arguments, cwd=root, environment=environment, input_text="", timeout_seconds=180, output_limit=256 * 1024
    )


def _process_ok(result) -> bool:
    return (
        result.returncode == 0
        and not result.timed_out
        and not result.containment_failed
        and not result.output_limit_exceeded
    )


def _required_command(arguments: tuple[str, ...], root: Path) -> None:
    result = _run(arguments, root)
    if not _process_ok(result):
        raise RuntimeError("qualification_transition_installation_command_failed")


def worker_evidence(result, expected: dict, phase: str) -> dict:
    try:
        report = assert_privacy_safe(json.loads(result.stdout))
    except (ValueError, TypeError):
        report = {"passed": False, "failure": {"reason": "worker_evidence_invalid"}}
    identity = report.get("identity")
    expected_prior_receipts = 2 * next(index for index, item in enumerate(_PHASES) if item[0] == phase)
    complete = (
        _process_ok(result)
        and report.get("schema") == "hol-guard.installed-artifact-transition-phase.v1"
        and report.get("phase") == phase
        and report.get("passed") is True
        and report.get("cleanup_confirmed") is True
        and report.get("registered_native_cases") == 2
        and type(report.get("control_revision")) is int
        and report["control_revision"] >= 1
        and type(report.get("prior_receipts_verified")) is int
        and report["prior_receipts_verified"] == expected_prior_receipts
        and report.get("stale_control_write_rejected") is True
        and report.get("registration_preserved") is (phase != "clean_baseline")
        and report.get("authority_health") == "protected"
        and isinstance(identity, Mapping)
        and identity.get("installed_origin_verified") is True
        and isinstance(identity.get("runtime_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", identity["runtime_sha256"]) is not None
        and all(identity.get(key) == value for key, value in expected.items())
    )
    return {
        "phase": phase,
        "passed": complete,
        "worker": report,
        "worker_timed_out": result.timed_out,
        "worker_containment_failed": result.containment_failed,
        "worker_limit_exceeded": result.output_limit_exceeded,
    }


def verify(
    python: Path,
    baseline_wheel: Path,
    candidate_wheel: Path,
    baseline_sha: str,
    candidate_sha: str,
    *,
    dependency_root: Path,
) -> dict:
    contracts = {
        "baseline": artifact_contract(baseline_wheel, baseline_sha),
        "candidate": artifact_contract(candidate_wheel, candidate_sha),
    }
    report = {
        "schema": "hol-guard.installed-artifact-transitions.v1",
        "passed": False,
        "identities": contracts,
        "phases": [],
        "scope": "stopped_artifact_replacement_shared_fixture_authority",
        "dependency_environment": "candidate_locked_dependencies",
        "registered_scope": "claude-code.PostToolUse.benign_and_block",
        "paired_installations_modified": False,
        "shared_fixture_state": True,
        "interactive_enrollment_qualified": False,
        "live_mixed_generations_qualified": False,
        "in_progress_replacement_qualified": False,
        "signing_changes_qualified": False,
        "version_downgrade_qualified": False,
        "native_program_downgrade_qualified": False,
        "headline_timing_eligible": False,
        "program_qualification_complete": False,
    }
    try:
        if (
            baseline_sha == candidate_sha
            or contracts["baseline"]["wheel_sha256"] == contracts["candidate"]["wheel_sha256"]
        ):
            raise ValueError("qualification_transition_requires_distinct_artifacts")
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("qualification_transition_installer_unavailable")
        wheels = {"baseline": baseline_wheel, "candidate": candidate_wheel}
        dependency_lock = sha256(dependency_root / "uv.lock")
        report["dependency_lock_sha256"] = dependency_lock
        with tempfile.TemporaryDirectory(prefix="hol-guard-artifact-transition-") as temporary:
            root = Path(temporary).resolve()
            prefix = root / "installation"
            _required_command((uv, "venv", "--python", str(python), str(prefix)), root)
            worker_python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            _required_command(
                (
                    uv,
                    "sync",
                    "--frozen",
                    "--extra",
                    "dev",
                    "--no-install-project",
                    "--project",
                    str(dependency_root),
                    "--python",
                    str(worker_python),
                ),
                root,
            )
            fixture = root / "fixture"
            fixture.mkdir(mode=0o700)
            for phase, arm in _PHASES:
                if sha256(wheels[arm]) != contracts[arm]["wheel_sha256"]:
                    raise RuntimeError("qualification_transition_wheel_changed")
                _required_command(
                    (
                        uv,
                        "pip",
                        "install",
                        "--python",
                        str(worker_python),
                        "--no-index",
                        "--no-deps",
                        "--force-reinstall",
                        str(wheels[arm]),
                    ),
                    root,
                )
                expected = root / "expected.json"
                expected.write_text(json.dumps(contracts[arm]), encoding="utf-8")
                expected.chmod(0o600)
                result = _run(
                    (
                        str(worker_python),
                        "-I",
                        str(Path(__file__).with_name("installed_artifact_transition_probe.py")),
                        "--expected",
                        str(expected),
                        "--fixture-root",
                        str(fixture),
                        "--phase",
                        phase,
                    ),
                    root,
                )
                observed = worker_evidence(result, contracts[arm], phase)
                report["phases"].append(observed)
                # Never overwrite the installation after an unverified native
                # shutdown, even if a malformed worker claims successful work.
                if not observed["passed"]:
                    break
            report["passed"] = len(report["phases"]) == len(_PHASES) and all(row["passed"] for row in report["phases"])
        if any(sha256(wheels[arm]) != contracts[arm]["wheel_sha256"] for arm in wheels):
            raise RuntimeError("qualification_transition_wheel_changed")
        if sha256(dependency_root / "uv.lock") != dependency_lock:
            raise RuntimeError("qualification_transition_dependency_lock_changed")
    except Exception as error:
        report["passed"] = False
        report["failure"] = failure_evidence(error)
    report["completed_phase_count"] = sum(row["passed"] for row in report["phases"])
    report["required_phase_count"] = len(_PHASES)
    return assert_privacy_safe(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--candidate-wheel", type=Path, required=True)
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--dependency-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(
            args.python.absolute(),
            args.baseline_wheel.resolve(),
            args.candidate_wheel.resolve(),
            args.baseline_sha,
            args.candidate_sha,
            dependency_root=args.dependency_root.resolve(),
        )
    except Exception as error:
        result = {
            "schema": "hol-guard.installed-artifact-transitions.v1",
            "passed": False,
            "failure": failure_evidence(error),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
