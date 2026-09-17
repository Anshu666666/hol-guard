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
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts import native_slo_evidence_files as evidence_files  # noqa: E402
from scripts.ci.installed_transition_state import PHASE_NAMES, STATE_LIMIT, write_private  # noqa: E402
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import FixtureFailureError, failure_evidence  # noqa: E402
from scripts.native_slo_interpreter import prepare_private_interpreter  # noqa: E402

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


def artifact_contract(wheel: Path, build_sha: str) -> dict[str, Any]:
    if not isinstance(build_sha, str) or re.fullmatch(r"[0-9a-f]{40}", build_sha) is None:
        raise ValueError("qualification_transition_build_identity_invalid")
    wheel_digest = sha256(wheel)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        candidates = {
            "codex_plugin_scanner/_native/hol-guard-runtime",
            "codex_plugin_scanner/_native/hol-guard-runtime.exe",
        }
        selected = [name for name in names if name in candidates]
        manifest_name = "codex_plugin_scanner/_native/runtime-manifest.json"
        if len(selected) != 1 or names.count(manifest_name) != 1 or len(names) != len(set(names)):
            raise ValueError("qualification_transition_wheel_runtime_ambiguous")
        member = selected[0]
        size = archive.getinfo(member).file_size
        if not 0 < size <= 128 * 1024 * 1024 or archive.getinfo(manifest_name).file_size > 4096:
            raise ValueError("qualification_transition_wheel_runtime_bounds")
        manifest = json.loads(archive.read(manifest_name))
        digest = hashlib.sha256()
        with archive.open(member) as runtime:
            for chunk in iter(lambda: runtime.read(1024 * 1024), b""):
                digest.update(chunk)
        if not (
            isinstance(manifest, dict)
            and manifest.get("schema") == "hol-guard-native-runtime.v1"
            and manifest.get("source_sha") == build_sha
            and type(manifest.get("runtime_size")) is int
            and manifest["runtime_size"] == size
            and manifest.get("runtime_sha256") == digest.hexdigest()
        ):
            raise ValueError("qualification_transition_wheel_runtime_identity")
    package_digest = wheel_package_digest(wheel)
    if sha256(wheel) != wheel_digest:
        raise ValueError("qualification_transition_wheel_changed")
    return {
        "build_sha": build_sha,
        "wheel_sha256": wheel_digest,
        "installed_package_sha256": package_digest,
        "runtime_sha256": digest.hexdigest(),
        "runtime_filename": Path(member).name,
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
        raise FixtureFailureError(
            {
                "schema": "hol-guard.native-qualification-failure.v1",
                "reason": "qualification_transition_installation_command_failed",
                "installer_stage": arguments[1] if arguments[1] in {"venv", "sync", "pip"} else "other",
                "installer_timed_out": result.timed_out is True,
                "installer_containment_failed": result.containment_failed is True,
                "installer_limit_exceeded": result.output_limit_exceeded is True,
                "installer_exit_code": result.returncode if type(result.returncode) is int else None,
            }
        )


def _project_worker(value: object) -> dict[str, Any]:
    """Expose only known typed fields; a child cannot publish arbitrary text."""
    if not isinstance(value, dict):
        return {"passed": False}
    projected: dict[str, Any] = {
        "schema": value.get("schema")
        if value.get("schema") == "hol-guard.installed-artifact-transition-phase.v1"
        else "invalid",
        "phase": value.get("phase") if value.get("phase") in {item[0] for item in _PHASES} else "invalid",
    }
    for field in (
        "passed",
        "cleanup_confirmed",
        "stale_control_write_rejected",
        "registration_preserved",
    ):
        if type(value.get(field)) is bool:
            projected[field] = value[field]
    for field in ("native_program_downgrade_qualified", "prior_binding_interpretation_qualified"):
        if value.get(field) is False:
            projected[field] = False
        elif value.get(field) is True:
            projected["unsupported_qualification_claim"] = True
    for field in ("registered_native_cases", "control_revision", "prior_receipts_verified"):
        if type(value.get(field)) is int and 0 <= value[field] <= 2**63 - 1:
            projected[field] = value[field]
    if value.get("authority_health") == "protected":
        projected["authority_health"] = "protected"
    if value.get("receipt_readback") in {"audited_baseline_sql", "installed_public_getter"}:
        projected["receipt_readback"] = value["receipt_readback"]
    identity = value.get("identity")
    if isinstance(identity, dict):
        selected: dict[str, Any] = {}
        for field, width in (
            ("build_sha", 40),
            ("wheel_sha256", 64),
            ("installed_package_sha256", 64),
            ("runtime_sha256", 64),
        ):
            if isinstance(identity.get(field), str) and re.fullmatch(f"[0-9a-f]{{{width}}}", identity[field]):
                selected[field] = identity[field]
        for field in ("installed_origin_verified", "native_program_supported"):
            if type(identity.get(field)) is bool:
                selected[field] = identity[field]
        if identity.get("runtime_filename") in {"hol-guard-runtime", "hol-guard-runtime.exe"}:
            selected["runtime_filename"] = identity["runtime_filename"]
        version = identity.get("package_version")
        if isinstance(version, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
            selected["package_version"] = version
        projected["identity"] = selected
    failure = value.get("failure")
    if "failure" in value:
        selected: dict[str, Any] = {"reason": "transition_worker_failed"}
        diagnostic = failure.get("diagnostic_digest") if isinstance(failure, dict) else None
        if isinstance(diagnostic, str) and re.fullmatch(r"[0-9a-f]{64}", diagnostic):
            selected["diagnostic_digest"] = diagnostic
        projected["failure"] = selected
    return projected


def worker_evidence(result, expected: dict[str, Any], phase: str) -> dict[str, Any]:
    report: dict[str, Any]
    try:
        report = _project_worker(json.loads(result.stdout))
    except (ValueError, TypeError, RecursionError):
        report = {"passed": False, "failure": {"reason": "worker_evidence_invalid"}}
    identity = report.get("identity")
    expected_prior_receipts = 2 * next(index for index, item in enumerate(_PHASES) if item[0] == phase)
    complete = (
        _process_ok(result)
        and report.get("schema") == "hol-guard.installed-artifact-transition-phase.v1"
        and report.get("phase") == phase
        and report.get("passed") is True
        and "failure" not in report
        and report.get("native_program_downgrade_qualified") is False
        and report.get("prior_binding_interpretation_qualified") is False
        and report.get("cleanup_confirmed") is True
        and type(report.get("registered_native_cases")) is int
        and report["registered_native_cases"] == 2
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
        and re.fullmatch(r"[0-9a-f]{64}", str(identity["runtime_sha256"])) is not None
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


def _retain_checkpoints(root: Path, destination: Path) -> dict[str, Any]:
    report: dict[str, Any] = {"files": 0, "complete": False}
    try:
        for phase in PHASE_NAMES:
            checkpoint = root / "transition-checkpoints" / f"{phase}.json"
            if not checkpoint.exists() and not checkpoint.is_symlink():
                continue
            content = evidence_files.read_file(checkpoint, STATE_LIMIT, private=True)
            evidence_files.atomic_exclusive(destination / f"installed-transition-{phase}.json", content)
            report["files"] += 1
        report["complete"] = True
    except Exception as error:
        report["failure"] = failure_evidence(error)
    return report


def verify(
    python: Path,
    baseline_wheel: Path,
    candidate_wheel: Path,
    baseline_sha: str,
    candidate_sha: str,
    *,
    dependency_root: Path,
    private_evidence: Path | None = None,
    expected_dependency_digest: str | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.installed-artifact-transitions.v1",
        "passed": False,
        "identities": {},
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
        "fixture_retained_for_unverified_retirement": False,
        "private_checkpoints_retained": 0,
        "fixture_retained_for_evidence_failure": False,
    }
    root = None
    retirement_confirmed = True
    try:
        if private_evidence is not None and private_evidence.name != "private_samples":
            raise ValueError("qualification_transition_private_destination_invalid")
        if expected_dependency_digest is not None and re.fullmatch(r"[0-9a-f]{64}", expected_dependency_digest) is None:
            raise ValueError("qualification_transition_dependency_identity_invalid")
        contracts = {
            "baseline": artifact_contract(baseline_wheel, baseline_sha),
            "candidate": artifact_contract(candidate_wheel, candidate_sha),
        }
        report["identities"] = contracts
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
        root = Path(tempfile.mkdtemp(prefix="hol-guard-artifact-transition-")).resolve()
        if any(
            root.is_relative_to(path) for path in (_ROOT, dependency_root.resolve(), python.absolute().parent.parent)
        ):
            raise ValueError("qualification_transition_fixture_not_external")
        prefix = root / "installation"
        retirement_confirmed = False
        _required_command((uv, "venv", "--python", str(python), str(prefix)), root)
        retirement_confirmed = True
        worker_python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        retirement_confirmed = False
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
        retirement_confirmed = True
        report["interpreter"] = prepare_private_interpreter(worker_python, environment_root=prefix)
        if expected_dependency_digest is not None:
            retirement_confirmed = False
            inventory = _run((str(worker_python), "-I", str(_ROOT / "scripts/native_slo_dependency_identity.py")), root)
            retirement_confirmed = _process_ok(inventory)
            if not retirement_confirmed or inventory.stdout.strip() != expected_dependency_digest:
                raise FixtureFailureError(
                    {
                        "schema": "hol-guard.native-qualification-failure.v1",
                        "reason": "qualification_transition_dependency_inventory_mismatch",
                        "worker_timed_out": inventory.timed_out is True,
                        "worker_containment_failed": inventory.containment_failed is True,
                        "worker_limit_exceeded": inventory.output_limit_exceeded is True,
                    }
                )
            report["dependency_versions_sha256"] = expected_dependency_digest
        fixture = root / "fixture"
        evidence_files.ensure_parent(fixture / "unused")
        for phase, arm in _PHASES:
            if sha256(wheels[arm]) != contracts[arm]["wheel_sha256"]:
                raise RuntimeError("qualification_transition_wheel_changed")
            retirement_confirmed = False
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
            retirement_confirmed = True
            expected = root / f"expected-{phase}.json"
            write_private(expected, contracts[arm])
            retirement_confirmed = False
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
            retirement_confirmed = observed["passed"] is True
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
    finally:
        if root is not None:
            if private_evidence is not None:
                try:
                    retained = _retain_checkpoints(root / "fixture", private_evidence)
                    report["private_checkpoint_retention"] = retained
                    report["private_checkpoints_retained"] = retained["files"]
                    if not retained["complete"]:
                        report["passed"] = False
                        report["fixture_retained_for_evidence_failure"] = True
                except Exception as error:
                    report["passed"] = False
                    report["retention_failure"] = failure_evidence(error)
                    report["fixture_retained_for_evidence_failure"] = True
            if retirement_confirmed and not report["fixture_retained_for_evidence_failure"]:
                try:
                    shutil.rmtree(root)
                except OSError as error:
                    report["passed"] = False
                    report["cleanup_failure"] = failure_evidence(error)
            elif not retirement_confirmed:
                report["fixture_retained_for_unverified_retirement"] = True
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
    parser.add_argument("--private-evidence", type=Path)
    parser.add_argument("--expected-dependency-digest")
    args = parser.parse_args()
    try:
        result = verify(
            args.python.absolute(),
            args.baseline_wheel.resolve(),
            args.candidate_wheel.resolve(),
            args.baseline_sha,
            args.candidate_sha,
            dependency_root=args.dependency_root.resolve(),
            private_evidence=args.private_evidence.absolute() if args.private_evidence else None,
            expected_dependency_digest=args.expected_dependency_digest,
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
