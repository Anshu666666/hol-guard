"""Explicit installed-wheel experiment; never selects a production launcher."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard import native_runtime  # noqa: E402
from scripts.ci.native_claude_pilot_measure import measure  # noqa: E402
from scripts.ci.native_claude_pilot_registration import ARMS, EVENTS, PilotRegistration  # noqa: E402
from scripts.native_slo_artifact import (  # noqa: E402
    assert_installed_import_origin,
    installed_package_digest,
    wheel_package_digest,
)
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_daemon_fixture import DaemonFixture  # noqa: E402
from scripts.native_slo_dependency_identity import dependency_versions_digest  # noqa: E402
from scripts.native_slo_evidence_files import _new_directory, atomic_exclusive  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_pair_io import write_public  # noqa: E402


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def _sha256(path: Path, limit: int = 256 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            count += len(chunk)
            _require(count <= limit, "claude_pilot_artifact_limit")
            digest.update(chunk)
    return digest.hexdigest()


def installed_identity(wheel: Path, build_sha: str) -> tuple[Path, dict[str, object]]:
    _require(re.fullmatch(r"[0-9a-f]{40}", build_sha) is not None, "claude_pilot_build_invalid")
    _require(not Path(sys.prefix).resolve().is_relative_to(_ROOT), "claude_pilot_environment_inside_checkout")
    distribution = importlib.metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    expected = wheel_package_digest(wheel)
    _require(installed_package_digest(distribution) == expected, "claude_pilot_installed_bytes_mismatch")
    status = native_runtime._inspect_native_runtime_status(allow_attestation=False)
    _require(status.mode == "auto" and status.available and status.compatible, "claude_pilot_native_unavailable")
    identity, capabilities = status.identity, status.capabilities
    _require(identity is not None and capabilities is not None, "claude_pilot_identity_missing")
    assert identity is not None and capabilities is not None
    _require("claude-launcher-pilot-v1" in capabilities.features, "claude_pilot_feature_missing")
    _require(capabilities.build_sha == build_sha, "claude_pilot_build_mismatch")
    _require(
        identity.path == native_runtime._bundled_runtime_candidate().resolve(strict=True), "claude_pilot_not_bundled"
    )
    helpers = sorted((_ROOT / "scripts").rglob("*.py"))
    _require(len(helpers) <= 1024, "claude_pilot_helper_inventory_limit")
    helper_hash = hashlib.sha256()
    for helper in helpers:
        helper_hash.update(str(helper.relative_to(_ROOT)).replace("\\", "/").encode() + b"\0")
        helper_hash.update(bytes.fromhex(_sha256(helper, 2 * 1024 * 1024)))
    return identity.path, {
        "wheel_sha256": _sha256(wheel),
        "installed_package_sha256": expected,
        "runtime_sha256": identity.sha256,
        "build_sha": build_sha,
        "package_version": distribution.version,
        "target": capabilities.target,
        "rule_digest": capabilities.rule_digest,
        "helper_digest": helper_hash.hexdigest(),
        "interpreter_sha256": _sha256(Path(sys.executable)),
        "dependency_versions_digest": dependency_versions_digest(),
    }


def run(*, wheel: Path, build_sha: str, iterations: int, run_index: int, output: Path) -> dict[str, object]:
    clear_proof_environment()
    os.environ.pop("PYTHONPATH", None)
    os.environ.pop("PYTHONHOME", None)
    report: dict[str, Any] = {
        "schema": "hol-guard.installed-claude-pilot-experiment.v1",
        "contracts_passed": False,
        "qualification_complete": False,
        "production_selected": False,
        "default_registration_changed": False,
        "selection": "explicit_private_fixture_only",
        "baseline": "optimized_python_same_wheel",
        "headline_frozen_baseline_replaced": False,
        "process_startup_included": True,
        "state": "fresh_launcher_prepared_resident",
        "concurrency": 1,
        "runs_in_this_report": 1,
        "run_index": run_index,
        "iterations_per_arm_event": iterations,
        "stage": "installed_identity",
        "progress": {},
        "remaining": [
            "c16",
            "recovery",
            "review_continuation",
            "watch",
            "source_references",
            "stdio_faults",
            "frozen_sidecars",
        ],
    }
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    samples = output / "private_samples"
    # Use the existing Windows private-directory/DACL path as well as POSIX
    # owner permissions before journals open files in the new directory.
    _new_directory(samples)
    try:
        runtime, identity = installed_identity(wheel, build_sha)
        report["identity"] = identity
        report["stage"] = "daemon_startup"
        with DaemonFixture(runtime, policy="normal") as session:
            report["readiness_ms"] = session.readiness_ms
            report["stage"] = "registration_preparation"
            registration = PilotRegistration(session)
            try:
                report["registrations"] = {}
                for arm in ARMS:
                    for event in EVENTS:
                        selected = registration.activate(arm, event)
                        report["registrations"][f"{arm}.{event}"] = {
                            "registration_sha256": selected.registration_sha256,
                            "argv_sha256": hashlib.sha256(json.dumps(selected.argv).encode()).hexdigest(),
                        }
                report["stage"] = "measurement"
                report["latency"] = measure(
                    session,
                    registration,
                    iterations=iterations,
                    run_index=run_index,
                    private_samples=samples,
                    progress=report["progress"],
                )
            except Exception as error:
                report["measurement_failure"] = failure_evidence(error)
                raise
            finally:
                try:
                    registration.restore()
                except Exception as error:
                    report["restoration_failure"] = failure_evidence(error)
                    raise
                report["fixture_registration_restored"] = True
        report["stage"] = "artifact_revalidation"
        _, final_identity = installed_identity(wheel, build_sha)
        _require(final_identity == identity, "claude_pilot_artifact_changed")
        report["contracts_passed"] = True
        report["stage"] = "complete"
    except Exception as error:
        report["failure"] = failure_evidence(error)
    report = assert_privacy_safe(report)
    # This fixed aggregate never contains argv, contexts, hook bodies or output.
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    write_public(output / "summary.json", report, limit=64 * 1024)
    # Include the manifest in encrypted retention even for a setup failure.
    atomic_exclusive(samples / "attempt-summary.json", encoded)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dormant-pilot", action="store_true", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--iterations", type=int, default=20, choices=range(1, 2001))
    parser.add_argument("--run-index", type=int, default=0, choices=range(5))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(
        wheel=args.wheel.resolve(strict=True),
        build_sha=args.build_sha,
        iterations=args.iterations,
        run_index=args.run_index,
        output=args.output.resolve(),
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["contracts_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
