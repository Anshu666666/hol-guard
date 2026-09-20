"""Bounded installed registered Cursor/Copilot correctness; no performance claim."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ci.native_runtime import probe_installed_pi_runtime as installed
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest, wheel_package_digest
from scripts.native_slo_contract import proof_environment_violations
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_managed_run import run_daemon_cases, run_no_daemon_cases, validate_population


def admit_installed(wheel: Path, source_sha: str) -> tuple[dict[str, Any], Any, Any]:
    if os.name == "nt" or not sys.flags.isolated or proof_environment_violations():
        raise RuntimeError("installed_managed_invocation_not_admitted")
    if len(source_sha) != 40 or any(char not in "0123456789abcdef" for char in source_sha):
        raise ValueError("installed_managed_source_sha")
    installed._installed_package_path(Path(__file__).resolve().parents[2])
    distribution = importlib.metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    package_before = installed_package_digest(distribution)
    if package_before != wheel_package_digest(wheel):
        raise RuntimeError("installed_managed_wheel_content_mismatch")
    status, identity, capabilities = installed._probe_native_identity()
    if capabilities.build_sha != source_sha or status.mode != "auto":
        raise RuntimeError("installed_managed_native_identity_mismatch")
    return (
        {
            "build_sha": source_sha,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "installed_package_sha256": package_before,
            "runtime_sha256": identity.sha256,
            "package_version": distribution.version,
            "target": capabilities.target,
            "rule_digest": capabilities.rule_digest,
            "runtime_version": capabilities.runtime_version,
            "mode": status.mode,
            "python_version": sys.version.split()[0],
            "python_prefix": sys.prefix,
        },
        distribution,
        identity,
    )


def verify(wheel: Path, source_sha: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.installed-managed-aliases.v1",
        "passed": False,
        "declared_cases": 14,
        "rows": [],
        "platform_scope": "POSIX",
        "performance_qualified": False,
        "external_host_application_executed": False,
        "native_approval_consume_qualified": False,
    }
    try:
        report["identity"], distribution, identity = admit_installed(wheel, source_sha)
        package_before = report["identity"]["installed_package_sha256"]
        run_daemon_cases(identity.path, report)
        run_no_daemon_cases(report, watch=False)
        run_no_daemon_cases(report, watch=True)
        validate_population(report)
        package_after = installed_package_digest(distribution)
        report["installed_package_after_sha256"] = package_after
        if package_after != package_before:
            raise RuntimeError("installed_managed_package_changed")
        report["passed"] = True
    except Exception as error:
        if report["rows"] and report["rows"][-1].get("status") == "offered":
            report["rows"][-1]["status"] = "failed"
        report["failure"] = failure_evidence(error)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("installed_managed_output_exists")
    report = verify(args.wheel.resolve(strict=True), args.source_sha)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
