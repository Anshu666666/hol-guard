"""Run ten registered Pi/OMP callbacks against an exact installed native wheel.

Invoke with the wheel-installed interpreter and -I. This is functional evidence,
not a host-application launch, latency population, Windows qualification or release.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ci.native_runtime import probe_installed_pi_output as existing
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest, wheel_package_digest
from scripts.native_slo_contract import proof_environment_violations
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_pi_receipts import PiReceipts
from scripts.native_slo_pi_sources import (
    cases,
    installed_registration,
    validate_delivery,
    validate_export_privacy,
    validate_reference_join,
)


def read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise RuntimeError("installed_pi_evidence_bound")
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) > 10 or not all(isinstance(row, dict) for row in rows):
        raise RuntimeError("installed_pi_evidence_shape")
    return rows


def admit_installed(wheel: Path, source_sha: str) -> tuple[dict[str, object], Any, Any]:
    if not sys.flags.isolated or proof_environment_violations():
        raise RuntimeError("installed_pi_invocation_not_admitted")
    if len(source_sha) != 40 or any(char not in "0123456789abcdef" for char in source_sha):
        raise ValueError("installed_pi_source_sha_invalid")
    distribution = importlib.metadata.distribution("hol-guard")
    existing._installed_package_path(Path(__file__).resolve().parents[2])
    assert_installed_import_origin(distribution)
    package_digest = installed_package_digest(distribution)
    if package_digest != wheel_package_digest(wheel):
        raise RuntimeError("installed_pi_wheel_content_mismatch")
    status, identity, capabilities = existing._probe_native_identity()
    if capabilities.build_sha != source_sha:
        raise RuntimeError("installed_pi_native_source_mismatch")
    digest = hashlib.sha256()
    with wheel.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return (
        {
            "wheel_sha256": digest.hexdigest(),
            "installed_package_sha256": package_digest,
            "package_version": distribution.version,
            "build_sha": source_sha,
            "target": capabilities.target,
            "runtime_sha256": identity.sha256,
            "rule_digest": capabilities.rule_digest,
            "runtime_version": capabilities.runtime_version,
            "mode": status.mode,
        },
        distribution,
        identity,
    )


def verify(wheel: Path, source_sha: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.installed-pi-source-correctness.v1",
        "passed": False,
        "declared_calls": 10,
        "offered_harnesses": [],
        "registrations": [],
        "callback_rows": [],
        "native_approval_consume_qualified": False,
        "performance_qualified": False,
        "external_host_application_executed": False,
        "platform_scope": "POSIX",
    }
    daemon = witness = identity = root = None
    startup_unsafe = process_unsafe = False
    cleanup_failures: list[dict[str, object]] = []
    try:
        if os.name == "nt":
            raise RuntimeError("installed_pi_platform_unsupported")
        report["identity"], distribution, identity = admit_installed(wheel, source_sha)
        node, python = existing._node_command(), existing._probe_python_path()
        root = Path(tempfile.mkdtemp(prefix="hg-pisrc-", dir=existing._short_temp_parent())).resolve()
        home, guard_home, workspace = (root / name for name in ("home", "guard-home", "workspace"))
        for directory in (home, guard_home, workspace):
            directory.mkdir(mode=0o700)
        context = HarnessContext(home, workspace, guard_home)
        declared = {harness: cases(workspace, harness) for harness in ("pi", "omp")}
        registrations = {}
        for harness in declared:
            extension, registration = installed_registration(context, harness)
            registrations[harness] = extension
            report["registrations"].append(registration)
        daemon = existing._start_installed_daemon(
            guard_home=guard_home, home=home, workspace=workspace, identity=identity
        )
        existing._prepare_installed_daemon_workspace(daemon, workspace)
        witness = PiReceipts(daemon, declared["pi"] + declared["omp"]).__enter__()
        for harness, cohort in declared.items():
            inputs, evidence = root / (harness + ".json"), root / (harness + ".jsonl")
            inputs.write_text(json.dumps([case.node_input() for case in cohort]), encoding="utf-8")
            inputs.chmod(0o600)
            report["offered_harnesses"].append(harness)
            result = run_isolated_hook_process(
                (
                    *node,
                    str(Path(__file__).resolve().parents[1] / "native_slo_pi_sources.mjs"),
                    str(registrations[harness]),
                    str(inputs),
                    str(workspace),
                    str(evidence),
                ),
                input_text="",
                cwd=workspace,
                environment=existing._isolated_env(home=home, python_path=python),
                timeout_seconds=60,
                output_limit=256 * 1024,
            )
            process_unsafe = result.containment_failed
            report.setdefault("processes", []).append(
                {
                    "harness": harness,
                    "returncode": result.returncode,
                    "timed_out": result.timed_out,
                    "containment_failed": result.containment_failed,
                    "output_limit_exceeded": result.output_limit_exceeded,
                    "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
                }
            )
            rows = read_rows(evidence)
            report["callback_rows"].extend(rows)
            if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
                raise RuntimeError("installed_pi_process_failed")
            expected_labels = [case.label for case in cohort]
            if [row.get("id") for row in rows] != [label for label in expected_labels for _ in range(2)]:
                raise RuntimeError("installed_pi_callback_membership")
            for case, row in zip(cohort, rows[1::2], strict=True):
                validate_delivery(case, row)
        report["native_route_metrics"] = existing._wait_for_native_route_metrics(daemon, 10)
        report["receipts"] = witness.reconcile()
        validate_reference_join(report["callback_rows"], report["receipts"])
        report["http_native_reference_join"] = True
        if report["receipts"]["complete"] is not True:
            raise RuntimeError("installed_pi_receipts_incomplete")
        assert_installed_import_origin(distribution)
        if installed_package_digest(distribution) != report["identity"]["installed_package_sha256"]:
            raise RuntimeError("installed_pi_package_changed")
        report["passed"] = True
    except Exception as error:
        startup_unsafe = isinstance(error, existing.ProbeCleanupUnsafeError)
        report["failure"] = failure_evidence(error)
    finally:
        if witness is not None:
            try:
                if "receipts" not in report:
                    report["receipts"] = witness.reconcile()
            except Exception as error:
                cleanup_failures.append({"stage": "receipt_readback", **failure_evidence(error)})
            finally:
                try:
                    witness.close()
                except Exception as error:
                    cleanup_failures.append({"stage": "observer_restore", **failure_evidence(error)})
        contained = not startup_unsafe and not process_unsafe
        if daemon is not None:
            try:
                existing._cleanup_installed_daemon(daemon)
            except Exception as error:
                contained = False
                cleanup_failures.append({"stage": "daemon_cleanup", **failure_evidence(error)})
        if identity is not None and root is not None:
            try:
                existing._cleanup_native(identity, root / "guard-home")
            except Exception as error:
                contained = False
                cleanup_failures.append({"stage": "native_cleanup", **failure_evidence(error)})
        if root is not None and contained:
            try:
                shutil.rmtree(root)
            except OSError as error:
                cleanup_failures.append({"stage": "private_root_cleanup", **failure_evidence(error)})
        report["cleanup"] = {"contained": contained, "failures": cleanup_failures}
        report["passed"] = report["passed"] and contained and not cleanup_failures
    try:
        report["export_privacy"] = validate_export_privacy(report, root)
    except Exception as error:
        # Never publish a rejected raw export. Preserve its identity and explicit
        # failure; the normal receipt proof is not filtered or silently truncated.
        report = {
            "schema": "hol-guard.installed-pi-source-correctness.v1",
            "passed": False,
            "export_withheld": True,
            "original_report_sha256": hashlib.sha256(
                json.dumps(report, sort_keys=True, ensure_ascii=True).encode()
            ).hexdigest(),
            "failure": failure_evidence(error),
            "qualification_complete": False,
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.wheel.resolve(), args.source_sha)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(json.dumps({"passed": report["passed"], "declared_calls": report.get("declared_calls")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
