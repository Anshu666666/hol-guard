"""Execute fourteen exact managed registrations; no timing qualification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import clear_proof_environment
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_managed_aliases import (
    DECLARED_LABELS,
    ManagedCase,
    daemon_cases,
    no_daemon_state,
    payload_digest,
    permission_cases,
    registration,
    validate_daemon_evidence,
    validate_delivery,
    watch_cases,
)
from scripts.native_slo_registered_surfaces import install_registered_surface


def invoke(context: HarnessContext, case: ManagedCase, row: dict[str, Any]) -> dict[str, object]:
    surface = registration(context, case)
    encoded = json.dumps(case.payload, separators=(",", ":"), ensure_ascii=True)
    row.update(
        stage="registered",
        registration_sha256=surface.registration_sha256,
        registered_argv_sha256=hashlib.sha256(json.dumps(surface.argv).encode()).hexdigest(),
        registered_executable_sha256=hashlib.sha256(Path(surface.argv[0]).read_bytes()).hexdigest(),
        artifact_sha256=dict(surface.artifact_sha256),
        input_sha256=payload_digest(case.payload),
    )
    environment = dict(os.environ)
    clear_proof_environment(environment)
    for name in ("PYTHONPATH", "PYTHONHOME", "HOL_GUARD_CLINE_CANARY"):
        environment.pop(name, None)
    configured = dict(surface.environment)
    if clear_proof_environment(configured):
        raise RuntimeError("managed_alias_registered_override")
    environment.update(configured)
    environment.update(HOME=str(context.home_dir), USERPROFILE=str(context.home_dir))
    # Product deadlines remain in the generated worker/bridge. This outer
    # containment ceiling includes process startup and retirement, not a new
    # permission-evaluation budget. Copilot's original internal limit is 25s.
    timeout = 10.0 if case.harness == "cursor" else 30.0
    row.update(stage="process", outer_containment_seconds=timeout)
    result = run_isolated_hook_process(
        surface.argv,
        input_text=encoded,
        cwd=surface.cwd,
        environment=environment,
        timeout_seconds=timeout,
        output_limit=2 * 1024 * 1024,
    )
    row.update(
        returncode=result.returncode,
        timed_out=result.timed_out,
        containment_failed=result.containment_failed,
        output_limit_exceeded=result.output_limit_exceeded,
        stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest(),
    )
    if result.timed_out or result.containment_failed or result.output_limit_exceeded or result.returncode is None:
        raise RuntimeError("managed_alias_process_failed")
    row["stage"] = "delivery"
    response = json.loads(result.stdout)
    validate_delivery(case, response, result.returncode, result.stderr)
    row["delivery"] = response
    if registration(context, case) != surface:
        raise RuntimeError("managed_alias_registration_changed")
    row["registration_unchanged"] = True
    return response


def _offer(report: dict[str, Any], case: ManagedCase) -> dict[str, Any]:
    row = {
        "label": case.label,
        "harness": case.harness,
        "event": case.event,
        "scope": case.scope,
        "kind": case.kind,
        "status": "offered",
        "stage": "setup",
        "native_evaluation": False,
    }
    report["rows"].append(row)
    return row


def run_daemon_cases(runtime: Path, report: dict[str, Any]) -> None:
    with DaemonFixture(runtime, setup="normal") as session:
        context = HarnessContext(session.root, session.workspace, session.guard_home)
        for harness in ("cursor", "copilot"):
            install_registered_surface(context, harness)
        for case in daemon_cases(session.workspace):
            row = _offer(report, case)
            session.control("case_before")
            metrics = session.daemon._server.hook_worker.metrics
            before = route_counts(metrics.snapshot())
            invoke(context, case, row)
            after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
            route = witnessed_route(before, after)
            evidence = session.control("case_result")
            row.update(stage="native_witness", route=route, routes_before=before, routes_after=after, evidence=evidence)
            validate_daemon_evidence(case, evidence, route)
            row.update(status="completed", stage="complete", native_evaluation=case.kind == "evaluated")
        if not session.stop_resident():
            raise RuntimeError("managed_alias_native_retirement_failed")
    report["daemon_cleanup_contained"] = True


def run_no_daemon_cases(report: dict[str, Any], *, watch: bool) -> None:
    root = Path(tempfile.mkdtemp(prefix="hg-managed-absent-")).resolve()
    home, workspace, guard_home = (root / name for name in ("home", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir(mode=0o700)
    context = HarnessContext(home, workspace, guard_home)
    config = (
        'mode = "observe"\nprotection_posture = "watch"\nwatch_auto_revert_hours = 0\n'
        if watch
        else 'mode = "enforce"\nprotection_posture = "protected"\n'
    ) + "desktop_notifications = false\n"
    (guard_home / "config.toml").write_text(config, encoding="utf-8")
    (guard_home / "config.toml").chmod(0o600)
    cohort = watch_cases(workspace) if watch else permission_cases(workspace, kind="permission_no_daemon")
    contained = True
    try:
        install_registered_surface(context, "cursor" if watch else "copilot")
        for case in cohort:
            row = _offer(report, case)
            row["daemon_endpoint_before"] = no_daemon_state(guard_home)
            row["posture"] = "watch" if watch else "protected"
            try:
                invoke(context, case, row)
            finally:
                contained = contained and row.get("containment_failed") is not True
            row["daemon_endpoint_after"] = no_daemon_state(guard_home)
            row.update(
                status="completed",
                stage="complete",
                native_evaluation=False,
                absence_scope="fresh_owned_home_no_daemon_started_endpoint_files_absent",
            )
    finally:
        # An uncontained child may still own private files: do not erase them.
        if contained:
            shutil.rmtree(root)
        report["no_daemon_cleanup_contained"] = report.get("no_daemon_cleanup_contained", True) and contained


def validate_population(report: dict[str, Any]) -> None:
    rows = report.get("rows")
    if not isinstance(rows, list) or tuple(row.get("label") for row in rows) != DECLARED_LABELS:
        raise AssertionError("managed_alias_population")
    expected = {"evaluated": 4, "permission_daemon": 4, "permission_no_daemon": 4, "watch_no_daemon": 2}
    if {kind: sum(row.get("kind") == kind for row in rows) for kind in expected} != expected:
        raise AssertionError("managed_alias_population_kinds")
    if any(row.get("status") != "completed" or row.get("registration_unchanged") is not True for row in rows):
        raise AssertionError("managed_alias_incomplete")
    if any(row.get("native_evaluation") is not (row.get("kind") == "evaluated") for row in rows):
        raise AssertionError("managed_alias_native_evaluation_count")
    if report.get("daemon_cleanup_contained") is not True or report.get("no_daemon_cleanup_contained") is not True:
        raise AssertionError("managed_alias_cleanup_incomplete")
