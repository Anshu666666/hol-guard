"""Frozen delivery cases through the exact installed priority registrations.

The independent daemon corpus supplies expected semantic outcomes. Codex's
documented stdout field projection is frozen here, separately from production
renderers. Native results and daemon route witnesses are checked independently
of stdout, so a launcher availability response cannot count as evaluated allow.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment
from scripts.native_slo_corpus_run import _IMPLEMENTED_SETUPS
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_priority_launchers import (
    LauncherSession,
    RegisteredLauncher,
    install_priority_launchers,
    registered_launcher,
)
from scripts.native_slo_workloads import (
    ExpectedResponse,
    QualificationCase,
    build_cases,
    validate_case,
    validate_native_result,
    validate_setup,
)

_SUPPORTED = frozenset(
    (harness, event) for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
)
_STDOUT_LIMIT = 2 * 1024 * 1024


def installed_expectation(case: QualificationCase) -> QualificationCase:
    """Freeze the externally documented Codex field filter, not its renderer."""
    if (case.harness, case.event) not in _SUPPORTED or not case.surface.startswith("installed_"):
        raise ValueError("launcher corpus case is not an installed registration")
    if case.harness != "codex":
        return replace(case, boundary="registered_launcher")
    top = {"continue", "stopReason", "suppressOutput", "systemMessage", "hookSpecificOutput"}
    if case.event == "PostToolUse":
        top.update({"decision", "reason"})
    post_specific = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}

    def retained(path: str) -> bool:
        parts = path.split(".")
        return parts[0] in top and not (
            case.event == "PostToolUse"
            and len(parts) > 1
            and parts[0] == "hookSpecificOutput"
            and parts[1] not in post_specific
        )

    return replace(
        case,
        boundary="registered_launcher",
        expected=ExpectedResponse(
            case.expected.decision,
            case.expected.model_action,
            case.expected.reason_class,
            {key: value for key, value in case.expected.fields.items() if retained(key)},
            tuple(key for key in case.expected.nonempty_fields if retained(key)),
            case.expected.exact_empty,
        ),
    )


def _run_registered(
    session: DaemonFixture, launcher: RegisteredLauncher, case: QualificationCase
) -> tuple[Mapping[str, object], float]:
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("launcher corpus registration changed")
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.update(launcher.environment)
    environment["HOME"] = str(session.root)
    environment["USERPROFILE"] = str(session.root)
    if launcher.harness == "codex":
        environment["CODEX_HOME"] = str(session.root / ".codex")
    payload = dict(case.payload)
    payload["tool_use_id"] = "installed-corpus-" + hashlib.sha256(case.case_id.encode()).hexdigest()[:24]
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    started = time.perf_counter()
    result = run_isolated_hook_process(
        launcher.argv,
        input_text=encoded,
        cwd=session.workspace,
        environment=environment,
        timeout_seconds=10,
        output_limit=_STDOUT_LIMIT,
    )
    elapsed = (time.perf_counter() - started) * 1000
    if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
        raise RuntimeError("launcher corpus process contract failed")
    try:
        response: object = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("launcher corpus stdout is not JSON") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("launcher corpus stdout is not an object")
    return cast(Mapping[str, object], response), elapsed


def _selected(case: QualificationCase) -> bool:
    return (
        (case.harness, case.event) in _SUPPORTED
        and case.surface.startswith("installed_")
        and case.expected_http_status == 200
    )


def validate_installed_response(case: QualificationCase, response: Mapping[str, object], route: str) -> None:
    if case.harness == "codex":
        allowed = {"continue", "stopReason", "suppressOutput", "systemMessage", "hookSpecificOutput"}
        if case.event == "PostToolUse":
            allowed.update({"decision", "reason"})
        specific = response.get("hookSpecificOutput")
        specific_allowed = {"hookEventName", "permissionDecision", "permissionDecisionReason"}
        if case.event == "PostToolUse":
            specific_allowed = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
        if not set(response) <= allowed or (isinstance(specific, Mapping) and not set(specific) <= specific_allowed):
            raise RuntimeError("launcher corpus Codex stdout schema mismatch")
    validate_case(case, response, route)


def run_registered_contract_corpus(runtime: Path, *, evidence_file: Path) -> dict[str, object]:
    """Run actual registrations across sizes, source refs, posture and faults.

    Browser approval continuation is a separately witnessed scenario. A missing
    scenario remains in the returned coverage obligations, never a skipped pass.
    """
    evidence_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    validated: list[str] = []
    remaining: set[str] = set()
    counts = {name: Counter() for name in ("harness", "event", "setup", "size", "route", "delivery", "representation")}
    with evidence_file.open("w", encoding="utf-8") as evidence:
        evidence_file.chmod(0o600)
        for setup in sorted(_IMPLEMENTED_SETUPS):
            with DaemonFixture(runtime, setup=setup) as session:
                launchers = {
                    (launcher.harness, launcher.event): launcher
                    for launcher in install_priority_launchers(cast(LauncherSession, cast(object, session)))
                }
                metrics = session.daemon._server.hook_worker.metrics
                for original in build_cases(session.workspace):
                    if original.setup != setup or not _selected(original):
                        continue
                    if original.expected.reason_class == "review":
                        remaining.add("browser_approval_continuation")
                        continue
                    case = installed_expectation(original)
                    case_digest = hashlib.sha256(case.case_id.encode()).hexdigest()
                    attempt: dict[str, object] = {
                        "case_digest": case_digest,
                        "harness": case.harness,
                        "event": case.event,
                        "setup": case.setup,
                        "status": "started",
                    }
                    evidence.write(json.dumps(attempt, separators=(",", ":")) + "\n")
                    evidence.flush()
                    try:
                        session.control("case_before")
                        before = route_counts(metrics.snapshot())
                        response, elapsed = _run_registered(session, launchers[case.harness, case.event], case)
                        after = route_counts(
                            metrics.snapshot()
                            if case.expected_route == "engine_bypassed"
                            else wait_for_route_corpus(metrics, expected=sum(before.values()) + 1)
                        )
                        route = witnessed_route(before, after)
                        result = session.control("case_result")
                        setup_evidence = result.get("setup")
                        native_evidence = result.get("native_result")
                        if not isinstance(setup_evidence, Mapping) or (
                            native_evidence is not None and not isinstance(native_evidence, Mapping)
                        ):
                            raise RuntimeError("launcher corpus fault witness is malformed")
                        validate_setup(case, setup_evidence)
                        validate_installed_response(case, response, route)
                        validate_native_result(case, native_evidence)
                    except Exception:
                        evidence.write(json.dumps({**attempt, "status": "failed"}, separators=(",", ":")) + "\n")
                        evidence.flush()
                        raise
                    evidence.write(
                        json.dumps({**attempt, "status": "validated", "elapsed_ms": elapsed}, separators=(",", ":"))
                        + "\n"
                    )
                    evidence.flush()
                    validated.append(case_digest)
                    for name, value in (
                        ("harness", case.harness),
                        ("event", case.event),
                        ("setup", case.setup),
                        ("size", case.size_class),
                        ("route", route),
                        ("delivery", case.expected.reason_class),
                        ("representation", case.payload_kind),
                    ):
                        counts[name][value] += 1
    if not validated:
        raise RuntimeError("installed launcher corpus was empty")
    return assert_privacy_safe(
        {
            "schema": "hol-guard.registered-launcher-corpus.v1",
            "boundary": "INSTALLED_LAUNCHER",
            "validated_cases": len(validated),
            "validated_digest": hashlib.sha256(json.dumps(sorted(validated)).encode()).hexdigest(),
            "coverage": {name: dict(count) for name, count in counts.items()},
            "configuration": "registered_argv_and_env",
            "stdout_and_exit_checked": True,
            "native_and_delivered_checked_independently": True,
            "implemented_scope_passed": True,
            "latency_claim": "semantic_preflight_no_tail_claim",
            "remaining": sorted(remaining | {"nonpriority_registered_launchers", "malformed_launcher_input"}),
            "qualification_complete": False,
        }
    )
