"""Collect exact malformed UTF-8 facts without inventing a cross-codec oracle."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import SAFE_ROUTE_NAMES, assert_privacy_safe, clear_proof_environment
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_evidence_files import atomic_exclusive
from scripts.native_slo_priority_launchers import LauncherSession, install_priority_launchers, registered_launcher
from scripts.native_slo_raw_process import run_registered_bytes
from scripts.native_slo_registered_surfaces_evidence import SurfaceAttempt, SurfaceEvidence


def raw_case(event: str) -> bytes:
    if event not in {"PreToolUse", "PostToolUse"}:
        raise ValueError("registered_utf8_event_invalid")
    # The octet is outside a JSON string. Some Python stdio profiles reject it
    # while others decode it before the JSON or bridge encoding boundary.
    return b'{"hook_event_name":"' + event.encode("ascii") + b'","tool_name":\xff}'


def _commitment(value: bytes) -> dict[str, object]:
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def _known(value: object, allowed: set[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "other"


def _shape(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return "invalid_utf8"
    if not text.strip():
        return "empty"
    try:
        response = json.loads(text)
    except ValueError:
        return "invalid_json"
    if not isinstance(response, dict):
        return "nonobject"
    if not response:
        return "empty_object"
    if _known(response.get("decision"), {"deny", "block"}) != "other":
        return "denial_shape"
    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    known_permission = _known(permission, {"deny", "ask", "allow"})
    if known_permission != "other":
        return {"deny": "denial_shape", "ask": "review_shape", "allow": "allow_shape"}[known_permission]
    return "other_object"


def _native_fact(evidence: Mapping[str, object]) -> dict[str, object]:
    native = evidence.get("native_result")
    if not isinstance(native, Mapping):
        return {"observed": False}
    return {
        "observed": True,
        "authority": _known(native.get("authority"), {"rust", "python"}) if "authority" in native else "not_present",
        "decision": _known(native.get("decision"), {"allow", "deny"}),
        "policy_action": _known(native.get("policy_action"), {"allow", "warn", "review", "block"}),
    }


def run_registered_utf8_observation(session: DaemonFixture, *, evidence_file: Path) -> dict[str, object]:
    """Separate untimed observation; the existing sixteen text cases are intact.

    The facts deliberately do not count as a passing malformed-input contract.
    Native results, wire-shape observations and Python codec outcomes differ.
    Actual platform observations must establish a reviewed expected profile.
    """
    observations: list[dict[str, object]] = []
    with SurfaceEvidence(evidence_file) as journal:
        launchers = install_priority_launchers(cast(LauncherSession, cast(object, session)))
        if len(launchers) != 4 or {(item.harness, item.event) for item in launchers} != {
            (harness, event) for harness in ("codex", "claude-code") for event in ("PreToolUse", "PostToolUse")
        }:
            raise RuntimeError("registered_utf8_registration_incomplete")
        for index, launcher in enumerate(launchers):
            data = raw_case(launcher.event)
            journal.offer(f"utf8/{launcher.harness}/{launcher.event}", launcher.registration_sha256)
            attempt = SurfaceAttempt(stage="registration")
            try:
                if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
                    raise RuntimeError("registered_utf8_registration_changed")
                environment = dict(os.environ)
                _ = clear_proof_environment(environment)
                configured = dict(launcher.environment)
                if clear_proof_environment(configured):
                    raise RuntimeError("registered_utf8_registration_override")
                environment.update(configured)
                environment["HOME"] = environment["USERPROFILE"] = str(session.root)
                if launcher.harness == "codex":
                    environment["CODEX_HOME"] = str(session.root / ".codex")
                attempt.stage = "setup"
                _ = session.control("case_before")
                metrics = session.daemon._server.hook_worker.metrics
                before = route_counts(metrics.snapshot())
                attempt.stage = "process"
                result = run_registered_bytes(launcher.argv, stdin=data, cwd=session.workspace, environment=environment)
                attempt.attempted_exit = result.returncode
                # Persist all exact captures before parsing, route or registration
                # assertions. Only these encrypted private files carry bytes.
                captured = {
                    "schema": "hol-guard.registered-utf8-captures.v1",
                    "stdin_base64": base64.b64encode(data).decode("ascii"),
                    "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
                    "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
                }
                atomic_exclusive(
                    evidence_file.with_name(f"{evidence_file.stem}-{index}-capture.json"),
                    json.dumps(captured, separators=(",", ":")).encode("ascii"),
                )
                attempt.stage = "readback_after"
                unchanged = registered_launcher(launcher.config_path, launcher.harness, launcher.event) == launcher
                after = route_counts(metrics.snapshot())
                attempt.stage = "witness"
                evidence = session.control("case_result")
                try:
                    route = witnessed_route(before, after)
                except RuntimeError:
                    route = "unclassified"
                attempt.route = route
                observation: dict[str, object] = {
                    "harness": launcher.harness,
                    "event": launcher.event,
                    "registration_unchanged": unchanged,
                    "stdin": _commitment(data),
                    "stdout": _commitment(result.stdout),
                    "stderr": _commitment(result.stderr),
                    "capture_identity": "exact_pipe_bytes",
                    "exit": result.returncode,
                    "observed_exit": result.observed_exit,
                    "timed_out": result.timed_out,
                    "containment_failed": result.containment_failed,
                    "capture_limit_exceeded": result.output_limit_exceeded,
                    "stdin_written": result.stdin_written,
                    "stdin_flushed": result.stdin_flushed,
                    "io_failed": result.io_failed,
                    "response_shape": _shape(result.stdout),
                    "route": route,
                    "routes_before": {name: before[name] for name in sorted(SAFE_ROUTE_NAMES)},
                    "routes_after": {name: after[name] for name in sorted(SAFE_ROUTE_NAMES)},
                    "native": _native_fact(evidence),
                }
                observations.append(observation)
                atomic_exclusive(
                    evidence_file.with_name(f"{evidence_file.stem}-{index}-facts.json"),
                    json.dumps(assert_privacy_safe(observation), separators=(",", ":")).encode("ascii"),
                )
                if result.containment_failed:
                    attempt.stage = "delivery"
                    raise RuntimeError("registered_utf8_containment_unconfirmed")
                attempt.stage = "complete"
                journal.finish("completed", attempt)
            except BaseException:
                journal.finish("failed", attempt)
                raise
    return assert_privacy_safe(
        {
            "schema": "hol-guard.registered-utf8-observation.v1",
            "collection_complete": len(observations) == 4,
            "observations": observations,
            "expected_delivery_profile": "not_qualified",
            "native_allow_claimed": False,
            "headline_timing_eligible": False,
            "passed": False,
            "qualification_complete": False,
        }
    )
