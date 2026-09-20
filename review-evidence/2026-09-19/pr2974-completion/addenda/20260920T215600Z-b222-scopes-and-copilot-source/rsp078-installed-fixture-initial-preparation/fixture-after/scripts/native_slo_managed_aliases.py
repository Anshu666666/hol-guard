"""Finite registered Cursor/Copilot delivery contracts, independent of renderers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from scripts.native_slo_registered_surfaces import (
    RegisteredSurface,
    _registered,
    read_registered_surfaces,
)
from scripts.native_slo_registered_surfaces_run import validate_surface_delivery
from scripts.native_slo_workloads import QualificationCase, build_cases, validate_native_result, validate_setup

PERMISSION_EVENTS = ("permissionRequest", "permissionRequestV2")
NORMAL_CASES = (
    ("cursor", "global", "cursor/beforeShellExecution/dangerous/small"),
    ("cursor", "global", "cursor/afterShellExecution/benign/1k"),
    ("copilot", "global", "copilot/preToolUse/dangerous/small"),
    ("copilot", "project", "copilot/postToolUse/benign/1k"),
)
DECLARED_LABELS = (
    *(scope + "/" + case_id for _, scope, case_id in NORMAL_CASES),
    *(
        f"{scope}/copilot/{event}/{kind}"
        for kind in ("permission_daemon", "permission_no_daemon")
        for scope in ("global", "project")
        for event in PERMISSION_EVENTS
    ),
    *(f"global/cursor/{event}/watch_no_daemon" for event in ("beforeShellExecution", "afterShellExecution")),
)
PERMISSION_MESSAGE = "HOL Guard could not complete the native hook decision safely."
PERMISSION_RESPONSE = {
    "behavior": "deny",
    "message": PERMISSION_MESSAGE,
    "interrupt": False,
    "reason_code": "native_hook_event_unavailable",
}


@dataclass(frozen=True, slots=True)
class ManagedCase:
    label: str
    harness: str
    event: str
    scope: str
    kind: str
    payload: Mapping[str, object]
    normal_case: QualificationCase | None = None


def daemon_cases(workspace: Path) -> tuple[ManagedCase, ...]:
    corpus = {case.case_id: case for case in build_cases(workspace)}
    result = []
    for harness, scope, case_id in NORMAL_CASES:
        case = corpus[case_id]
        if case.setup != "normal" or case.expected_route != "native_resident":
            raise RuntimeError("managed_alias_native_case_changed")
        result.append(ManagedCase(scope + "/" + case_id, harness, case.event, scope, "evaluated", case.payload, case))
    result.extend(permission_cases(workspace, kind="permission_daemon"))
    return tuple(result)


def permission_cases(workspace: Path, *, kind: str) -> tuple[ManagedCase, ...]:
    if kind not in {"permission_daemon", "permission_no_daemon"}:
        raise ValueError("managed_alias_permission_kind")
    return tuple(
        ManagedCase(
            f"{scope}/copilot/{event}/{kind}",
            "copilot",
            event,
            scope,
            kind,
            {"hookName": event, "toolName": "Bash", "toolInput": {"command": "pwd"}, "cwd": str(workspace)},
        )
        for scope in ("global", "project")
        for event in PERMISSION_EVENTS
    )


def watch_cases(workspace: Path) -> tuple[ManagedCase, ...]:
    return tuple(
        ManagedCase(
            f"global/cursor/{event}/watch_no_daemon",
            "cursor",
            event,
            "global",
            "watch_no_daemon",
            {"hook_event_name": event, "command": "rm -rf /", "cwd": str(workspace), "output": "synthetic output"},
        )
        for event in ("beforeShellExecution", "afterShellExecution")
    )


def registration(context: HarnessContext, case: ManagedCase) -> RegisteredSurface:
    if case.harness == "copilot" and case.event in PERMISSION_EVENTS:
        path = (
            CopilotHarnessAdapter._config_path(context)
            if case.scope == "global"
            else CopilotHarnessAdapter._hook_path(context)
        )
        if path is None:
            raise RuntimeError("managed_alias_project_registration_missing")
        return _registered(context, case.harness, case.event, case.scope, path)
    found = [
        surface
        for surface in read_registered_surfaces(context, case.harness)
        if (surface.event, surface.scope) == (case.event, case.scope)
    ]
    if len(found) != 1:
        raise RuntimeError("managed_alias_registration_ambiguous")
    return found[0]


def validate_delivery(case: ManagedCase, response: object, exit_code: object, stderr: str) -> None:
    if not isinstance(response, dict) or type(exit_code) is not int or stderr:
        raise AssertionError("managed_alias_delivery_shape")
    if case.kind == "evaluated":
        if case.normal_case is None:
            raise AssertionError("managed_alias_original_oracle_missing")
        validate_surface_delivery(case.normal_case, response, exit_code, stderr)
    elif case.kind in {"permission_daemon", "permission_no_daemon"}:
        if response != PERMISSION_RESPONSE or exit_code != 0:
            raise AssertionError("managed_alias_permission_handoff")
    elif case.kind == "watch_no_daemon":
        expected = {} if case.event == "afterShellExecution" else {"permission": "allow"}
        if response != expected or exit_code != 0:
            raise AssertionError("managed_alias_watch_delivery")
    else:
        raise AssertionError("managed_alias_kind_unknown")


def validate_daemon_evidence(case: ManagedCase, evidence: Mapping[str, object], route: str) -> None:
    setup = evidence.get("setup")
    if (
        not isinstance(setup, dict)
        or setup.get("fault_scope") != "none"
        or setup.get("python_oracle_disabled") is not True
    ):
        raise AssertionError("managed_alias_daemon_setup")
    if any(
        type(evidence.get(key)) is not int or evidence.get(key) != 1
        for key in ("native_call_count", "native_completed_call_count")
    ):
        raise AssertionError("managed_alias_edge_call_count")
    native_result = evidence.get("native_result")
    if case.kind == "evaluated":
        if case.normal_case is None or not isinstance(native_result, dict) or route != "native_resident":
            raise AssertionError("managed_alias_native_result_missing")
        validate_setup(case.normal_case, setup)
        validate_native_result(case.normal_case, native_result)
    elif case.kind == "permission_daemon":
        if route != "native_fail_safe" or native_result is not None:
            raise AssertionError("managed_alias_permission_evaluation_invented")
        if setup.get("policy_ack_current") is not True or setup.get("effective_policy_allow") is not True:
            raise AssertionError("managed_alias_permission_authority_setup")
    else:
        raise AssertionError("managed_alias_no_daemon_witness_forbidden")


def no_daemon_state(guard_home: Path) -> dict[str, bool]:
    # The fixture never starts a daemon for this fresh private Guard home.
    # These are the exact endpoint inputs consumed by the registered bridge.
    names = ("daemon-state.json", "daemon-auth-token")
    state = {name: (guard_home / name).exists() or (guard_home / name).is_symlink() for name in names}
    if any(state.values()):
        raise RuntimeError("managed_alias_daemon_absence_not_proven")
    return state


def payload_digest(payload: Mapping[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > 256 * 1024:
        raise ValueError("managed_alias_payload_bound")
    return hashlib.sha256(raw).hexdigest()
