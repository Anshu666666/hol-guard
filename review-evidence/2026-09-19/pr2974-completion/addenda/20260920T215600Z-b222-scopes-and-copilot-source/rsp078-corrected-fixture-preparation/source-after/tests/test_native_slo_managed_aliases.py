"""Finite registered alias oracle controls; modeled edges are not installed runs."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts import native_slo_managed_run as runner
from scripts.native_slo_contract import clear_proof_environment
from scripts.native_slo_managed_aliases import (
    PERMISSION_RESPONSE,
    daemon_cases,
    no_daemon_state,
    payload_digest,
    permission_cases,
    registration,
    validate_daemon_evidence,
    validate_delivery,
    watch_cases,
)
from scripts.native_slo_managed_run import validate_population
from scripts.native_slo_registered_surfaces import install_registered_surface
from scripts.native_slo_registered_surfaces_run import delivery_expectation


def test_population_preserves_original_normal_cases_and_all_managed_permission_slots(tmp_path: Path) -> None:
    cases = daemon_cases(tmp_path) + permission_cases(tmp_path, kind="permission_no_daemon") + watch_cases(tmp_path)
    assert len(cases) == len({case.label for case in cases}) == 14
    assert [(case.harness, case.event, case.scope) for case in cases[:4]] == [
        ("cursor", "beforeShellExecution", "global"),
        ("cursor", "afterShellExecution", "global"),
        ("copilot", "preToolUse", "global"),
        ("copilot", "postToolUse", "project"),
    ]
    for kind in ("permission_daemon", "permission_no_daemon"):
        assert {(case.event, case.scope) for case in cases if case.kind == kind} == {
            (event, scope) for event in ("permissionRequest", "permissionRequestV2") for scope in ("global", "project")
        }
    assert len({payload_digest(case.payload) for case in cases}) >= 6


@pytest.mark.parametrize("index", range(4))
def test_original_stdout_exit_and_native_oracles_remain_required(tmp_path: Path, index: int) -> None:
    case = daemon_cases(tmp_path)[index]
    assert case.normal_case is not None and case.normal_case.native_expected is not None
    expected, exit_code = delivery_expectation(case.normal_case)
    response = dict(expected.fields)
    response.update(dict.fromkeys(expected.nonempty_fields, "Original fixture reason."))
    validate_delivery(case, response, exit_code, "")
    with pytest.raises(AssertionError):
        validate_delivery(case, response, 0 if exit_code else 2, "")
    evidence: dict[str, object] = {
        "setup": {
            "fault_scope": "none",
            "python_oracle_disabled": True,
            "isolated_store": True,
            "policy_ack_current": True,
            "effective_policy_allow": True,
        },
        "native_call_count": 1,
        "native_completed_call_count": 1,
        "native_result": dict(case.normal_case.native_expected.fields),
    }
    validate_daemon_evidence(case, evidence, "native_resident")
    evidence["native_result"] = None
    with pytest.raises(AssertionError):
        validate_daemon_evidence(case, evidence, "native_resident")


@pytest.mark.parametrize(
    "change", ("allow", "interrupt", "nested", "message", "reason", "extra", "exit", "stderr", "nonobject")
)
def test_permission_delivery_rejects_contract_changes(tmp_path: Path, change: str) -> None:
    case = permission_cases(tmp_path, kind="permission_daemon")[0]
    response: object = dict(PERMISSION_RESPONSE)
    validate_delivery(case, response, 0, "")
    assert isinstance(response, dict)
    if change == "allow":
        response["behavior"] = "allow"
    elif change == "interrupt":
        response["interrupt"] = True
    elif change == "nested":
        response = {"hookSpecificOutput": {"permissionDecision": "allow"}}
    elif change == "message":
        response["message"] = "Changed reason."
    elif change == "reason":
        response["reason_code"] = "native_policy_not_ready"
    elif change == "extra":
        response["permissionDecision"] = "allow"
    elif change == "nonobject":
        response = []
    with pytest.raises(AssertionError):
        validate_delivery(case, response, 2 if change == "exit" else 0, "unexpected" if change == "stderr" else "")


@pytest.mark.parametrize(
    "change", ("native-result", "route", "zero-calls", "bool-calls", "not-completed", "oracle", "injected", "no-ack")
)
def test_permission_edge_attempt_cannot_be_claimed_as_native_evaluation(tmp_path: Path, change: str) -> None:
    case = permission_cases(tmp_path, kind="permission_daemon")[0]
    setup = {
        "fault_scope": "none",
        "python_oracle_disabled": True,
        "policy_ack_current": True,
        "effective_policy_allow": True,
    }
    evidence: dict[str, object] = {
        "setup": setup,
        "native_result": None,
        "native_call_count": 1,
        "native_completed_call_count": 1,
    }
    validate_daemon_evidence(case, evidence, "native_fail_safe")
    if change == "native-result":
        evidence["native_result"] = {"decision": "allow"}
    elif change == "zero-calls":
        evidence["native_call_count"] = 0
    elif change == "bool-calls":
        evidence["native_call_count"] = True
    elif change == "not-completed":
        evidence["native_completed_call_count"] = 0
    elif change == "oracle":
        setup["python_oracle_disabled"] = False
    elif change == "injected":
        setup["fault_scope"] = "injected_native_transport_unavailable"
    elif change == "no-ack":
        setup["policy_ack_current"] = False
    with pytest.raises(AssertionError):
        validate_daemon_evidence(case, evidence, "native_resident" if change == "route" else "native_fail_safe")


@pytest.mark.parametrize("event_index", (0, 1))
def test_watch_unavailable_preserves_cursor_native_pre_post_shapes(tmp_path: Path, event_index: int) -> None:
    case = watch_cases(tmp_path)[event_index]
    response = {"permission": "allow"} if event_index == 0 else {}
    validate_delivery(case, response, 0, "")
    with pytest.raises(AssertionError):
        validate_delivery(case, {"hookSpecificOutput": {"permissionDecision": "allow"}}, 0, "")


@pytest.mark.parametrize("entry", ("daemon-state.json", "daemon-auth-token"))
@pytest.mark.parametrize("symlink", (False, True))
def test_actual_absence_rejects_endpoint_metadata_and_dangling_symlinks(
    tmp_path: Path, entry: str, symlink: bool
) -> None:
    assert no_daemon_state(tmp_path) == {"daemon-state.json": False, "daemon-auth-token": False}
    path = tmp_path / entry
    if symlink:
        path.symlink_to(tmp_path / "absent")
    else:
        path.write_text("present", encoding="utf-8")
    with pytest.raises(RuntimeError, match="absence"):
        no_daemon_state(tmp_path)


@pytest.mark.parametrize("scope", ("global", "project"))
@pytest.mark.parametrize("event", ("permissionRequest", "permissionRequestV2"))
def test_actual_registered_permission_reader_rejects_changed_event_slot(tmp_path: Path, scope: str, event: str) -> None:
    home, workspace, guard_home = (tmp_path / name for name in ("home", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    install_registered_surface(context, "copilot")
    case = next(
        c for c in permission_cases(workspace, kind="permission_daemon") if (c.scope, c.event) == (scope, event)
    )
    before = registration(context, case)
    assert before.event == event and before.scope == scope and before.argv[1:3] == ("-I", "-c")
    payload = json.loads(before.config_path.read_text())
    payload["hooks"][event][0]["enabled"] = False
    before.config_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="disabled"):
        registration(context, case)
    with pytest.raises(RuntimeError):
        registration(context, replace(case, scope="project" if scope == "global" else "global", event="unknown"))


@pytest.mark.parametrize(
    "change", ("missing", "duplicate", "false-native", "swapped-native", "renamed", "failed", "cleanup")
)
def test_summary_rejects_missing_or_misclassified_offers(tmp_path: Path, change: str) -> None:
    cases = daemon_cases(tmp_path) + permission_cases(tmp_path, kind="permission_no_daemon") + watch_cases(tmp_path)
    report = {
        "rows": [
            {
                "label": c.label,
                "kind": c.kind,
                "status": "completed",
                "registration_unchanged": True,
                "native_evaluation": c.kind == "evaluated",
            }
            for c in cases
        ],
        "daemon_cleanup_contained": True,
        "no_daemon_cleanup_contained": True,
    }
    validate_population(report)
    mutated = copy.deepcopy(report)
    rows = mutated["rows"]
    assert isinstance(rows, list)
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows[-1] = rows[0]
    elif change == "false-native":
        rows[-1]["native_evaluation"] = True
    elif change == "swapped-native":
        rows[0]["native_evaluation"], rows[-1]["native_evaluation"] = False, True
    elif change == "renamed":
        rows[-1]["label"] = "undeclared/case"
    elif change == "failed":
        rows[-1]["status"] = "offered"
    else:
        mutated["no_daemon_cleanup_contained"] = False
    with pytest.raises(AssertionError):
        validate_population(mutated)


@pytest.mark.parametrize(
    "failure", ("none", "timeout", "containment", "output", "invalid-json", "changed-registration")
)
def test_invocation_forwards_exact_registration_and_contains_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    # Match the installed driver's cleared environment at registration time.
    # The ordinary pytest suite supplies development/oracle overrides.
    ambient = dict(os.environ)
    for name in clear_proof_environment(ambient):
        monkeypatch.delenv(name, raising=False)
    home, workspace, guard_home = (tmp_path / name for name in ("home", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    install_registered_surface(context, "copilot")
    case = permission_cases(workspace, kind="permission_no_daemon")[0]
    surface = registration(context, case)
    offered: list[object] = []

    def process(argv: tuple[str, ...], **kwargs: Any) -> BoundedHookProcessResult:
        assert argv == surface.argv
        assert kwargs["cwd"] == surface.cwd
        assert kwargs["timeout_seconds"] == 30.0
        assert kwargs["output_limit"] == 2 * 1024 * 1024
        assert json.loads(kwargs["input_text"]) == dict(case.payload)
        assert kwargs["environment"]["HOME"] == str(home)
        assert "PYTHONPATH" not in kwargs["environment"] and "PYTHONHOME" not in kwargs["environment"]
        offered.append(argv)
        if failure == "changed-registration":
            surface.config_path.write_bytes(surface.config_path.read_bytes() + b"\n")
        return BoundedHookProcessResult(
            0,
            "{" if failure == "invalid-json" else json.dumps(PERMISSION_RESPONSE),
            failure == "output",
            failure == "timeout",
            containment_failed=failure == "containment",
        )

    monkeypatch.setattr(runner, "run_isolated_hook_process", process)
    row: dict[str, Any] = {}
    if failure == "none":
        assert runner.invoke(context, case, row) == PERMISSION_RESPONSE
        assert row["registration_unchanged"] is True
    else:
        with pytest.raises((RuntimeError, ValueError)):
            runner.invoke(context, case, row)
        assert row.get("registration_unchanged") is not True
    assert offered == [surface.argv]
    assert row["returncode"] == 0


def test_registered_development_override_is_rejected_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, workspace, guard_home = (tmp_path / name for name in ("home", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    install_registered_surface(context, "copilot")
    case = permission_cases(workspace, kind="permission_no_daemon")[0]
    surface = registration(context, case)
    data = json.loads(surface.config_path.read_text())
    data["hooks"][case.event][0]["env"] = {"HOL_GUARD_NATIVE": "off"}
    surface.config_path.write_text(json.dumps(data), encoding="utf-8")

    def unexpected(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("inadmissible registration executed")

    monkeypatch.setattr(runner, "run_isolated_hook_process", unexpected)
    with pytest.raises(RuntimeError, match="registered_override"):
        runner.invoke(context, case, {})


def test_process_exception_retains_owned_private_root_and_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ambient = dict(os.environ)
    for name in clear_proof_environment(ambient):
        monkeypatch.delenv(name, raising=False)
    owned = tmp_path / "owned"
    owned.mkdir()
    monkeypatch.setattr(runner.tempfile, "mkdtemp", lambda **kwargs: str(owned))
    original = RuntimeError("modeled post-spawn failure before containment result")

    def process(*args: Any, **kwargs: Any) -> Any:
        raise original

    monkeypatch.setattr(runner, "run_isolated_hook_process", process)
    report: dict[str, Any] = {"rows": []}
    with pytest.raises(RuntimeError) as raised:
        runner.run_no_daemon_cases(report, watch=False)
    assert raised.value is original
    assert owned.is_dir() and (owned / "guard-home/config.toml").is_file()
    assert report["no_daemon_cleanup_contained"] is False
    assert report["rows"][0]["containment_unavailable"] is True
    assert report["rows"][0]["stage"] == "process"


@pytest.mark.parametrize("index", (0, 2))
def test_full_original_delivery_is_validated_without_exporting_private_reason_or_extra_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    import hashlib

    ambient = dict(os.environ)
    for name in clear_proof_environment(ambient):
        monkeypatch.delenv(name, raising=False)
    for name in ("home", "workspace", "guard-home"):
        (tmp_path / name).mkdir()
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home")
    case = daemon_cases(tmp_path / "workspace")[index]
    assert case.normal_case is not None
    install_registered_surface(context, case.harness)
    expected, exit_code = delivery_expectation(case.normal_case)
    secret = "/private/case/token=synthetic-do-not-export"
    response: dict[str, object] = dict(expected.fields)
    response.update(dict.fromkeys(expected.nonempty_fields, secret))
    response["scanner_evidence"] = {"private_extra": secret}

    def process(*args: Any, **kwargs: Any) -> BoundedHookProcessResult:
        return BoundedHookProcessResult(exit_code, json.dumps(response), False, False)

    monkeypatch.setattr(runner, "run_isolated_hook_process", process)
    row: dict[str, Any] = {}
    assert runner.invoke(context, case, row) == response
    assert secret not in json.dumps(row) and "private_extra" not in json.dumps(row)
    assert row["delivery"]["original_oracle_passed"] is True
    assert row["delivery"]["fields"] == dict(expected.fields)
    for image in row["delivery"]["nonempty_text_images"].values():
        assert image["bytes"] == len(secret.encode())
        assert image["sha256"] == hashlib.sha256(secret.encode()).hexdigest()


def test_native_full_original_object_is_checked_before_bounded_private_projection(tmp_path: Path) -> None:
    from scripts.native_slo_managed_aliases import native_evidence_projection

    case = daemon_cases(tmp_path)[0]
    assert case.normal_case is not None and case.normal_case.native_expected is not None
    secret = "/private/credential=synthetic-native-secret"
    evidence: dict[str, Any] = {
        "setup": {
            "fault_scope": "none",
            "python_oracle_disabled": True,
            "isolated_store": True,
            "policy_ack_current": True,
            "effective_policy_allow": True,
            "private_extra": secret,
        },
        "native_call_count": 1,
        "native_completed_call_count": 1,
        "native_result": dict(case.normal_case.native_expected.fields),
        "private_extra": secret,
    }
    evidence["native_result"]["private_extra"] = secret
    projected = native_evidence_projection(case, evidence, "native_resident")
    assert secret not in json.dumps(projected) and "private_extra" not in json.dumps(projected)
    assert projected["native_result"] == dict(case.normal_case.native_expected.fields)
    assert projected["validated_full_evidence_sha256"] == payload_digest(evidence)
    evidence["native_result"]["policy_action"] = "allow"
    with pytest.raises(AssertionError):
        native_evidence_projection(case, evidence, "native_resident")


@pytest.mark.parametrize("fault", ("missing-text", "raw-text", "empty-text", "hash", "extra", "oracle"))
def test_delivery_projection_cannot_hide_an_unvalidated_or_private_field(tmp_path: Path, fault: str) -> None:
    from scripts.native_slo_managed_aliases import delivery_projection, validate_delivery_projection

    case = daemon_cases(tmp_path)[0]
    assert case.normal_case is not None
    expected, code = delivery_expectation(case.normal_case)
    response: dict[str, object] = dict(expected.fields)
    response.update(dict.fromkeys(expected.nonempty_fields, "Private text is hashed only."))
    projected: dict[str, Any] = delivery_projection(case, response, code, "")
    validate_delivery_projection(case, projected, code)
    if fault == "missing-text":
        projected["nonempty_text_images"].pop("user_message")
    elif fault == "raw-text":
        projected["nonempty_text_images"]["user_message"] = "private"
    elif fault == "empty-text":
        projected["nonempty_text_images"]["user_message"]["bytes"] = 0
    elif fault == "hash":
        projected["nonempty_text_images"]["user_message"]["sha256"] = "bad"
    elif fault == "extra":
        projected["private_extra"] = "/private/path"
    elif fault == "oracle":
        projected["original_oracle_passed"] = False
    with pytest.raises(AssertionError):
        validate_delivery_projection(case, projected, code)
