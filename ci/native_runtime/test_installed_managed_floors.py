"""Fail-closed installed-probe controls, separate from real native acceptance."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime import probe_installed_managed_floors as probe


@pytest.mark.parametrize(
    "fault",
    [None, "http_allow", "approval", "generation", "digest", "request_digest", "controls", "receipt", "stale_receipt"],
)
def test_probe_requires_final_http_floor_and_exact_native_receipt(fault: str | None) -> None:
    response: dict[str, object] = {"hookSpecificOutput": {"permissionDecision": "deny"}, "policy_action": "block"}
    binding: dict[str, object] = {"generation": 3, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}
    receipt: object = {
        "decision_id": "d" * 64,
        "request_id": "synthetic-current",
        "request_digest": "e" * 64,
        "reason_code": "native_command_permission_disabled",
        "policy_action": "block",
        "authority": "rust",
        "decision": "deny",
        "policy_generation": 3,
        "policy_digest": binding["policy_digest"],
        "runtime_identity": binding["runtime_identity"],
        "command_extensions": {"revision": 7},
    }
    assert isinstance(receipt, dict)
    if fault == "http_allow":
        response["hookSpecificOutput"] = {"permissionDecision": "allow"}
    elif fault == "approval":
        response["approval_reuse_status"] = "accepted"
    elif fault == "generation":
        receipt["policy_generation"] = 2
    elif fault == "digest":
        receipt["policy_digest"] = "c" * 64
    elif fault == "request_digest":
        receipt["request_digest"] = "f" * 64
    elif fault == "controls":
        receipt["command_extensions"] = {"revision": 6}
    elif fault == "receipt":
        receipt = None
    if fault is None:
        probe.verify_delivery(
            response,
            binding=binding,
            receipt=receipt,
            command_binding={"revision": 7},
            previous_receipt=receipt if fault == "stale_receipt" else None,
            expected_reason="native_command_permission_disabled",
            expected_request_digest="e" * 64,
        )
    else:
        with pytest.raises(probe.ProbeError) as caught:
            probe.verify_delivery(
                response,
                binding=binding,
                receipt=receipt,
                command_binding={"revision": 7},
                previous_receipt=receipt if fault == "stale_receipt" else None,
                expected_reason="native_command_permission_disabled",
                expected_request_digest="e" * 64,
            )
        if fault == "request_digest":
            assert str(caught.value) == "receipt_request_mismatch"


def test_managed_probe_binds_identical_sources_through_an_owned_directory_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Actual fixture/encoder/path validation; no native readiness or ACK is supplied."""
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope

    target = tmp_path / "real"
    target.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("An owned directory symlink is required for this path-identity control.")
    root = alias / "fixture"
    root.mkdir(mode=0o700)
    seen: list[probe.ManagedPolicyFixture] = []

    def compare_sources(root: Path, fixture: probe.ManagedPolicyFixture) -> dict[str, object]:
        seen.append(fixture)
        home, workspace = fixture.store.guard_home, fixture.workspace
        assert fixture.thread.is_alive()
        # The HTTP endpoint resolves these directories before calling its worker.
        # Invoke that same validator with only this owned fixture as an allowed root.
        handler = object.__new__(_GuardDaemonHandler)
        http_home = handler._validate_hook_directory_path("home", str(home), roots=(target,))
        http_workspace = handler._validate_hook_directory_path("workspace", str(workspace), roots=(target,))
        assert http_home.samefile(home) and http_workspace.samefile(workspace)

        def encode(home_dir: Path, cwd: Path) -> dict[str, object]:
            encoded = _encode_hook_envelope(
                payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pwd"}},
                harness="claude-code",
                event="PreToolUse",
                guard_home=home,
                home_dir=home_dir,
                cwd=cwd,
                source_ref_external_allowed=False,
                deadline_budget_ms=100,
                # A serialization input, never installed or advertised as authority.
                snapshot={"generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64},
            )
            assert encoded is not None
            value: dict[str, object] = json.loads(encoded)
            return value

        raw = encode(home, workspace)
        http = encode(http_home, http_workspace)
        assert raw == http
        assert root == root.resolve(strict=True)
        assert fixture.root == root
        return {"source_inputs_equal": True}

    monkeypatch.setattr(probe, "_exercise_fixture", compare_sources)
    try:
        assert probe.exercise(root) == {"source_inputs_equal": True}
    finally:
        for fixture in seen:
            assert not fixture.thread.is_alive()
            assert fixture.server.socket.fileno() == -1


def test_probe_rejects_uninstalled_source_without_private_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "report.json"
    monkeypatch.setattr(probe.codex_plugin_scanner, "__file__", "/synthetic-private-canary/package.py")
    monkeypatch.setattr(probe.sys, "argv", ["probe", "--json", str(target), "--expected-source-sha", "a" * 40])
    assert probe.main() == 1
    report = json.loads(target.read_text())
    assert report == {
        "schema": "guard.installed-managed-floors.v1",
        "passed": False,
        "failure": "not_installed_package",
    }
    assert "synthetic-private-canary" not in capsys.readouterr().out


def test_setup_failure_closes_actual_tls_fixture_and_restores_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    fixture = probe.ManagedPolicyFixture(tmp_path)
    original = RuntimeError("synthetic-setup-failure")
    monkeypatch.setenv("SSL_CERT_FILE", "synthetic-prior-ca")
    monkeypatch.setattr(probe, "ManagedPolicyFixture", lambda _root: fixture)

    def fail(_store: object) -> None:
        raise original

    monkeypatch.setattr(probe, "provision", fail)
    with pytest.raises(RuntimeError) as caught:
        probe.exercise(tmp_path)
    assert caught.value is original
    assert not fixture.thread.is_alive()
    assert fixture.server.socket.fileno() == -1
    assert os.environ["SSL_CERT_FILE"] == "synthetic-prior-ca"


def test_each_platform_runs_source_bound_probe_and_retains_its_report() -> None:
    import yaml

    workflow = yaml.load(
        (Path(__file__).resolve().parents[2] / ".github/workflows/native-wheel-ci.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    for job in workflow["jobs"].values():
        steps = job["steps"]
        runs = [step["run"] for step in steps if "probe_installed_managed_floors.py" in step.get("run", "")]
        assert len(runs) == 1
        run = runs[0]
        assert "--expected-source-sha" in run and "SOURCE_SHA" in run
        assert "--json installed-managed-floors.json" in run and " -I " in run
        for flag in (
            "GUARD_EXTENSION_CATALOG_SYNC_V1",
            "GUARD_POLICY_EXTENSION_TARGETS_V1",
            "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
            "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        ):
            assert flag in run
        if "Scripts\\python.exe" in run:
            after = run.split("probe_installed_managed_floors.py", 1)[1]
            assert after.splitlines()[1].strip() == "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        assert any(
            "installed-managed-floors.json" in step.get("with", {}).get("path", "") and step.get("if") == "always()"
            for step in steps
        )


@pytest.mark.parametrize("immutable_review", [False, True])
@pytest.mark.parametrize("fault", [None, "allow", "wrong_floor", "wrong_action", "missing_rule", "uncertain_rule"])
def test_native_floor_predicate_distinguishes_exact_immutable_review_from_hard_block(
    immutable_review: bool, fault: str | None
) -> None:
    """Predicate controls only; the corresponding Rust test evaluates the catalog."""
    floor = "review" if immutable_review else "block"
    row: dict[str, object] = {
        "rule_id": "command.guard-self-protection.self-authorization",
        "effective_segment_indexes": [0],
        "uncertainty_reasons": [],
    }
    result = {
        "decision": "deny",
        "minimum_action": floor,
        "policy_action": floor,
        "command_extensions": {"observations": [row]},
    }
    if fault == "allow":
        result["decision"] = "allow"
    elif fault == "wrong_floor":
        result["minimum_action"] = "allow" if immutable_review else "review"
    elif fault == "wrong_action":
        result["policy_action"] = "allow"
    elif fault == "missing_rule":
        row["rule_id"] = "different-rule"
    elif fault == "uncertain_rule":
        row["uncertainty_reasons"] = ["uncertain"]
    rejected = fault is not None and (immutable_review or fault not in {"missing_rule", "uncertain_rule"})
    if rejected:
        with pytest.raises(probe.ProbeError):
            probe.verify_native_floor(
                result, label="immutable-enable-rejected-enforce", immutable_review=immutable_review
            )
    else:
        probe.verify_native_floor(result, label="immutable-enable-rejected-enforce", immutable_review=immutable_review)


@pytest.mark.parametrize("fault", [None, "allow", "deny", "missing_approval", "unprompted", "reused", "receipt_block"])
def test_immutable_review_requires_exact_http_pause_and_native_review_receipt(fault: str | None) -> None:
    response: dict[str, object] = {
        "hookSpecificOutput": {"permissionDecision": "ask"},
        "policy_action": "review",
        "approval_request_id": "synthetic-pending",
        "prompted": True,
    }
    binding: dict[str, object] = {"generation": 3, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}
    receipt = {
        "decision_id": "current-decision",
        "request_id": "current-request",
        "request_digest": "e" * 64,
        "reason_code": "native_command_extension_review",
        "policy_action": "review",
        "authority": "rust",
        "decision": "deny",
        "policy_generation": 3,
        "policy_digest": binding["policy_digest"],
        "runtime_identity": binding["runtime_identity"],
        "command_extensions": {"revision": 7},
    }
    if fault in {"allow", "deny"}:
        response["hookSpecificOutput"] = {"permissionDecision": fault}
    elif fault == "missing_approval":
        del response["approval_request_id"]
    elif fault == "unprompted":
        response["prompted"] = False
    elif fault == "reused":
        response["approval_reuse_status"] = "accepted"
    elif fault == "receipt_block":
        receipt["policy_action"] = "block"

    def verify() -> None:
        probe.verify_delivery(
            response,
            binding=binding,
            receipt=receipt,
            command_binding={"revision": 7},
            previous_receipt=None,
            expected_reason="native_command_extension_review",
            expected_request_digest="e" * 64,
            immutable_review=True,
        )

    if fault is None:
        verify()
    else:
        with pytest.raises(probe.ProbeError):
            verify()


def test_floor_failure_observation_preserves_only_finite_decision_values() -> None:
    error = probe.NativeFloorMismatchError(
        "synthetic-private-case",
        {"decision": "synthetic-private-value", "minimum_action": "private-material"},
        "private-expectation",
    )
    assert str(error) == "native_floor_weakened"
    assert error.observation == {
        "case": "other",
        "expected_minimum_action": "invalid",
        "decision": "invalid",
        "minimum_action": "invalid",
    }
    actual = probe.NativeFloorMismatchError(
        "immutable-enable-rejected-enforce", {"decision": "deny", "minimum_action": "review"}, "block"
    )
    assert actual.observation == {
        "case": "immutable-enable-rejected-enforce",
        "expected_minimum_action": "block",
        "decision": "deny",
        "minimum_action": "review",
    }


@pytest.mark.parametrize(
    "changed",
    [
        None,
        "policy_generation",
        "policy_digest",
        "runtime_identity",
        "command_extensions",
        "reason_code",
        "policy_action",
    ],
)
def test_request_mismatch_preserves_failure_and_distinguishes_captured_binding_comparisons(
    changed: str | None,
) -> None:
    """Real probe predicate; the supplied receipts are synthetic comparison inputs."""
    binding: dict[str, object] = {"generation": 3, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}
    receipt: dict[str, object] = {
        "decision_id": "current-decision",
        "request_id": "current-request",
        "request_digest": "f" * 64,
        "reason_code": "native_command_permission_disabled",
        "policy_action": "block",
        "authority": "rust",
        "decision": "deny",
        "policy_generation": 3,
        "policy_digest": binding["policy_digest"],
        "runtime_identity": binding["runtime_identity"],
        "command_extensions": {"revision": 7},
    }
    if changed is not None:
        receipt[changed] = "synthetic-private-changed-value"
    with pytest.raises(probe.ReceiptRequestMismatchError) as caught:
        probe.verify_delivery(
            {"hookSpecificOutput": {"permissionDecision": "deny"}, "policy_action": "block"},
            binding=binding,
            receipt=receipt,
            command_binding={"revision": 7},
            previous_receipt=None,
            expected_reason="native_command_permission_disabled",
            expected_request_digest="e" * 64,
            label="managed-permission-observe",
            completed_cases=2,
        )
    assert str(caught.value) == "receipt_request_mismatch"
    assert caught.value.observation == {
        "case": "managed-permission-observe",
        "completed_cases": 2,
        "matches_expected": {
            field: field != changed
            for field in (
                "policy_generation",
                "policy_digest",
                "runtime_identity",
                "command_extensions",
                "reason_code",
                "policy_action",
            )
        },
    }
    assert "synthetic-private" not in json.dumps(caught.value.observation)


@pytest.mark.parametrize("completed,expected", [(None, None), (True, None), (-1, 0), (2, 2), (10_000, 20)])
def test_request_mismatch_report_keeps_only_finite_fields_and_the_original_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    completed: int | None,
    expected: int | None,
) -> None:
    """Exercise report serialization only; stop before any native prerequisites."""
    private = "synthetic-private-report-canary"
    error = probe.ReceiptRequestMismatchError(
        label=private,
        completed_cases=completed,
        receipt={"policy_digest": private, "command_extensions": {"path": private}},
        binding={"generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64},
        command_binding={"revision": 1},
        expected_reason=private,
        expected_action=private,
    )

    def stop_before_native_prerequisites(_environment: object) -> bool:
        raise error

    target = tmp_path / "report.json"
    monkeypatch.setattr(probe.codex_plugin_scanner, "__file__", str(tmp_path / "site-packages" / "package.py"))
    monkeypatch.setattr(probe, "environment_is_clean", stop_before_native_prerequisites)
    monkeypatch.setattr(probe.sys, "argv", ["probe", "--json", str(target), "--expected-source-sha", "a" * 40])
    assert probe.main() == 1
    output = capsys.readouterr().out
    report = json.loads(target.read_text())
    assert report == json.loads(output)
    assert report == {
        "schema": "guard.installed-managed-floors.v1",
        "passed": False,
        "failure": "receipt_request_mismatch",
        "failure_observation": {
            "case": "other",
            "completed_cases": expected,
            "matches_expected": dict.fromkeys(
                (
                    "policy_generation",
                    "policy_digest",
                    "runtime_identity",
                    "command_extensions",
                    "reason_code",
                    "policy_action",
                ),
                False,
            ),
        },
    }
    assert private not in output and private not in target.read_text()


def _controlled_http_call(
    monkeypatch: pytest.MonkeyPatch, home: Path, binding: dict[str, Any]
) -> tuple[Any, dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Real worker delegation/encoder; the resident response is explicitly controlled."""
    from codex_plugin_scanner.guard.daemon import hook_worker
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope

    worker = object.__new__(hook_worker.HookWorker)
    inputs = {
        "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pwd"}},
        "harness": "claude-code",
        "event": "PreToolUse",
        "guard_home": home,
        "home_dir": home,
        "cwd": home,
        "source_ref_external_allowed": False,
        "observe_mode": False,
        "deadline": 123.0,
        "policy_snapshot": binding,
    }
    returned: list[dict[str, Any]] = []

    def resident(**kwargs: Any) -> dict[str, Any]:
        encoded = _encode_hook_envelope(
            **{
                key: value
                for key, value in kwargs.items()
                if key not in {"policy_snapshot", "deadline", "observe_mode"}
            },
            snapshot=kwargs["policy_snapshot"],
            deadline_budget_ms=100,
        )
        assert encoded is not None
        # A deterministic fixture digest over the real encoded inputs, not a
        # claim to reproduce Rust's canonical request-identity implementation.
        current = kwargs["policy_snapshot"]
        receipt = {
            "decision_id": f"decision-{len(returned)}",
            "request_id": f"request-{len(returned)}",
            "request_digest": hashlib.sha256(encoded).hexdigest(),
            "reason_code": "native_command_permission_disabled",
            "policy_action": "block",
            "authority": "rust",
            "decision": "deny",
            "policy_generation": current["generation"],
            "policy_digest": current["policy_digest"],
            "runtime_identity": current["runtime_identity"],
            "command_extensions": {"revision": 7},
        }
        edge = {
            "authority": "rust",
            "schema": "guard-hook-edge-result.v2",
            "receipt": receipt,
            "result": {"decision": "deny", "minimum_action": "block", "policy_action": "block"},
        }
        returned.append(edge)
        return edge

    monkeypatch.setattr(hook_worker, "review_raw_hook_native", resident)
    verify = {
        "payload": inputs["payload"],
        "home": home,
        "workspace": home,
        "mode": binding["mode"],
        "runtime_identity": binding["runtime_identity"],
        "label": "recovered-lockdown-observe",
        "immutable_review": False,
    }
    return worker, inputs, returned, verify


def test_http_receipt_uses_its_actual_renewed_publication_without_replaying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Actual Store/publication/worker; native ACK and responses are controlled."""
    from tests.test_guard_extension_control_authority import MemorySecretStore, _store
    from tests.test_native_command_control_binding_publisher import _publish_ready, _publisher

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, monkeypatch)
    try:
        _publish_ready(publisher)
        first = publisher.current_snapshot_binding()
        assert first is not None
        worker, inputs, returned, verify = _controlled_http_call(monkeypatch, tmp_path, first)
        direct = worker._review_raw_hook_native(**inputs)
        generation = first["generation"]
        assert isinstance(generation, int)
        publisher._publish_once(renew_after_generation=generation)
        assert publisher.is_ready(), publisher.last_error
        current = publisher.current_snapshot_binding()
        assert current is not None
        assert current["generation"] != first["generation"]
        assert current["policy_digest"] == first["policy_digest"]
        assert current["runtime_identity"] == first["runtime_identity"]
        inputs["policy_snapshot"] = current
        with probe.observe_http_native_call(worker) as calls:
            actual = worker._review_raw_hook_native(**inputs)
        assert len(returned) == 2 and actual is returned[1]
        assert "_review_raw_hook_native" not in vars(worker)
        response: dict[str, object] = {"hookSpecificOutput": {"permissionDecision": "deny"}, "policy_action": "block"}
        checks = dict(
            receipt=actual["receipt"],
            command_binding={"revision": 7},
            previous_receipt=direct["receipt"],
            expected_reason="native_command_permission_disabled",
        )
        # The original cross-call comparison refuses an otherwise valid renewal.
        with pytest.raises(probe.ReceiptRequestMismatchError) as before:
            probe.verify_delivery(
                response, binding=first, expected_request_digest=direct["receipt"]["request_digest"], **checks
            )
        comparisons = before.value.observation["matches_expected"]
        assert isinstance(comparisons, dict)
        assert comparisons["policy_generation"] is False
        assert comparisons["policy_digest"] is True
        selected, edge = probe.verify_http_native_call(calls, receipt=actual["receipt"], **verify)
        probe.verify_delivery(
            response, binding=selected, expected_request_digest=edge["receipt"]["request_digest"], **checks
        )
        assert len(returned) == 2  # Observation/verification never retries either call.
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "none",
        "extra",
        "payload",
        "harness",
        "event",
        "guard_home",
        "home_dir",
        "cwd",
        "source_ref_external_allowed",
        "observe_mode",
        "mode",
        "runtime_identity",
        "command_extensions_bound",
        "source_input_digest",
        "authority",
        "floor",
        "receipt",
    ],
)
def test_http_observation_refuses_foreign_inputs_or_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None
) -> None:
    binding = {
        "generation": 3,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": "observe",
        "command_extensions_bound": True,
    }
    worker, inputs, returned, verify = _controlled_http_call(monkeypatch, tmp_path, binding)
    expected_inputs = copy.deepcopy(inputs)
    with probe.observe_http_native_call(worker) as calls:
        actual = worker._review_raw_hook_native(**inputs)
    assert inputs == expected_inputs and actual is returned[0]
    assert len(calls) == 1
    observed_inputs, observed_edge = calls[0]
    assert isinstance(observed_edge, dict)
    if fault == "none":
        calls.clear()
    elif fault == "extra":
        calls.append(copy.deepcopy(calls[0]))
    elif fault in {"payload", "harness", "event", "guard_home", "home_dir", "cwd"}:
        observed_inputs[fault] = "private-foreign-canary"
    elif fault in {"source_ref_external_allowed", "observe_mode"}:
        observed_inputs[fault] = True
    elif fault in {"mode", "runtime_identity", "command_extensions_bound", "source_input_digest"}:
        observed_inputs["policy_snapshot"][fault] = "private-foreign-canary"
    elif fault == "authority":
        observed_edge["authority"] = "python"
    elif fault == "floor":
        observed_edge["result"]["minimum_action"] = "allow"
    elif fault == "receipt":
        observed_edge["receipt"]["request_id"] = "foreign"
    if fault is None:
        probe.verify_http_native_call(calls, receipt=actual["receipt"], **verify)
    else:
        with pytest.raises(probe.ProbeError) as caught:
            probe.verify_http_native_call(calls, receipt=actual["receipt"], **verify)
        assert "private-foreign-canary" not in str(caught.value)


def test_http_observer_restores_existing_override_and_forwards_original_exception() -> None:
    from types import SimpleNamespace

    error = RuntimeError("controlled native failure")
    seen: list[object] = []

    def original(**kwargs: Any) -> None:
        seen.append(kwargs["payload"])
        raise error

    worker = SimpleNamespace(_review_raw_hook_native=original)
    payload = {"command": "private-canary"}
    with pytest.raises(RuntimeError) as caught, probe.observe_http_native_call(worker) as calls:
        worker._review_raw_hook_native(payload=payload)
    assert caught.value is error and seen[0] is payload
    assert worker._review_raw_hook_native is original and calls == []
