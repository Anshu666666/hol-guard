"""Fail-closed installed-probe controls, separate from real native acceptance."""

from __future__ import annotations

import json
from pathlib import Path

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
