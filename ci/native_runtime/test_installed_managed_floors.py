"""Fail-closed installed-probe controls, separate from real native acceptance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.native_runtime import probe_installed_managed_floors as probe


@pytest.mark.parametrize(
    "fault", [None, "http_allow", "approval", "generation", "digest", "controls", "receipt", "stale_receipt"]
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
        with pytest.raises(probe.ProbeError):
            probe.verify_delivery(
                response,
                binding=binding,
                receipt=receipt,
                command_binding={"revision": 7},
                previous_receipt=receipt if fault == "stale_receipt" else None,
                expected_reason="native_command_permission_disabled",
                expected_request_digest="e" * 64,
            )


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
