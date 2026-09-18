"""Actual generic relaxation and terminal-control boundaries for managed origins."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook import _run_guard_hook_command
from codex_plugin_scanner.guard.cli.commands_support_connect import _synced_policy_payload
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config, overlay_synced_guard_policy
from codex_plugin_scanner.guard.mdm.policy import load_managed_policy
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import managed_store
from tests.test_generic_managed_origin_outer import Mode, _toml
from tests.test_guard_extension_control_authority import MemorySecretStore


def _config(store: GuardStore, workspace: Path, mode: Mode, managed: dict[str, object]) -> GuardConfig:
    _ = (store.guard_home / "config.toml").write_text(
        _toml(
            {
                "mode": mode,
                "default_action": "allow",
                "unknown_publisher_action": "allow",
                "approval_wait_timeout_seconds": 0,
            }
        )
    )
    profile = store.guard_home / "synthetic-managed.json"
    _ = profile.write_text(
        json.dumps({"schemaVersion": "hol-guard-mdm-policy.v1", "settings": managed, "lockedSettings": list(managed)})
    )
    state = load_managed_policy(policy_path=profile, write_cache=False)
    assert state.status == "active" and state.policy is not None
    return load_guard_config(store.guard_home, workspace=workspace, managed_policy_state=state)


def _invoke(
    store: GuardStore,
    workspace: Path,
    config: GuardConfig,
    tool: str,
    command: str,
    *,
    runtime_expected: bool,
) -> int:
    raw: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
        "source_scope": "project",
        "approval_requests": [],
    }
    payload = _normalize_hook_payload(raw, harness="codex")
    action = _hook_action_envelope(harness="codex", payload=payload, home_dir=workspace.parent, workspace=workspace)
    assert action is not None
    artifact = _hook_runtime_artifact(
        harness="codex",
        payload=payload,
        action_envelope=action,
        home_dir=workspace.parent,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    assert (artifact is not None) is runtime_expected
    return _run_guard_hook_command(
        argparse.Namespace(harness="codex", artifact_id=None, artifact_name=None, json=True, policy_action=None),
        guard_home=store.guard_home,
        workspace=workspace,
        context=HarnessContext(home_dir=workspace.parent, workspace_dir=workspace, guard_home=store.guard_home),
        store=store,
        config=config,
        input_text=json.dumps(raw),
    )


@pytest.mark.parametrize("tool", ("Shell", "Bash", "shell", "exec_command"))
@pytest.mark.parametrize("action", ("review", "require-reapproval"))
@pytest.mark.parametrize("selector", ("default", "artifact"))
@pytest.mark.parametrize("mode", ("enforce", "observe"))
def test_actual_pwd_generic_relaxation_requires_its_tool_contract_and_broad_default(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    tool: str,
    action: str,
    selector: str,
    mode: Mode,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard")
    managed: dict[str, object] = (
        {"default_action": action} if selector == "default" else {"artifacts": {f"codex:project:{tool}": action}}
    )
    config = _config(store, workspace, mode, managed)
    code = _invoke(store, workspace, config, tool, "pwd", runtime_expected=False)
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    composition = output["policy_composition"]
    assert isinstance(composition, dict)
    relaxed = selector == "default" and tool in {"Shell", "Bash", "shell"}
    current = "warn" if relaxed else action
    observed = current if mode == "observe" and current != "warn" else None
    final = "allow" if observed else current
    assert composition["configured_policy_action"] == action
    assert composition["current_config_action"] == current
    assert composition["configured_default_disposition"] == ("relaxed_verified_benign" if relaxed else "applied")
    assert composition["observed_policy_action"] == observed
    assert output["policy_action"] == final
    assert code == (0 if final in {"allow", "warn"} else 1)


@pytest.mark.parametrize("mode", ("enforce", "observe"))
def test_remote_command_retains_its_distinct_runtime_boundary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    mode: Mode,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(store, workspace, mode, {"default_action": "allow"})
    code = _invoke(store, workspace, config, "Shell", "ssh synthetic@example.invalid whoami", runtime_expected=True)
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    expected = "review" if mode == "enforce" else "allow"
    assert output["policy_action"] == expected and code == (1 if mode == "enforce" else 0)


@pytest.mark.parametrize("mode", ("enforce", "observe"))
@pytest.mark.parametrize("lockdown", (False, True))
def test_signed_lockdown_remains_hard_for_a_generic_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    mode: Mode,
    lockdown: bool,
) -> None:
    store = managed_store(tmp_path, monkeypatch, lockdown=lockdown)
    authority = store.read_extension_control_authority_for_registry(REGISTRY)
    assert authority.health is AuthorityHealth.PROTECTED
    assert any(layer.global_lockdown for layer in authority.layers) is lockdown
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(store, workspace, mode, {"default_action": "allow"})
    code = _invoke(store, workspace, config, "Shell", "printf Synthetic", runtime_expected=False)
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert output["policy_action"] == ("block" if lockdown else "allow")
    assert code == (1 if lockdown else 0)


@pytest.mark.parametrize("mode", ("enforce", "observe"))
@pytest.mark.parametrize("failure", ("unavailable", "tampered"))
def test_enrolled_generic_control_authority_failure_cannot_release_a_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    mode: Mode,
    failure: str,
) -> None:
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.PROTECTED
    if failure == "unavailable":
        secrets = store._extension_control_authority_secret_store
        assert isinstance(secrets, MemorySecretStore)
        secrets.available = False
    else:
        with store._connect() as connection:
            _ = connection.execute(
                "update extension_control_authority_snapshot set snapshot_mac=? where singleton=1",
                ("synthetic-invalid",),
            )
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is not AuthorityHealth.PROTECTED
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(store, workspace, mode, {"default_action": "allow"})
    code = _invoke(store, workspace, config, "Shell", "printf Synthetic", runtime_expected=False)
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert output["policy_action"] == "block" and code == 1


@pytest.mark.parametrize("authority_lost", (False, True))
def test_actual_generic_post_claim_refresh_reads_current_control_authority(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    authority_lost: bool,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _ = (store.guard_home / "config.toml").write_text(
        _toml(
            {
                "default_action": "review",
                "unknown_publisher_action": "allow",
                "approval_wait_timeout_seconds": 0,
                "artifacts": {"codex:project:Shell": "review"},
            }
        )
    )
    config = overlay_synced_guard_policy(
        load_guard_config(store.guard_home, workspace=workspace), _synced_policy_payload(store)
    )
    assert _invoke(store, workspace, config, "Shell", "printf Synthetic", runtime_expected=False) == 1
    first = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert first["policy_action"] == "review"
    receipt = store.list_receipts(limit=1)[0]
    approval_id = store.record_local_once_approval(
        request_id="synthetic-generic-control-claim",
        harness=cast(str, receipt["harness"]),
        artifact_id=cast(str, receipt["artifact_id"]),
        artifact_hash=cast(str, receipt["artifact_hash"]),
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    secrets = store._extension_control_authority_secret_store
    assert isinstance(secrets, MemorySecretStore)
    original_claim = store.claim_approval_reuse_decision
    claim_count = 0

    def claim_then_change_authority(decision: Mapping[str, object], *, now: str | None = None) -> bool:
        nonlocal claim_count
        claimed = original_claim(decision, now=now)
        if claimed:
            claim_count += 1
            if authority_lost:
                secrets.available = False
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_change_authority)
    code = _invoke(store, workspace, config, "Shell", "printf Synthetic", runtime_expected=False)
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert claim_count == 1
    assert output["policy_action"] == ("block" if authority_lost else "allow")
    assert code == (1 if authority_lost else 0)
