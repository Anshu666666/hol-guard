"""HGP-183: policy permissions at the Python launch/action boundary."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import (
    _runtime_artifact_policy_action,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact


def _config(tmp_path: Path, *, default_action: str) -> GuardConfig:
    return GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path, default_action=default_action)


def _artifact(kind: str, *, harness: str = "codex") -> GuardArtifact:
    metadata: dict[str, object] = {"action_class": kind}
    if kind == "mcp":
        metadata["tool_name"] = "mcp__server__tool"
    if kind == "package":
        metadata["package_name"] = "demo-pkg"
    return GuardArtifact(
        artifact_id=f"{harness}:{kind}:canary",
        name=kind,
        harness=harness,
        artifact_type=kind,
        source_scope="project",
        config_path="/workspace/config.toml",
        command="echo canary" if kind == "shell" else None,
        metadata=metadata,
    )


def test_allow_review_block_at_python_launch_boundary(tmp_path: Path) -> None:
    uncovered = sorted(
        {f"{contract.harness}:{spot}" for contract in HARNESS_CONTRACTS for spot in contract.known_blind_spots}
    )
    assert uncovered
    ranks = {
        "allow": 0,
        "warn": 1,
        "review": 2,
        "require-reapproval": 3,
        "sandbox-required": 4,
        "block": 5,
    }
    for kind in ("shell", "file_read", "mcp", "package"):
        allowed = _runtime_artifact_policy_action(_config(tmp_path, default_action="allow"), _artifact(kind), "codex")
        reviewed = _runtime_artifact_policy_action(_config(tmp_path, default_action="review"), _artifact(kind), "codex")
        blocked = _runtime_artifact_policy_action(_config(tmp_path, default_action="block"), _artifact(kind), "codex")
        assert blocked == "block"
        assert ranks[allowed] <= ranks[blocked]
        assert ranks[reviewed] <= ranks[blocked]
