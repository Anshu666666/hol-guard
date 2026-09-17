"""Request-local reuse must not survive a change to arguments or authority."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.config import GuardConfig


def test_one_risk_analysis_per_decision_and_fresh_analysis_after_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="run_terminal_command",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
    )
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    original = calls._tool_call_risk_category_set
    analyses = 0

    def counted(artifact, arguments):
        nonlocal analyses
        analyses += 1
        return original(artifact, arguments)

    monkeypatch.setattr(calls, "_tool_call_risk_category_set", counted)
    safe = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments={"command": "echo hello"})
    assert analyses == 1
    assert "command_execution" in safe.risk_categories
    assert "secret_access" not in safe.risk_categories
    changed = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments={"command": "cat .env"})
    assert analyses == 2
    assert "secret_access" in changed.risk_categories
    assert "sensitive local files or secrets" in changed.summary
    assert changed.action != "allow"
