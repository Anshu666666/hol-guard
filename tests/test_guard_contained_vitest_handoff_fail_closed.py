from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import contained_node_execution


def test_installed_package_shim_stops_vitest_when_runner_evidence_is_missing(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    shim_directory = guard_home / "package-shims" / "bin"
    shim_directory.mkdir(parents=True)

    monkeypatch.setattr(
        contained_node_execution,
        "parse_package_intent",
        lambda *args, **kwargs: SimpleNamespace(local_executions=(SimpleNamespace(package_name="vitest"),)),
    )
    monkeypatch.setattr(contained_node_execution, "build_local_node_runner_evidence", lambda *args, **kwargs: None)

    with pytest.raises(SystemExit, match="refused uncontained Vitest execution"):
        contained_node_execution.try_execute_contained_node_command(
            "bunx",
            ("vitest", "run", "tests/unit.test.ts"),
            workspace=workspace,
            guard_home=guard_home,
            shim_directory=shim_directory,
            environment={"PATH": "/usr/bin"},
        )


def test_non_shim_vitest_returns_to_review_when_runner_evidence_is_missing(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shim_directory = tmp_path / "bin"
    shim_directory.mkdir()

    monkeypatch.setattr(
        contained_node_execution,
        "parse_package_intent",
        lambda *args, **kwargs: SimpleNamespace(local_executions=(SimpleNamespace(package_name="vitest"),)),
    )
    monkeypatch.setattr(contained_node_execution, "build_local_node_runner_evidence", lambda *args, **kwargs: None)

    result = contained_node_execution.try_execute_contained_node_command(
        "bunx",
        ("vitest", "run", "tests/unit.test.ts"),
        workspace=workspace,
        guard_home=tmp_path / "guard-home",
        shim_directory=shim_directory,
        environment={"PATH": "/usr/bin"},
    )
    assert result is None
