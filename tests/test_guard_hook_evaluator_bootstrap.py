"""Oracle cold work finishes before evaluator readiness without state access."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_extension_control_manifest as manifests
from codex_plugin_scanner.guard.cli import commands_hook_compat_loader as compatibility
from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as entrypoint
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)

_RENDER_MODULE = "codex_plugin_scanner.guard.cli.render"


@dataclass
class StoppedConnection:
    events: list[str]
    sent: list[object] = field(default_factory=list)

    def send(self, value: object) -> None:
        self.sent.append(value)
        self.events.append("ready")

    def recv(self) -> tuple[str, None]:
        return "stop", None


def _prepare_spies(monkeypatch: pytest.MonkeyPatch, *, failure: str | None = None) -> list[str]:
    events: list[str] = []
    original_import = importlib.import_module

    def load_surface() -> dict[str, object] | None:
        events.append("compatibility")
        if failure == "compatibility":
            return None
        return {"admitted_fixture": object()}

    def import_module(name: str, package: str | None = None) -> ModuleType:
        if name == _RENDER_MODULE:
            events.append("render")
            if failure == "render":
                raise RuntimeError("render bootstrap failed")
            return ModuleType(name)
        # Preserve the six existing bootstrap imports and any dependencies.
        return original_import(name, package)

    def manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        assert registry is BUILT_IN_COMMAND_EXTENSION_REGISTRY
        events.append("manifest")
        if failure == "manifest":
            raise RuntimeError("manifest bootstrap failed")
        return {"extension:fixture": "a" * 64}

    monkeypatch.setattr(compatibility, "load_hook_compatibility_surface", load_surface)
    monkeypatch.setattr(importlib, "import_module", import_module)
    monkeypatch.setattr(manifests, "catalog_target_manifest", manifest)
    return events


@pytest.mark.parametrize(
    ("mode", "oracle", "test_context", "diagnostic"),
    [
        ("auto", "1", True, "1"),
        ("force", "1", True, "1"),
        ("off", "0", True, "1"),
        ("off", "1", False, "1"),
        ("shadow", "1", True, "0"),
    ],
)
def test_unadmitted_oracle_does_not_prepare_code_or_manifest(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    oracle: str,
    test_context: bool,
    diagnostic: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", oracle)
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", diagnostic)
    if not test_context:
        monkeypatch.delenv("HOL_GUARD_TEST_MODE", raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    events = _prepare_spies(monkeypatch)

    entrypoint._prepare_hook_evaluator_oracle()

    assert events == []


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_admitted_preparation_finishes_before_ready_without_creating_guard_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    # The main entry sets this internally; preserve the surrounding test env.
    monkeypatch.setenv(entrypoint._HOOK_SQLITE_TIMEOUT_ENV, "250")
    events = _prepare_spies(monkeypatch)
    connection = StoppedConnection(events)
    guard_home = tmp_path / "absent-guard-home"

    entrypoint._hook_evaluator_main(cast(Connection, cast(object, connection)), str(guard_home))

    assert events == ["compatibility", "render", "manifest", "ready"]
    assert connection.sent == [("ready", None)]
    assert not guard_home.exists()


@pytest.mark.parametrize("failure", ["compatibility", "render", "manifest"])
def test_failed_preparation_cannot_advertise_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv(entrypoint._HOOK_SQLITE_TIMEOUT_ENV, "250")
    events = _prepare_spies(monkeypatch, failure=failure)
    connection = StoppedConnection(events)
    guard_home = tmp_path / "absent-guard-home"

    with pytest.raises(RuntimeError, match="bootstrap"):
        entrypoint._hook_evaluator_main(cast(Connection, cast(object, connection)), str(guard_home))

    assert connection.sent == []
    assert "ready" not in events
    assert not guard_home.exists()


def test_prepared_manifest_is_reused_without_returning_mutable_cached_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    original_manifest = manifests.catalog_target_manifest
    original_build = manifests._build_catalog_target_manifest
    events = _prepare_spies(monkeypatch)
    monkeypatch.setattr(manifests, "catalog_target_manifest", original_manifest)
    monkeypatch.setattr(manifests, "_manifest_cache", None)
    built: list[CommandSafetyExtensionRegistry] = []

    def build(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        built.append(registry)
        return original_build(registry)

    monkeypatch.setattr(manifests, "_build_catalog_target_manifest", build)
    entrypoint._prepare_hook_evaluator_oracle()
    first = original_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert first
    expected = dict(first)
    first.clear()
    second = original_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert second == expected
    assert built == [BUILT_IN_COMMAND_EXTENSION_REGISTRY]
    assert events == ["compatibility", "render"]
