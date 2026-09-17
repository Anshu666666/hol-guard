"""Compatibility identity and payload routing avoid unrelated implementations."""

from __future__ import annotations

import builtins
import importlib
from collections.abc import Mapping, Sequence
from typing import cast

import pytest

from codex_plugin_scanner.guard import adapters
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.cli import commands_hook_compatibility as compatibility
from codex_plugin_scanner.guard.cli import commands_support_runtime_resolution as resolution

_PREPARERS = (
    "adapters.cline_hook_payload",
    "adapters.cursor_hooks",
    "adapters.grok_hooks",
    "adapters.zcode_hooks",
)


def test_runtime_identity_does_not_load_adapter_implementations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical identity loaded adapter implementations")

    adapters._adapters.cache_clear()
    monkeypatch.setattr(adapters, "import_module", forbidden)
    for contract in HARNESS_CONTRACTS:
        for alias in (contract.harness, *contract.install_aliases):
            assert resolution._canonical_harness_name(alias) == contract.harness
    for unknown in ("other-private-harness", "PI", " pi ", "claude_code", ""):
        assert resolution._canonical_harness_name(unknown) == unknown


@pytest.mark.parametrize("harness", ["pi", "omp", "codex", "claude", "other"])
def test_unrelated_payload_does_not_import_harness_preparers(harness: str, monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def observed_import(
        name: str,
        globals: Mapping[str, object] | None = None,  # noqa: A002 - preserve __import__ keyword names
        locals: Mapping[str, object] | None = None,  # noqa: A002 - preserve __import__ keyword names
        fromlist: Sequence[str] | None = (),
        level: int = 0,
    ) -> object:
        assert not name.endswith(_PREPARERS), "unrelated payload imported a harness preparer"
        return cast(object, original_import(name, globals, locals, fromlist, level))

    monkeypatch.setattr(builtins, "__import__", observed_import)
    payload: dict[str, object] = {"hook_event_name": "PreToolUse", "private-input": "retained"}
    assert compatibility.prepare_compatibility_hook_payload(payload, harness=harness) is payload


@pytest.mark.parametrize(
    ("harness", "module_suffix", "function_name"),
    [
        ("cline-vscode", "adapters.cline_hook_payload", "prepare_cline_hook_payload"),
        ("cursor", "adapters.cursor_hooks", "prepare_cursor_hook_payload"),
        ("xai-grok", "adapters.grok_hooks", "prepare_grok_hook_payload"),
        ("zai-zcode", "adapters.zcode_hooks", "prepare_zcode_hook_payload"),
    ],
)
def test_only_selected_preparer_runs_then_normalizes_with_original_alias(
    harness: str, module_suffix: str, function_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = importlib.import_module(f"codex_plugin_scanner.guard.{module_suffix}")
    original_import = builtins.__import__
    imports: list[str] = []
    received: list[dict[str, object]] = []
    normalized: list[tuple[dict[str, object], str]] = []
    prepared: dict[str, object] = {"prepared": True}
    result: dict[str, object] = {"normalized": True}

    def observed_import(
        name: str,
        globals: Mapping[str, object] | None = None,  # noqa: A002 - preserve __import__ keyword names
        locals: Mapping[str, object] | None = None,  # noqa: A002 - preserve __import__ keyword names
        fromlist: Sequence[str] | None = (),
        level: int = 0,
    ) -> object:
        if name.endswith(_PREPARERS):
            assert name.endswith(module_suffix), "selected payload imported an unrelated preparer"
            imports.append(name)
        return cast(object, original_import(name, globals, locals, fromlist, level))

    def prepare(payload: dict[str, object]) -> dict[str, object]:
        received.append(payload)
        return prepared

    def normalize(payload: dict[str, object], *, harness: str) -> dict[str, object]:
        normalized.append((payload, harness))
        return result

    monkeypatch.setattr(module, function_name, prepare)
    monkeypatch.setattr(compatibility, "_normalize_hook_payload", normalize)
    monkeypatch.setattr(builtins, "__import__", observed_import)
    payload: dict[str, object] = {"original": True}
    assert compatibility.prepare_compatibility_hook_payload(payload, harness=harness) is result
    assert received == [payload]
    assert normalized == [(prepared, harness)]
    assert len(imports) == 1
