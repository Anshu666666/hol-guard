"""Capacity identity must not load harness implementation code on ingress."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import adapters
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer


def test_capacity_identity_does_not_load_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_adapter_import(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("capacity admission attempted an adapter import")

    adapters._adapters.cache_clear()
    monkeypatch.setattr(adapters, "import_module", forbidden_adapter_import)
    for contract in HARNESS_CONTRACTS:
        for name in (contract.harness, *contract.install_aliases):
            assert _GuardDaemonHttpServer.canonical_hook_capacity_harness(name) == contract.harness
    for name in ("unknown", "PI", " pi ", "claude_code", ""):
        assert _GuardDaemonHttpServer.canonical_hook_capacity_harness(name) == "other"


def test_capacity_contract_identity_exactly_matches_adapter_aliases() -> None:
    actual = {
        alias: adapter.harness
        for adapter in adapters.list_adapters()
        for alias in (adapter.harness, *getattr(adapter, "aliases", ()))
    }
    declared = {
        alias: contract.harness
        for contract in HARNESS_CONTRACTS
        for alias in (contract.harness, *contract.install_aliases)
    }
    assert declared == actual
