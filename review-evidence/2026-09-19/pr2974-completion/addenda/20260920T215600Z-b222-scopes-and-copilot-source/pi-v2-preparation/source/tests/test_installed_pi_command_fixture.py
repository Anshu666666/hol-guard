"""Real disposable authority, with daemon/native execution explicitly modeled."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_pi_output as probe
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_command_fixture import prepare_empty_command_authority, verify_empty_command_authority


@pytest.mark.parametrize("provision", (False, True), ids=("default-unchanged", "explicit-command-corpus"))
def test_only_explicit_command_corpus_provisions_real_authority_before_daemon(tmp_path, monkeypatch, provision):
    events = []

    def daemon(store, **kwargs):
        view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
        expected = AuthorityHealth.PROTECTED if provision else AuthorityHealth.UNENROLLED
        assert view.health is expected and not view.layers
        if provision:
            assert verify_empty_command_authority(store)["verified_health"] == "protected"
        events.append("constructed")
        return SimpleNamespace(
            _server=SimpleNamespace(
                store=store,
                hook_worker=SimpleNamespace(
                    policy_snapshot_publisher=SimpleNamespace(
                        register_workspace=lambda workspace: events.append("registered")
                    )
                ),
            ),
            start=lambda: events.append("started"),
        )

    monkeypatch.setattr(server, "GuardDaemonServer", daemon)
    result = probe._start_installed_daemon(
        guard_home=tmp_path / "guard",
        home=tmp_path,
        workspace=tmp_path,
        identity=SimpleNamespace(path=Path("/not-executed")),
        prepare_command_authority=provision,
    )
    assert events == ["constructed", "registered", "started"]
    if provision:
        receipt = verify_empty_command_authority(result._server.store)
        assert receipt["provisioning"] == "isolated_ci_generated_key_empty_authority"
        assert receipt["enrollment_flow"] == "not_exercised"


def test_existing_authority_is_not_reset_or_bypassed_by_fixture_opt_in(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    original = prepare_empty_command_authority(store)
    calls = []
    monkeypatch.setattr(server, "GuardDaemonServer", lambda *args, **kwargs: calls.append("daemon"))
    with pytest.raises(probe.ProbeCleanupUnsafeError) as failure:
        probe._start_installed_daemon(
            guard_home=store.guard_home,
            home=tmp_path,
            workspace=tmp_path,
            identity=SimpleNamespace(path=Path("/not-executed")),
            prepare_command_authority=True,
        )
    assert not calls and isinstance(failure.value.__cause__, RuntimeError)
    assert "freshly unenrolled" in str(failure.value.__cause__)
    assert verify_empty_command_authority(store) == original
