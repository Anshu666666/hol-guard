from __future__ import annotations

import json

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as claude_transport
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as codex_bridge
from codex_plugin_scanner.guard.native_hook_edge import _trusted_package_shim_managers


@pytest.mark.parametrize("bridge", (codex_bridge, claude_transport))
def test_bridge_replaces_untrusted_transport_path_with_process_path(
    bridge: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "/guard/package-shims/bin:/usr/bin")
    encoder = getattr(bridge, "_with_transport_environment")
    payload = json.loads(
        encoder(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "_hol_guard_transport": {"path": "/tmp/attacker"},
                }
            )
        )
    )

    assert payload["_hol_guard_transport"] == {
        "path": "/guard/package-shims/bin:/usr/bin"
    }


def test_trusted_package_shim_manager_requires_transport_path_and_intact_active_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _trusted_package_shim_managers(
        guard_home=tmp_path, home_dir=tmp_path, cwd=tmp_path, transport_metadata=None
    ) == []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.package_shim_status",
        lambda _context, *, path_env: {
            "manager_details": [
                {"manager": "bunx", "integrity": "ok", "path_active": True},
                {"manager": "npx", "integrity": "tampered", "path_active": True},
                {"manager": "npm", "integrity": "ok", "path_active": True},
            ]
        },
    )
    assert _trusted_package_shim_managers(
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        transport_metadata={"path": "/guard/package-shims/bin:/usr/bin"},
    ) == ["bunx"]
