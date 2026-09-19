"""Source-bound consent for the inventory-versus-receipt scheduling cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.optional_uploads import SYNTHETIC_WORKSPACE_ID
from tests.support.receipt_transport import confirm_existing_legacy_uploads
from tests.test_aibom_operation_authority import _context, _selected
from tests.test_oauth_connection_authority import _inputs


def inventory_receipt_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Preserve the shared credential/key/expiry fixture, with a canonical receipt workspace.
    inputs = {**_inputs(), "workspace_id": SYNTHETIC_WORKSPACE_ID}
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False, source="default")
    store.set_oauth_local_credentials(**inputs)
    confirm_existing_legacy_uploads(store, monkeypatch)
    context = _context(store, tmp_path)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir(parents=True)
    (context.home_dir / ".codex").mkdir(parents=True)
    (context.home_dir / ".codex/config.toml").write_text('[mcp_servers.generic]\ncommand="node"\nargs=["server.js"]\n')
    return store, inputs, context


def selected_receipt_inventory(context: HarnessContext) -> dict[str, object]:
    return {**_selected(context), "workspace_id": SYNTHETIC_WORKSPACE_ID}
