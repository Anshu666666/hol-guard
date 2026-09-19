"""Real preparation and selected-source fixtures for receipt transport tests."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_preference_authority import (
    accept_workspace_preference_response,
    capture_workspace_preference_state,
)
from tests.support.network import stub_authenticated_urlopen
from tests.support.optional_uploads import assert_dpop_proof, seed_legacy_optional_uploads


class ReceiptJsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def confirm_existing_legacy_uploads(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    telemetry: bool = False,
) -> None:
    """Confirm existing credentials without resolving or refreshing their access token."""
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    (store.guard_home / "config.toml").write_text(
        f"sync = true\ntelemetry = {str(telemetry).lower()}\n", encoding="utf-8"
    )
    connection = store.capture_oauth_connection()
    assert connection is not None
    captured = capture_workspace_preference_state(store, required_connection=connection)
    accepted = accept_workspace_preference_response(
        store,
        captured,
        {"syncedAt": datetime.now(timezone.utc).isoformat(), "receiptsStored": 0},
        sent_revision=None,
    )
    assert accepted.receipt_accepted
    assert accepted.state.confirmed and accepted.state.mode == "legacy"
    assert accepted.state.connection.same_authority(connection)


@dataclass
class Receipt401Trace:
    refresh_flags: list[bool] = field(default_factory=list)
    post_attempts: int = 0
    token_requests: int = 0
    authorizations: list[str] = field(default_factory=list)


def install_receipt_401_transport(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    unauthorized_error: Callable[[], urllib.error.HTTPError],
) -> Receipt401Trace:
    key = seed_legacy_optional_uploads(store, monkeypatch, token="stale")
    trace = Receipt401Trace()
    resolve = runner._resolve_guard_sync_auth_context

    def observe_resolution(current_store: GuardStore, **kwargs: Any) -> dict[str, object]:
        trace.refresh_flags.append(kwargs.get("force_refresh", False))
        return resolve(current_store, **kwargs)

    def post(request: urllib.request.Request, timeout: float | None = None) -> ReceiptJsonResponse:
        del timeout
        assert request.data is not None
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            trace.token_requests += 1
            form = urllib.parse.parse_qs(request.data.decode())
            assert form["grant_type"] == ["refresh_token"]
            assert form["refresh_token"] == ["synthetic-refresh"]
            return ReceiptJsonResponse(
                {
                    "access_token": "fresh",
                    "refresh_token": "synthetic-refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            )
        assert request.full_url == "https://hol.org/api/guard/receipts/sync"
        payload = json.loads(request.data)
        assert len(payload["receipts"]) == 1
        trace.post_attempts += 1
        token = "stale" if trace.post_attempts == 1 else "fresh"
        headers = {name.lower(): value for name, value in request.header_items()}
        assert headers["authorization"] == f"Bearer {token}"
        trace.authorizations.append(headers["authorization"])
        assert_dpop_proof(headers["dpop"], key=key, request_url=request.full_url, token=token)
        if trace.post_attempts == 1:
            raise unauthorized_error()
        return ReceiptJsonResponse({"syncedAt": "2026-04-15T00:01:00Z", "receiptsStored": 1})

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", observe_resolution)
    stub_authenticated_urlopen(monkeypatch, post)
    return trace
