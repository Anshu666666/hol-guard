"""Preserve authority callbacks in legacy controlled OAuth refresh fixtures."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial


def validating_refresh_fixture(
    fake: Callable[..., dict[str, object]],
) -> Callable[..., dict[str, object]]:
    """Keep the production pre-request and completed-attempt validation boundary."""

    @wraps(fake)
    def refresh(
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        dpop_key_material: GuardDpopKeyMaterial,
        credential_reloader: Callable[[], object] | None = None,
        request_validator: Callable[[], None] | None = None,
        completion_validator: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        if request_validator is not None:
            request_validator()
        try:
            result = fake(
                token_endpoint=token_endpoint,
                client_id=client_id,
                refresh_token=refresh_token,
                dpop_key_material=dpop_key_material,
                credential_reloader=credential_reloader,
            )
        except Exception:
            if completion_validator is not None:
                completion_validator()
            raise
        if request_validator is not None:
            request_validator()
        return result

    return refresh
