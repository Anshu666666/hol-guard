"""Connection capture and reset operations for the existing OAuth store mixin."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Callable

from .oauth_connection_authority import OAuthConnectionSnapshot
from .runtime.extension_control_authority import ExtensionControlAuthorityView


class StoreOAuthConnectionAuthorityMixin:
    def clear_cloud_sync_state_for_reconnect(
        self,
        *,
        now: str | None = None,
        managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
    ) -> None:
        from . import store_oauth as _oauth_api

        with self._hold_advisory_file_lock(
            path=self.guard_home / "oauth-connection-reset.lock",
            timeout_seconds=_oauth_api._OAUTH_CREDENTIAL_LOCK_TIMEOUT_SECONDS,
            poll_seconds=_oauth_api._OAUTH_CREDENTIAL_LOCK_POLL_SECONDS,
            timeout_message="Timed out waiting for the connection reset lock.",
        ):
            reset_token = _oauth_api.uuid4().hex
            with self.hold_oauth_credential_lock():
                with self._connect() as connection:
                    _oauth_api.advance_connection_epoch(
                        connection,
                        self._oauth_local_credentials_state_key,
                        now or _oauth_api._now(),
                        reset_token=reset_token,
                    )
                self.clear_review_policy_memory_state()
            self.clear_policy_bundle_authority(
                now or _oauth_api._now(),
                policy_bundle_last_error={},
                managed_controls_publish=managed_controls_publish,
            )
            self.delete_sync_payloads(
                [
                    state_key
                    for state_key in _oauth_api._GUARD_CLOUD_RESET_STATE_KEYS
                    if state_key
                    not in {
                        "managed_controls_active",
                        "managed_controls_negotiated_capabilities",
                    }
                ]
            )
            # A failed/crashed reset remains unavailable until a later serialized reset completes.
            with self.hold_oauth_credential_lock(), self._connect() as connection:
                _oauth_api.advance_connection_epoch(
                    connection,
                    self._oauth_local_credentials_state_key,
                    now or _oauth_api._now(),
                    complete_reset_token=reset_token,
                )

    def capture_oauth_connection(
        self, *, allow_primary: bool = False, allow_recoverable: bool = False
    ) -> OAuthConnectionSnapshot | None:
        """Capture credentials and their durable authority under the credential lock."""
        with self.hold_oauth_credential_lock():
            return self._capture_oauth_connection_unlocked(
                allow_primary=allow_primary, allow_recoverable=allow_recoverable
            )

    def _capture_oauth_connection_unlocked(
        self, *, allow_primary: bool = False, allow_recoverable: bool = False
    ) -> OAuthConnectionSnapshot | None:
        from . import store_oauth as _oauth_api

        credentials = self.get_oauth_local_credentials(allow_primary=allow_primary)
        if credentials is None and allow_recoverable:
            credentials = self.get_recoverable_oauth_local_credentials()
        if credentials is None:
            return None
        with self._connect() as connection:
            epoch = _oauth_api.capture_connection_epoch(
                connection, self._oauth_local_credentials_state_key, _oauth_api._now()
            )
            if epoch is None:
                return None
        return _oauth_api.OAuthConnectionSnapshot.capture(
            self._oauth_local_credentials_state_key, epoch, str(self.path.resolve()), credentials
        )

    def _clear_oauth_local_credentials_locked(
        self, *, expected_connection: OAuthConnectionSnapshot | None = None
    ) -> None:
        from . import store_oauth as _oauth_api

        with self.hold_oauth_credential_lock():
            if (
                expected_connection is not None
                and self._capture_oauth_connection_unlocked(allow_recoverable=True) != expected_connection
            ):
                raise RuntimeError("The connection changed before credentials could be cleared.")
            self._clear_oauth_secret_payload_cache()
            payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
            if isinstance(payload, dict):
                secret_ref = payload.get(_oauth_api._OAUTH_LOCAL_CREDENTIALS_REF_KEY)
                if isinstance(secret_ref, str) and secret_ref:
                    self._oauth_secret_store.delete_secret(secret_ref)
                    if _oauth_api.sys.platform == "darwin":
                        legacy_fallback = _oauth_api.EncryptedFileSecretStore(self.guard_home)
                        legacy_path = legacy_fallback._path_for(secret_ref)
                        with _oauth_api.suppress(OSError):
                            legacy_path.unlink()
            self._delete_sync_payloads_unlocked([self._oauth_local_credentials_state_key])
            self.clear_review_policy_memory_state()
            # A capability bound to one OAuth grant must not survive disconnect for a later grant.
            self.delete_sync_payloads(list(_oauth_api._GUARD_CLOUD_COMMAND_STATE_KEYS))
