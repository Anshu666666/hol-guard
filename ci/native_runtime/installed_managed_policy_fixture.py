"""Signed managed controls for probes using the verified loopback TLS fixture.

Enrollment and trust remain synthetic inputs inherited from SignedPolicyFixture.
No policy authority, runtime capability, acknowledgement or receipt is seeded.
These payloads are fixture-authored, not evidence of a production builder flow.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from ci.native_runtime.installed_scoped_policy_fixture import SignedPolicyFixture
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    HOL_EXTENSION_CONTROLS_SCHEMA_VERSION,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    is_mapping,
)


class ManagedPolicyFixture(SignedPolicyFixture):
    """Deliver controls and defaults through the existing signed TLS transport."""

    def __init__(self, root: Path) -> None:
        self.negotiated_capabilities: tuple[str, ...] = ()
        super().__init__(root)

    def response_for_request(self, path: str, request: dict[str, object]) -> dict[str, object]:
        if path == "/api/guard/runtime/sessions/sync":
            session = request.get("session")
            advertised = session.get("managedControlsCapabilities") if isinstance(session, dict) else None
            supported = (
                EXTENSION_CONTROL_LAYER_CAPABILITY,
                POLICY_EXTENSION_TARGETS_CAPABILITY,
                MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
            )
            self.negotiated_capabilities = tuple(
                item for item in supported if isinstance(advertised, list) and item in advertised
            )
            return {"syncedAt": datetime.now(timezone.utc).isoformat(), "sessionsVisible": 1}
        response = super().response_for_request(path, request)
        if path == "/api/guard/receipts/sync":
            response["managedControlsCapabilities"] = list(self.negotiated_capabilities)
        return response

    def signed_managed_bundle(
        self,
        version: int,
        *,
        controls: Sequence[Mapping[str, str]] = (),
        lockdown: bool = False,
        defaults: Mapping[str, str] | None = None,
        authority_mode: str = "managed-restrictive",
    ) -> dict[str, object]:
        """Sign a rule-free payload, including deliberate parser refusal cases.

        Enabled controls are not normalized or silently removed: callers can
        deliver them to prove that actual validation refuses weaker authority.
        """
        bundle = self.signed_bundle(version)
        payload = bundle["payload"]
        assert is_mapping(payload)
        spec = payload["spec"]
        assert is_mapping(spec)
        spec["rules"] = []
        if defaults is not None:
            spec["defaults"] = dict(defaults)
        payload[HOL_EXTENSION_CONTROLS_FIELD] = {
            "schemaVersion": HOL_EXTENSION_CONTROLS_SCHEMA_VERSION,
            "authorityMode": authority_mode,
            "controls": [dict(control) for control in controls],
            **({"globalLockdown": True} if lockdown else {}),
        }
        return self.sign(bundle)
