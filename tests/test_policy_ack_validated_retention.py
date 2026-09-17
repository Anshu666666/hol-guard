"""Generic ACK refresh preserves validated evidence and exact identity boundaries."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.policy_bundle_ack_contract import validated_generic_policy_acknowledgement
from codex_plugin_scanner.guard.policy_bundle_delivery import effective_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

_BUNDLE = {
    "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
    "workspaceId": "workspace-alpha",
    "bundleVersion": 8,
    "bundleHash": "sha256:" + "a" * 64,
}


def _observation(status: str = "validated") -> dict[str, object]:
    return {
        **_BUNDLE,
        "deviceId": "device-alpha",
        "sequence": 2,
        "status": status,
        "observedAt": "2026-07-15T12:01:00Z",
        "errorCode": "temporarily_unavailable" if status in {"failed", "offline"} else None,
    }


def _refresh(previous: dict[str, object], *, applied: bool = False) -> dict[str, object]:
    return effective_policy_bundle_acknowledgement(
        device_id="device-alpha",
        device_name="Guard",
        effective_policy_bundle=_BUNDLE,
        validated_policy_bundle=_BUNDLE,
        validated_delivery=None,
        stored_acknowledgement=previous,
        synced_at="2026-07-15T12:02:00Z",
        applied=applied,
    )


@pytest.mark.parametrize("status", ["validated", "applied"])
def test_unapplied_refresh_keeps_existing_exact_progress_without_rewriting_observation_time(status: str) -> None:
    previous = _observation(status)
    assert validated_generic_policy_acknowledgement(previous) == (previous, None)
    refreshed = _refresh(previous)
    assert refreshed == previous
    assert refreshed is not previous
    assert validated_generic_policy_acknowledgement(refreshed, previous=previous) == (previous, None)
    assert "deliveryId" not in refreshed


def test_validated_observation_advances_only_after_application_is_confirmed() -> None:
    previous = _observation()
    refreshed = _refresh(previous, applied=True)
    assert refreshed["status"] == "applied"
    assert refreshed["sequence"] == 3
    assert refreshed["observedAt"] == "2026-07-15T12:02:00Z"
    assert validated_generic_policy_acknowledgement(refreshed, previous=previous) == (refreshed, None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("workspaceId", "workspace-other"),
        ("deviceId", "device-other"),
        ("bundleVersion", 9),
        ("bundleHash", "sha256:" + "b" * 64),
    ],
)
def test_validated_observation_for_a_different_identity_never_carries_progress(field: str, value: object) -> None:
    previous = {**_observation(), field: value}
    refreshed = _refresh(previous)
    assert refreshed["status"] == "received"
    assert refreshed["sequence"] == 1
    assert refreshed["deviceId"] == "device-alpha"
    assert all(refreshed[key] == value for key, value in _BUNDLE.items())
    assert validated_generic_policy_acknowledgement(refreshed) == (refreshed, None)


@pytest.mark.parametrize("status", ["received", "failed", "offline"])
def test_retryable_observation_can_report_a_new_receipt(status: str) -> None:
    previous = _observation(status)
    refreshed = _refresh(previous)
    assert refreshed["status"] == "received"
    assert refreshed["sequence"] == 3
    assert refreshed["errorCode"] is None
    assert validated_generic_policy_acknowledgement(refreshed, previous=previous) == (refreshed, None)


def test_malformed_previous_observation_cannot_claim_validated_progress() -> None:
    refreshed = _refresh({**_observation(), "sequence": True})
    assert refreshed["status"] == "received"
    assert refreshed["sequence"] == 1
    assert validated_generic_policy_acknowledgement(refreshed) == (refreshed, None)
