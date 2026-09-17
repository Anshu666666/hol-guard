"""Current enforcement observations remain distinct from runtime capability admission."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from codex_plugin_scanner.guard.policy_canonical_rollout import canonical_runtime_posture
from codex_plugin_scanner.guard.runtime import runner
from tests.test_policy_bundle_v2 import _verification_key
from tests.test_policy_bundle_v2_runtime_admission import _seed_v2_admission_store

_TARGET_CAPABILITY = "policy-extension-targets.v1"
_MANAGED_FLAGS = (
    "GUARD_EXTENSION_CATALOG_SYNC_V1",
    "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
    "GUARD_POLICY_EXTENSION_TARGETS_V1",
)


@pytest.mark.parametrize(
    "contract,protected,negotiated,required,rollout,lane,reason,effective",
    [
        (None, False, frozenset(), None, "1", "legacy", None, False),
        ("guard-policy-bundle.v1", False, frozenset(), None, "1", "legacy", None, False),
        (
            POLICY_BUNDLE_V2_CONTRACT,
            False,
            frozenset({_TARGET_CAPABILITY}),
            _TARGET_CAPABILITY,
            "1",
            "incompatible",
            "missing_protected_authority",
            False,
        ),
        (
            POLICY_BUNDLE_V2_CONTRACT,
            True,
            frozenset(),
            _TARGET_CAPABILITY,
            "1",
            "incompatible",
            "missing_negotiated_capability",
            False,
        ),
        (
            POLICY_BUNDLE_V2_CONTRACT,
            False,
            frozenset(),
            None,
            "0",
            "unverified",
            "canonical_enforcement_disabled",
            False,
        ),
        (POLICY_BUNDLE_V2_CONTRACT, False, frozenset(), None, "1", "canonical", None, True),
        (
            POLICY_BUNDLE_V2_CONTRACT,
            True,
            frozenset({_TARGET_CAPABILITY}),
            _TARGET_CAPABILITY,
            "1",
            "canonical",
            None,
            True,
        ),
    ],
)
def test_effective_enforcement_tracks_the_selected_lane_without_removing_capability_admission(
    monkeypatch: pytest.MonkeyPatch,
    contract: str | None,
    protected: bool,
    negotiated: frozenset[str],
    required: str | None,
    rollout: str,
    lane: str,
    reason: str | None,
    effective: bool,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", rollout)
    for flag in _MANAGED_FLAGS:
        monkeypatch.setenv(flag, "true")
    posture = canonical_runtime_posture(
        device_id="device-alpha",
        workspace_id="workspace-alpha",
        protected_authority=protected,
        negotiated_capabilities=negotiated,
        contract_version=contract,
        required_capability=required,
    )
    assert posture["selected_enforcement_lane"] == lane
    assert posture.get("canonical_incompatibility_reason") == reason
    assert posture["canonical_policy_enforcement_enabled"] is effective
    assert posture.get("canonical_policy_enforcement", False) is (rollout == "1")
    assert posture["canonical_rollout_percentage"] == (100 if rollout == "1" else 0)
    assert _TARGET_CAPABILITY in posture["advertised_canonical_capabilities"]
    if required is not None and (not protected or not negotiated):
        assert _TARGET_CAPABILITY not in posture["effective_canonical_capabilities"]


def test_empty_store_keeps_initial_delivery_capability_without_claiming_current_enforcement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setattr(runner, "_cloud_local_identity_payload", lambda *, observed_at: {"lastSyncedAt": observed_at})
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store = _seed_v2_admission_store(tmp_path, _verification_key(private_key, workspace_id="workspace-alpha"))
    local = runner._local_guard_runtime_session(store=store)
    wire = runner._cloud_runtime_session_payload(store, local)
    assert local["canonical_policy_enforcement_enabled"] is False
    assert local["selected_enforcement_lane"] == wire["selectedEnforcementLane"] == "legacy"
    assert local["canonical_policy_enforcement"] is True
    assert wire["canonicalPolicyEnforcement"] is True
    assert "guard-policy-bundle.v2" in wire["policyBundleVersions"]
    assert not store.get_sync_payload("policy_bundle")
