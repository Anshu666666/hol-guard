"""Current signed v2 bundles retain pinned key state and validity authority."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard import policy_bundle_trusted_keys as trusted_keys
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import PolicyBundleVerificationKey
from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_payload
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)
_NOW_ISO = "2026-07-16T00:00:00Z"
_WORKSPACE = "workspace-alpha"


@pytest.fixture(scope="module")
def signed_v2() -> tuple[dict[str, object], PolicyBundleVerificationKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id=_WORKSPACE)
    return _signed_bundle(private_key, key), key


@pytest.fixture(autouse=True)
def local_anchor_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trusted_keys, "managed_policy_bundle_verification_keys", lambda: (False, ()))


def _sync(
    bundle: dict[str, object],
    anchor: PolicyBundleVerificationKey,
    advertised: PolicyBundleVerificationKey,
) -> tuple[dict[str, object] | None, str | None, tuple[PolicyBundleVerificationKey, ...]]:
    return trusted_keys.validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [anchor.to_dict()]},
        sync_payload={"policyBundleVerificationKeys": [advertised.to_dict()]},
        expected_workspace_id=_WORKSPACE,
        now=_NOW.timestamp(),
    )


@pytest.mark.parametrize("entrypoint", ["direct", "sync"])
def test_current_signed_v2_bundle_rejects_a_grace_key(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey], entrypoint: str
) -> None:
    bundle, key = signed_v2
    grace_key = replace(key, state="grace")
    if entrypoint == "direct":
        validated, reason = validated_policy_bundle_v2_payload(
            bundle, trusted_verification_keys=(grace_key,), anchored_verification_keys=(grace_key,), now=_NOW
        )
    else:
        validated, reason, _ = _sync(bundle, grace_key, grace_key)
    assert validated is None
    assert reason == "untrusted_signing_key"


@pytest.mark.parametrize(
    "restriction",
    [
        {"state": "grace"},
        {"state": "revoked"},
        {"valid_until": "2026-07-15T23:59:59Z"},
        {"valid_from": "2026-07-16T00:00:01Z"},
    ],
    ids=["grace", "revoked", "expired", "not-yet-valid"],
)
def test_sync_metadata_cannot_restore_a_restricted_pinned_v2_key(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey], restriction: dict[str, str]
) -> None:
    bundle, advertised_active_key = signed_v2
    anchor = replace(advertised_active_key, **restriction)
    validated, reason, retained_keys = _sync(bundle, anchor, advertised_active_key)
    assert validated is None
    assert reason == "untrusted_signing_key"
    assert retained_keys == (anchor,)


def test_managed_grace_anchor_cannot_be_restored_by_advertised_active_metadata(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey], monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, advertised_active_key = signed_v2
    anchor = replace(advertised_active_key, state="grace")
    monkeypatch.setattr(trusted_keys, "managed_policy_bundle_verification_keys", lambda: (True, (anchor,)))
    validated, reason, retained_keys = trusted_keys.validate_synced_policy_bundle(
        bundle,
        stored_keyring={},
        sync_payload={"policyBundleVerificationKeys": [advertised_active_key.to_dict()]},
        expected_workspace_id=_WORKSPACE,
        now=_NOW.timestamp(),
    )
    assert validated is None
    assert reason == "untrusted_signing_key"
    assert retained_keys == (anchor,)


@pytest.mark.parametrize("boundary", ["valid_from", "valid_until"])
def test_active_v2_anchor_keeps_inclusive_validity_boundaries(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey], boundary: str
) -> None:
    bundle, key = signed_v2
    anchor = replace(key, **{boundary: _NOW_ISO})
    validated, reason, _ = _sync(bundle, anchor, key)
    assert validated == bundle
    assert reason is None


def test_active_pinned_v2_key_keeps_grace_rotation_metadata_compatible(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey],
) -> None:
    bundle, anchor = signed_v2
    validated, reason, retained_keys = _sync(bundle, anchor, replace(anchor, state="grace"))
    assert validated == bundle
    assert reason is None
    assert retained_keys == (anchor,)


def test_existing_workspace_unscoped_v2_anchor_remains_compatible(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey],
) -> None:
    bundle, key = signed_v2
    legacy_key = replace(key, workspace_id=None)
    validated, reason, _ = _sync(bundle, legacy_key, legacy_key)
    assert validated == bundle
    assert reason is None


def test_expired_advertised_key_still_fails_with_an_active_anchor(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey],
) -> None:
    bundle, anchor = signed_v2
    advertised = replace(anchor, valid_until="2026-07-15T23:59:59Z")
    validated, reason, _ = _sync(bundle, anchor, advertised)
    assert validated is None
    assert reason == "untrusted_signing_key"


def test_active_anchor_does_not_make_a_bad_v2_signature_valid(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey],
) -> None:
    original, key = signed_v2
    bundle = deepcopy(original)
    cast(dict[str, object], bundle["verifier"])["signature"] = "AA=="
    validated, reason, _ = _sync(bundle, key, key)
    assert validated is None
    assert reason == "bundle_signature_invalid"


def test_an_advertised_rotated_key_does_not_bootstrap_its_own_anchor(
    signed_v2: tuple[dict[str, object], PolicyBundleVerificationKey],
) -> None:
    _, anchor = signed_v2
    rotated_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated_key = _verification_key(rotated_private_key, key_id="policy-v2-rotated", workspace_id=_WORKSPACE)
    bundle = _signed_bundle(rotated_private_key, rotated_key)
    validated, reason, _ = _sync(bundle, anchor, rotated_key)
    assert validated is None
    assert reason == "untrusted_signing_key"
