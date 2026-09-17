"""Sync summary statuses for policy application vs fallback/retention."""

from __future__ import annotations

from collections.abc import Mapping

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT


def policy_application_status(
    *,
    policy_application_committed: bool,
    validated_policy_bundle: Mapping[str, object] | None,
    canonical_enforcement: bool,
    policy_bundle_field_provided: bool,
    activation_last_error: Mapping[str, object],
    retained_authority: bool,
) -> str:
    """Report whether this sync applied, fell back, retained, or has no authority."""

    if policy_application_committed and validated_policy_bundle is not None:
        is_v2 = validated_policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
        if is_v2 and not canonical_enforcement:
            return "fallback"
        return "applied"
    if retained_authority:
        return "retained"
    if activation_last_error or not policy_bundle_field_provided:
        return "no_authority"
    return "rejected"


def stored_policy_authority_present(*, current: object, last_good: object) -> bool:
    return _non_empty_mapping(current) or _non_empty_mapping(last_good)


def _non_empty_mapping(value: object) -> bool:
    return isinstance(value, Mapping) and bool(value)


__all__ = ["policy_application_status", "stored_policy_authority_present"]
