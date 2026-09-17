"""Contract-aware rollout-state admission for v1 and v2 policy bundles."""

from __future__ import annotations

from collections.abc import Mapping

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES = frozenset({"enforcing", "enforced", "rollback_available"})
_INACTIVE_ROLLOUT_STATES = frozenset({"draft", "simulated", "pending_approval"})


def policy_bundle_rollout_state(policy_bundle: Mapping[str, object]) -> str | None:
    """Return the live rollout state, including v2 ``payload.spec.rolloutState``."""

    if policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        payload = policy_bundle.get("payload")
        spec = payload.get("spec") if isinstance(payload, Mapping) else None
        state = spec.get("rolloutState") if isinstance(spec, Mapping) else None
        return state if isinstance(state, str) and state else None
    state = policy_bundle.get("rolloutState")
    return state if isinstance(state, str) and state else None


def policy_bundle_is_enforceable(policy_bundle: Mapping[str, object]) -> bool:
    """Return whether an authenticated rollout is intended as live authority."""

    state = policy_bundle_rollout_state(policy_bundle)
    if state is None:
        return policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
    if state in _INACTIVE_ROLLOUT_STATES:
        return False
    return state in POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES
