"""Retain a bounded failed warmup proof without repeating its request wave."""

from __future__ import annotations

import json

from scripts.native_slo_capacity_routes import CapacityRouteEvidence
from scripts.native_slo_failure import FixtureFailureError

_ROUTES = frozenset({"native_resident", "native_fail_safe", "native_oneshot", "python_semantic", "unrecognized"})
_FAILURES = frozenset(
    {
        "invalid_route_counter",
        "route_counter_regressed",
        "route_bookkeeping_incomplete",
        "attempt_completion_mismatch",
        "unclassified_delivered_response",
        "unexpected_engine_route",
        "resident_count_mismatch",
        "native_overload_route_mismatch",
        "noncapacity_fail_safe_count",
        "route_counter_conservation_failed",
    }
)


def _count(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


class CapacityWarmupFailureError(FixtureFailureError):
    def __init__(self, evidence: CapacityRouteEvidence, expected: int) -> None:
        source = evidence.report()
        counts = {
            key: _count(source.get(key))
            for key in (
                "attempted",
                "completed",
                "errors",
                "delivered_allowed",
                "explicit_overloaded",
                "unclassified_responses",
                "engine_bypassed",
                "native_overloads",
            )
        }
        super().__init__(
            {
                "schema": "hol-guard.native-qualification-failure.v1",
                "detail_schema": "hol-guard.native-capacity-warmup-failure.v1",
                "reason": "capacity_warmup_route_failed",
                "expected": _count(expected),
                "counts": counts,
                "engine_routes": {
                    name: _count(evidence.engine_routes[name])
                    for name in sorted(_ROUTES)
                    if name in evidence.engine_routes
                },
                "proof_failures": sorted({name if name in _FAILURES else "other" for name in evidence.failures}),
                "bookkeeping_complete": evidence.bookkeeping_complete is True,
                "allow_overload": False,
                "per_request_native_route_proven": False,
                "qualification_complete": False,
            }
        )
        self.args = (
            "native_installed_slo_failed: RSS warmup route proof failed: " + json.dumps(self.detail, sort_keys=True),
        )
