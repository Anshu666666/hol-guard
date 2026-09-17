"""Bounded failed-recovery evidence from the original observations, without retries."""

from __future__ import annotations

import json
import math

from scripts.native_slo_adapter import Observation, observation_reason_code
from scripts.native_slo_contract import SAFE_ROUTE_NAMES
from scripts.native_slo_failure import FixtureFailureError


def _observation(value: Observation) -> dict[str, object]:
    latency = value.latency_ms
    return {
        "route": value.route if value.route in SAFE_ROUTE_NAMES else "unclassified",
        "delivered_allowed": value.allowed is True,
        "explicit_overload": value.overloaded is True,
        "reason_code": observation_reason_code({"reason_code": value.reason_code}),
        "latency_ms": round(latency, 3)
        if type(latency) in (int, float) and math.isfinite(latency) and 0 <= latency <= 60_000
        else None,
    }


class RecoveryFailureError(FixtureFailureError):
    """Retain the same finite projection in a paired report and legacy CI logs."""

    def __init__(self, index: int, preparation: Observation, recovery: Observation) -> None:
        super().__init__(
            {
                "schema": "hol-guard.native-qualification-failure.v1",
                "category": "RecoveryFailureError",
                "detail_schema": "hol-guard.native-recovery-failure.v1",
                "reason": "recovery_sample_failed",
                "sample_index": index if type(index) is int and 0 <= index <= 1_000_000 else None,
                "preparation": _observation(preparation),
                "recovery": _observation(recovery),
                "qualification_complete": False,
            }
        )
        # The legacy installed SLO runner raises directly, without the paired
        # worker's error exporter. Its logs must retain the same safe evidence.
        self.args = ("qualification recovery sample failed: " + json.dumps(self.detail, sort_keys=True),)
