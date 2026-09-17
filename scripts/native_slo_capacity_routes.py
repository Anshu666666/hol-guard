"""Whole-wave route evidence; counters never identify an individual response."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import cast

from scripts.native_slo_adapter import Observation
from scripts.native_slo_capacity_witness import capacity_none_report

_ROUTES = frozenset({"native_resident", "native_fail_safe", "native_oneshot", "python_semantic"})


@dataclass(frozen=True)
class CapacityRouteEvidence:
    attempted: int
    completed: int
    errors: int
    delivered_allowed: int
    explicit_overloaded: int
    unclassified_responses: int
    engine_routes: dict[str, int]
    engine_bypassed: int | None
    bookkeeping_complete: bool
    native_overloads: int | None
    failures: tuple[str, ...]
    none_witness: dict[str, object] | None = field(default=None, compare=False)

    def qualifies(self, *, expected: int, allow_overload: bool) -> bool:
        return (
            not self.failures
            and self.bookkeeping_complete
            and self.attempted == self.completed == expected
            and self.errors == 0
            and (allow_overload or self.explicit_overloaded == 0)
        )

    def report(self) -> dict[str, object]:
        fields = asdict(self)
        fields.pop("none_witness")
        if self.none_witness is not None:
            fields["none_witness"] = capacity_none_report(self.none_witness)
        return {
            "route_attribution": "isolated_whole_wave_counter_conservation",
            "per_request_native_route_proven": False,
            **fields,
            "responses_received": self.completed,
            "terminal_outcomes": self.completed + self.errors,
            "accounted": self.attempted == self.completed + self.errors,
        }


def capacity_route_evidence(
    observations: Sequence[Observation],
    *,
    attempted: int,
    errors: int,
    before: Mapping[str, object],
    after: Mapping[str, object],
    bookkeeping_complete: bool,
    native_overloads: int | None,
    none_witness: dict[str, object] | None = None,
) -> CapacityRouteEvidence:
    failures: list[str] = []
    routes: dict[str, int] = {}
    valid = all(
        isinstance(name, str) and type(value) is int and value >= 0
        for counts in (before, after)
        for name, value in counts.items()
    )
    if not valid:
        failures.append("invalid_route_counter")
    else:
        for name in before.keys() | after.keys():
            difference = cast(int, after.get(name, 0)) - cast(int, before.get(name, 0))
            if difference < 0:
                failures.append("route_counter_regressed")
            if difference:
                label = name if name in _ROUTES else "unrecognized"
                routes[label] = routes.get(label, 0) + difference
    allowed = sum(item.allowed and not item.overloaded for item in observations)
    overloaded = sum(item.overloaded and not item.allowed for item in observations)
    unclassified = len(observations) - allowed - overloaded
    if not bookkeeping_complete:
        failures.append("route_bookkeeping_incomplete")
    if (
        type(attempted) is not int
        or not 1 <= attempted <= 64
        or type(errors) is not int
        or errors != 0
        or len(observations) != attempted
    ):
        failures.append("attempt_completion_mismatch")
    if unclassified:
        failures.append("unclassified_delivered_response")
    if set(routes) - {"native_resident", "native_fail_safe"}:
        failures.append("unexpected_engine_route")
    if routes.get("native_resident", 0) != allowed:
        failures.append("resident_count_mismatch")
    fail_safe = routes.get("native_fail_safe", 0)
    if type(native_overloads) is not int or native_overloads < 0 or native_overloads != fail_safe:
        failures.append("native_overload_route_mismatch")
    if fail_safe > overloaded:
        failures.append("noncapacity_fail_safe_count")
    bypassed = overloaded - fail_safe if valid and 0 <= fail_safe <= overloaded else None
    if bypassed is None or sum(routes.values()) + bypassed != len(observations):
        failures.append("route_counter_conservation_failed")
    return CapacityRouteEvidence(
        attempted,
        len(observations),
        errors,
        allowed,
        overloaded,
        unclassified,
        routes,
        bypassed,
        bookkeeping_complete,
        native_overloads,
        tuple(dict.fromkeys(failures)),
        none_witness,
    )


__all__ = ["CapacityRouteEvidence", "capacity_route_evidence"]
