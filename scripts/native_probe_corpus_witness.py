"""Failure-only delivery context for the unchanged installed corpus gate."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress

from scripts.native_probe_request_witness import _EVENTS, _HARNESSES
from scripts.native_slo_adapter import observation_reason_code
from scripts.native_slo_contract import SAFE_ROUTE_NAMES

_MAX_ROWS = 32
_DELIVERY_FIELDS = {
    "decision": frozenset({"allow", "deny", "block", "review", "ask"}),
    "policy_action": frozenset({"allow", "warn", "block", "review", "suppress"}),
    "reason_code": frozenset(
        {
            "native_exact_safe_command",
            "native_command_control_authority_block",
            "native_command_control_mutation_in_progress",
            "native_request_invalid_json",
            "native_policy_warning",
            "native_policy_block",
            "native_policy_snapshot_unavailable",
            "native_hook_unavailable",
            "output_secret_match",
        }
    ),
}


def delivery_diagnostic(response: Mapping[str, object]) -> dict[str, object]:
    """Preserve the probe's existing per-response diagnostic projection."""
    result: dict[str, object] = {}
    for field, choices in _DELIVERY_FIELDS.items():
        value = response.get(field)
        result[field] = value if isinstance(value, str) and value in choices else (None if value is None else "other")
    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, Mapping) else None
    if not isinstance(permission, str):
        permission = None
    result["permission_decision"] = permission if permission in {None, "allow", "deny", "ask"} else "other"
    return result


def _bounded_count(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= _MAX_ROWS else None


def _emit(report: dict[str, object]) -> None:
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)


class InstalledCorpusDeliveryWitness:
    """Retain bounded delivery fields without attributing native decisions."""

    def __init__(self) -> None:
        self._rows: list[dict[str, object]] = []
        self._seen = self._projection_errors = 0

    def record(self, harness: str, event: str, response: Mapping[str, object], *, allowed: bool) -> None:
        self._seen += 1
        if len(self._rows) >= _MAX_ROWS:
            return
        try:
            row = delivery_diagnostic(response)
            reason = observation_reason_code(response)
            if reason != "other":
                row["reason_code"] = reason
            elif row["reason_code"] is None:
                row["reason_code"] = "other"
            action = response.get("model_output_action")
            continue_value = response.get("continue")
            row.update(
                harness=harness if harness in _HARNESSES else "other",
                event=event if event in _EVENTS else "other",
                delivered_allowed=allowed if type(allowed) is bool else None,
                continue_value=continue_value if type(continue_value) is bool else None,
                model_action=action
                if isinstance(action, str)
                and action in {"allow_original", "replace_with_reviewed_excerpt", "block", "not_applicable"}
                else "other",
            )
            self._rows.append(row)
        except BaseException:
            # Observing a response must not change the original validation.
            self._projection_errors += 1

    def report(self, *, expected: object, worker_stats: object) -> dict[str, object]:
        raw = worker_stats.get("routes") if isinstance(worker_stats, Mapping) else None
        routes = {
            route: _bounded_count(raw.get(route)) if isinstance(raw, Mapping) else None
            for route in sorted(SAFE_ROUTE_NAMES)
        }
        return {
            "schema": "hol-guard.installed-corpus-delivery-failure.v1",
            "stage": "aggregate_validation",
            "expected": _bounded_count(expected),
            "responses_seen": _bounded_count(self._seen),
            "retained": len(self._rows),
            "truncated": self._seen > _MAX_ROWS,
            "projection_errors": _bounded_count(self._projection_errors),
            "aggregate_routes": routes,
            "rows": [dict(row) for row in self._rows],
            "delivery_only": True,
            "per_request_native_route_proven": False,
            "cause_proven": False,
        }

    @contextmanager
    def aggregate_validation(self, *, expected: object, worker_stats: object) -> Iterator[None]:
        """Keep the exact original exception even if diagnostic emission fails."""
        try:
            yield
        except BaseException:
            with suppress(BaseException):
                _emit(self.report(expected=expected, worker_stats=worker_stats))
            raise
