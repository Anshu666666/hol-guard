"""Finite proof from an already-failed installed launcher authority check."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any

from scripts.native_slo_contract import SAFE_ROUTE_NAMES
from scripts.native_slo_failure import FixtureFailureError

_REASONS = {
    "output_scan_allow": "scan_allow",
    "output_secret_match": "credential_match",
    "native_policy_warning": "native_policy_warning",
    "native_policy_blocked": "native_policy_blocked",
    "native_policy_unavailable": "native_policy_unavailable",
    "native_policy_not_ready": "native_policy_not_ready",
    "native_policy_expired": "native_policy_expired",
    "native_command_control_fence_unavailable": "native_control_fence_unavailable",
    "native_review_required": "native_review_required",
    "native_overloaded": "native_overloaded",
    "native_degraded_emergency_safe": "native_degraded_emergency_safe",
    "no_output_to_review": "nothing_to_review",
    "native_post_tool_unavailable": "native_post_tool_unavailable",
    "native_hook_edge_unavailable": "native_hook_edge_unavailable",
    "native_hook_edge_invalid_response": "native_hook_edge_invalid_response",
    "native_policy_snapshot_not_current": "native_policy_snapshot_not_current",
    "native_policy_snapshot_expired": "native_policy_snapshot_expired",
    "guard_daemon_unavailable": "guard_daemon_unavailable",
    "guard_daemon_authenticated_control_plane_failure": "authenticated_control_plane_failure",
}


def _known(value: object, options: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in options else "other"


def _count(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 1_000_000_000 else None


def _capture(value: object) -> dict[str, object]:
    # The containment API already returns bounded decoded strings. This hash
    # identifies their UTF-8 re-encoding, not undisclosed original pipe bytes.
    if not isinstance(value, str) or len(value) > 2 * 1024 * 1024:
        return {"available": False}
    encoded = value.encode("utf-8", errors="replace")
    return {"available": True, "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


class LauncherAuthorityFailureError(FixtureFailureError):
    def __init__(
        self,
        *,
        before: Mapping[str, object],
        after: Mapping[str, object],
        route: str,
        response: Mapping[str, object],
        completed: Any,
        sample: int,
        case: str,
        elapsed_ms: float,
    ) -> None:
        reason = response.get("reason_code")
        super().__init__(
            {
                "schema": "hol-guard.native-qualification-failure.v1",
                "detail_schema": "hol-guard.installed-launcher-authority-failure.v1",
                "reason": "installed_launcher_authority_missing",
                "boundary": "INSTALLED_LAUNCHER",
                "harness": "claude-code",
                "event": "PostToolUse",
                "case": {"benign": "benign", "secret": "credential"}.get(case, "other"),
                "sample": sample if type(sample) is int and -1 <= sample <= 100_000 else None,
                "elapsed_ms": min(60_000, max(0, int(elapsed_ms))) if math.isfinite(elapsed_ms) else None,
                "route": _known(route, SAFE_ROUTE_NAMES),
                "routes_before": {name: _count(before.get(name)) for name in sorted(SAFE_ROUTE_NAMES)},
                "routes_after": {name: _count(after.get(name)) for name in sorted(SAFE_ROUTE_NAMES)},
                "successful_exit": completed.returncode == 0,
                "timed_out": completed.timed_out is True,
                "containment_failed": completed.containment_failed is True,
                "capture_limit_exceeded": completed.output_limit_exceeded is True,
                "capture_identity": "utf8_reencoded_contained_capture",
                "stdout": _capture(completed.stdout),
                "stderr": _capture(getattr(completed, "stderr", None)),
                "response_fields": sorted(
                    name
                    for name in ("decision", "policy_action", "reason_code", "hookSpecificOutput", "systemMessage")
                    if name in response
                ),
                "decision": _known(response.get("decision"), frozenset({"allow", "deny", "block"})),
                "policy_action": _known(response.get("policy_action"), frozenset({"allow", "warn", "block", "review"})),
                "delivery": _known(
                    response.get("model_output_action"), frozenset({"allow_original", "block", "not_applicable"})
                ),
                "response_reason": _REASONS.get(reason, "other") if isinstance(reason, str) else "other",
                "per_request_native_route_proven": False,
                "qualification_complete": False,
            }
        )
        self.args = (
            "installed launcher did not use native resident authority: " + json.dumps(self.detail, sort_keys=True),
        )
