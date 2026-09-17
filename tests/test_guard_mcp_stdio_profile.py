"""The benchmark must exercise forwarding, freshness and approvals, not skip them."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "guard_mcp_stdio_profile", Path(__file__).resolve().parents[1] / "scripts" / "profile_guard_mcp_session.py"
)
assert SPEC and SPEC.loader
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


def test_real_stdio_catalog_modes_preserve_complete_trace_and_refresh() -> None:
    optimized = profile.run_case(catalog_size=10, payload_bytes=16384, samples=2, profile=True, refresh_every=1)
    uncached = profile.run_case(catalog_size=10, payload_bytes=16384, samples=2, uncached=True, refresh_every=1)
    expected = optimized["correctness"]
    assert expected["exact_response_trace_sha256"] == uncached["correctness"]["exact_response_trace_sha256"]
    assert expected["forwarded_ids_exact"] is True
    assert expected["accepted"] == 3
    assert expected["notifications"] == {"notifications/progress": 3, "notifications/tools/list_changed": 2}
    assert len(expected["catalog_generations"]) == 3
    assert expected["quiet_barrier_seconds"] == 0.005
    assert optimized["exclusive_phases"]["prewrite_quiet_barrier"]["calls"] == 2
    assert optimized["memory"]["max_processes"] >= 2
    encoded = json.dumps(optimized)
    assert "guard-mcp-profile-" not in encoded
    assert "xxxxxxxx" not in encoded


@pytest.mark.parametrize("approval", ["accept", "cancel", "invalidate"])
def test_real_stdio_approval_wait_preserves_outcome_and_no_replay(approval: str) -> None:
    result = profile.run_case(
        catalog_size=10, payload_bytes=256, samples=1, profile=True, approval=approval, approval_delay_ms=25
    )
    correctness = result["correctness"]
    assert correctness["errors"] == 0
    assert correctness["forwarded_ids_exact"] is True
    assert correctness[{"accept": "accepted", "cancel": "cancelled", "invalidate": "invalidated"}[approval]] == 2
    assert result["exclusive_phases"]["inline_approval_wait"]["calls"] == 1
    if approval != "accept":
        assert correctness["accepted"] == 0
    if approval == "invalidate":
        assert correctness["notifications"]["notifications/tools/list_changed"] == 2
