"""Preserve the separate platform source-denial probe outside SLO timing."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from scripts.native_slo_adapter import route_counts, route_delta
from scripts.native_slo_source_witness import source_reference_denial_witness

if TYPE_CHECKING:
    from scripts.native_slo_session import AdapterSession


def probe_source_reference_denial(
    self: AdapterSession,
    harness: str,
    event: str,
    size_class: str,
    request: Mapping[str, object],
) -> dict[str, object]:
    """Retain a platform denial proof outside every SLO sample collection."""
    from scripts.native_slo_session import _request
    from scripts.native_slo_workloads import QualificationCase, _post_expected, validate_case

    before = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
    with source_reference_denial_witness(self.daemon._server.hook_worker, request):
        response = _request(
            self.daemon,
            guard_home=self.guard_home,
            workspace=self.workspace,
            harness=harness,
            request_payload=request,
            connection=self._connection,
        )
    after = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
    route = route_delta(before, after)
    case = QualificationCase(
        f"{harness}/{event}/platform-source-denial/{size_class}",
        harness,
        event,
        "PostToolUse",
        size_class,
        request,
        _post_expected(harness, "block", "no_output_to_review"),
        "native_resident",
        "normal",
        "platform_source_reference_denial",
        0,
        0,
        "source_file_ref",
        validation_scope="platform_source_reference_denial",
    )
    validate_case(case, response, route)
    return {
        "harness": harness,
        "event": event,
        "size_class": size_class,
        "route": route,
        "reason_code": "no_output_to_review",
        "native_denial_validated": True,
        "delivered_denial_validated": True,
        "full_review": False,
        "headline_timing_eligible": False,
    }
