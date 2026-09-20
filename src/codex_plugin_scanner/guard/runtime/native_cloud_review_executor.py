"""Deliver an opaque native proof to the original waiting hook."""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import datetime, timezone

from ..native_live_approval_state import stage_native_job
from ..store import GuardStore


def execute_native_cloud_review(store: GuardStore, job: Mapping[str, object], *, now: str) -> dict[str, object]:
    request_id, receipt_id = stage_native_job(store, job, now=now)
    # Same five-second observation budget as ordinary continuation. Staging an
    # assertion is not application or an allow result; only the live hook may
    # claim Rust authority and commit the terminal effect.
    deadline = time.monotonic() + 5.0
    resumed = False
    while True:
        request = store.get_approval_request(request_id)
        resume = store.get_request_resume(request_id)
        resumed = bool(
            isinstance(request, dict)
            and request.get("status") == "resolved"
            and request.get("resolution_action") == "allow"
            and request.get("reason") == "native_approval_v4_consumed"
            and isinstance(resume, dict)
            and resume.get("continuation_status") == "resumed"
        )
        if resumed or time.monotonic() >= deadline:
            break
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    observed = datetime.now(timezone.utc).isoformat()
    return {
        "data": {
            "applicationStatus": "applied" if resumed else "not_applicable",
            "applicationReason": None if resumed else "native_proof_pending",
            "applicationUpdatedAt": observed,
            "continuationStatus": "resumed" if resumed else "waiting",
            "continuationReason": "live_hook_completed" if resumed else "native_proof_pending",
            "continuationUpdatedAt": observed,
            "localRequestId": request_id,
            "receiptId": receipt_id,
            "remoteDecision": "allow",
            "status": "completed",
        },
        "generatedAt": observed,
    }
