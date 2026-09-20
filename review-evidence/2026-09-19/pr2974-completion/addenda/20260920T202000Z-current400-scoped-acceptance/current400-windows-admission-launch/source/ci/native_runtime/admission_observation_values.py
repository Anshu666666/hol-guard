"""Closed projections of existing counters; no extra product request or wait."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from ci.native_runtime.default_auto_failure import _CODES, _HARNESS, _RECEIPTS, _ROUTES
from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    _INTEGRITY_FAIL_CLOSED_REASON_CODES,
    _REVIEW_CANNOT_FINISH_REASON_CODES,
)

REASONS = _CODES | _INTEGRITY_FAIL_CLOSED_REASON_CODES | _REVIEW_CANNOT_FINISH_REASON_CODES
REJECTIONS = frozenset({"daemon_hook_deadline_exhausted", "daemon_hook_queue_capacity", "daemon_hook_queue_bytes"})
HARNESS = _HARNESS | {"other"}
SCALARS = ("active", "queued", "retained_bytes", "admitted", "completed", "expired", "cancelled", "retries")


def integer(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("admission_counter_invalid")
    return value


def counts(value: object, allowed: frozenset[str] | set[str], *, bound: int = 64) -> dict[str, int]:
    if (type(value) is not dict and type(value) is not defaultdict) or len(value) > bound:
        raise ValueError("admission_counter_map_invalid")
    output = {}
    for key, number in dict.items(value):
        if type(key) is not str or key not in allowed:
            raise ValueError("admission_counter_key_invalid")
        output[key] = integer(number)
    return output


def failures(value: object) -> dict[str, int]:
    """Only aggregate original failure stages, never exception-class strings."""
    if (type(value) is not dict and type(value) is not defaultdict) or len(value) > 256:
        raise ValueError("admission_metric_map_invalid")
    result = {"engine": 0, "metrics": 0, "server": 0, "unknown": 0}
    for key, number in dict.items(value):
        if type(key) is not str or len(key) > 512:
            raise ValueError("admission_metric_key_invalid")
        number = integer(number)
        if key.startswith("failure:"):
            stage = key.split(":", 2)[1]
            stage = stage if stage in result else "unknown"
            result[stage] = integer(result[stage] + number)
    return result


def worker_stats(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("admission_worker_stats_invalid")
    return {
        "routes": counts(value.get("routes"), _ROUTES),
        "total_decisions": integer(value.get("total_decisions")),
        "failure_stages": failures(value.get("counters")),
    }


def receipt_stats(value: object) -> dict[str, int]:
    if type(value) is not dict:
        raise ValueError("admission_receipt_stats_invalid")
    return {name: integer(value.get(name)) for name in sorted(_RECEIPTS)}


def response(value: object) -> dict[str, object]:
    if type(value) is not dict:
        return {"available": False}
    output: dict[str, object] = {"available": True}
    for name, allowed in (("reason_code", REASONS), ("decision", {"allow", "deny", "block", "review", "ask"})):
        item = value.get(name)
        output[name + "_present"] = name in value
        output[name] = item if type(item) is str and item in allowed else None
        output[name + "_unknown"] = item is not None and not (type(item) is str and item in allowed)
    item = value.get("observed_review_failure")
    output["observed_review_failure_present"] = "observed_review_failure" in value
    output["observed_review_failure"] = item if type(item) is bool else None
    output["observed_review_failure_invalid"] = "observed_review_failure" in value and type(item) is not bool
    return output


def _locked(lock: Any, read: Callable[[], dict[str, object]]) -> dict[str, object]:
    if not lock.acquire(blocking=False):
        return {"available": False, "reason": "lock_busy"}
    try:
        return {"available": True, "values": read()}
    except BaseException:
        return {"available": False, "reason": "counter_projection_failed"}
    finally:
        lock.release()


def snapshot(server: Any) -> dict[str, object]:
    """Separate nonblocking lock snapshots, not one atomic server transaction."""
    metrics = server.hook_worker.metrics
    scheduler = server.runtime_hook_scheduler
    return {
        "scope": "sequential_nonatomic_existing_counter_snapshots",
        "metrics": _locked(
            metrics._lock,
            lambda: {
                "routes": counts(metrics._routes, _ROUTES),
                "failure_stages": failures(metrics._counters),
            },
        ),
        "scheduler": _locked(
            scheduler._condition,
            lambda: {
                **{name: integer(getattr(scheduler, "_" + name)) for name in SCALARS},
                "rejected": counts(scheduler._rejected, REJECTIONS),
                "per_harness_active": counts(scheduler._active_by_harness, HARNESS),
                "per_harness_queued": counts(scheduler._queued_by_harness, HARNESS),
            },
        ),
        "admission": _locked(
            server.hook_capacity_lock,
            lambda: {
                "active": integer(server.active_hook_requests),
                "rejected": integer(server.rejected_hook_requests),
                "per_harness_active": counts(server.hook_harness_active, HARNESS),
                "per_harness_rejected": counts(server.hook_harness_rejected, HARNESS),
            },
        ),
    }


def complete_snapshot(value: dict[str, Any]) -> bool:
    return all(value.get(name, {}).get("available") is True for name in ("metrics", "scheduler", "admission"))
