"""Finite positive Cloud Review worker polling and backoff ranges."""

from __future__ import annotations

import math
from typing import Final

DEFAULT_SAFETY_POLL_SECONDS: Final = 30.0
DEFAULT_ERROR_BACKOFF_SECONDS: Final = 30.0
DEFAULT_ERROR_BACKOFF_BASE_SECONDS: Final = 1.0
MAX_SAFETY_POLL_SECONDS: Final = 3600.0
MAX_ERROR_BACKOFF_SECONDS: Final = 300.0
MIN_INTERVAL_SECONDS: Final = 0.05


def normalized_cloud_review_interval(
    value: object,
    *,
    default: float,
    maximum: float,
) -> float:
    """Return a finite positive interval, falling back instead of hot-looping."""

    parsed: float | None = None
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError:
            parsed = None
    if parsed is None or not math.isfinite(parsed) or parsed <= 0:
        fallback = default if math.isfinite(default) and default > 0 else MIN_INTERVAL_SECONDS
        return min(maximum, max(MIN_INTERVAL_SECONDS, fallback))
    return min(maximum, max(MIN_INTERVAL_SECONDS, parsed))


def cloud_review_worker_intervals(
    *,
    poll_interval: object = None,
    error_backoff: object = None,
    error_backoff_base: object = None,
) -> tuple[float, float, float]:
    safety_poll = normalized_cloud_review_interval(
        poll_interval,
        default=DEFAULT_SAFETY_POLL_SECONDS,
        maximum=MAX_SAFETY_POLL_SECONDS,
    )
    maximum_backoff = normalized_cloud_review_interval(
        error_backoff,
        default=DEFAULT_ERROR_BACKOFF_SECONDS,
        maximum=MAX_ERROR_BACKOFF_SECONDS,
    )
    initial_backoff = normalized_cloud_review_interval(
        error_backoff_base,
        default=DEFAULT_ERROR_BACKOFF_BASE_SECONDS,
        maximum=maximum_backoff,
    )
    return safety_poll, maximum_backoff, min(initial_backoff, maximum_backoff)


__all__ = [
    "DEFAULT_ERROR_BACKOFF_BASE_SECONDS",
    "DEFAULT_ERROR_BACKOFF_SECONDS",
    "DEFAULT_SAFETY_POLL_SECONDS",
    "MAX_ERROR_BACKOFF_SECONDS",
    "MAX_SAFETY_POLL_SECONDS",
    "MIN_INTERVAL_SECONDS",
    "cloud_review_worker_intervals",
    "normalized_cloud_review_interval",
]
