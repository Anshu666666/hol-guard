"""Pure numerical summaries shared by installed and component qualification."""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence


def percentile(values: Sequence[float], quantile: float) -> float:
    """Return a deterministic nearest-rank percentile for non-empty samples."""

    if not values:
        raise ValueError("percentile requires at least one sample")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    ordered = sorted(float(value) for value in values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def summarize(values: Sequence[float]) -> dict[str, float]:
    """Return bounded latency aggregates without retaining individual samples."""

    if not values:
        return {"count": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    if any(not math.isfinite(float(value)) or float(value) < 0 for value in values):
        raise ValueError("latency samples must be finite and non-negative")
    return {
        "count": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }
