"""Typed public metrics; no arbitrary worker text crosses this boundary."""

from __future__ import annotations

from typing import Any

from scripts.mcp_rebaseline_public_types import (
    MODE,
    ROLE,
    array,
    boolean,
    choice,
    fields,
    integer,
    mapping,
    number,
    optional,
    require,
    summary,
)
from scripts.mcp_rebaseline_trace import TRACES

TRACE = choice(*(trace.name for trace in TRACES))
PHASE_NAMES = {
    "synthetic_approval_callback",
    "child_startup_and_launch_identity",
    "catalog_capture",
    "authority_composite",
    "catalog_drain",
    "final_quiet_barrier",
    "child_response_wait",
    "quiet_frame_wait",
    "child_frame_poll",
    "forwarding_composite",
    "catalog_fingerprint",
    "policy_evaluation_composite",
    "request_identity",
    "receipt_and_inventory_composite",
    "classification_categories",
    "classification_signals",
    "classification_signals_from_categories",
    "policy_store_lookup",
    "persistence.record_inventory_artifact",
    "persistence.add_receipt",
    "persistence.add_event",
    "persistence.upsert_policy",
    "serialization.json_dumps",
    "serialization.json_loads",
    "serialization.frame_encode",
    "hash.sha256",
}
COUNTER_NAMES = PHASE_NAMES | {
    "serialization.json_dumps.output_bytes",
    "serialization.json_loads.output_bytes",
    "serialization.frame_encode.output_bytes",
    "hash.sha256.input_bytes",
}
COMPARISON = fields(
    {
        "role": ROLE,
        "mode": MODE,
        "trace": TRACE,
        "independent_runs": integer,
        "warm_attempts": integer,
        "cold_attempts": integer,
        "headline_eligible": boolean,
        **{
            key: summary
            for key in (
                "warm_wall_ns",
                "warm_process_cpu_ns",
                "first_call_wall_ns",
                "session_wall_ns",
                "construction_wall_ns",
                "child_service_wall_ns",
                "child_observed_wire_bytes",
                "synthetic_approval_wall_ns",
            )
        },
    }
)
PHASE = fields(
    {
        "role": ROLE,
        "trace": TRACE,
        "phase": choice(*sorted(PHASE_NAMES)),
        "count": integer,
        "inclusive_wall_ns": summary,
        "exclusive_wall_ns": summary,
        "exclusive_thread_cpu_ns": summary,
        "failures": integer,
    }
)
METRICS = {"rss_bytes", "private_bytes", "cpu_seconds", "processes", "threads", "descriptors", "handles"}
REASONS = {"permission_denied", "platform_unsupported", "metric_unavailable", "process_history_bound"}


def growth(value: Any) -> int | float:
    require(type(value) in (int, float) and value >= -1)
    number(value + 1)
    return value


RESOURCE = fields(
    {
        "scope": choice("mcp_proxy_worker_and_descendants"),
        "collector": choice("psutil_with_linux_proc_cpu", "psutil_observed_descendants"),
        "samples": integer,
        "unavailable_samples": integer,
        "metric_samples": mapping(METRICS, integer),
        "unavailable_metrics": mapping(METRICS, mapping(REASONS, integer)),
        "metric_minimum_met": mapping(METRICS, boolean),
        "sample_minimum_met": boolean,
        "elapsed_seconds": number,
        "baseline": fields({key: optional(number) for key in METRICS - {"cpu_seconds"}}),
        "peak": fields({key: optional(number) for key in METRICS - {"cpu_seconds"}}),
        "rss_growth": optional(growth),
        "cpu_seconds": optional(number),
        "cpu_ms_per_attempt": optional(number),
        "cpu_includes_reaped_descendants": boolean,
        "short_exited_descendants_cpu_complete": boolean,
        "includes_load_generator": choice(False),
        "fixture_control_overhead_included": choice(True),
    }
)


def return_code(value: Any) -> int | None:
    require(value is None or (type(value) is int and -65535 <= value <= 65535))
    return value


def capture_failure(value: Any) -> str | None:
    if value is None:
        return None
    require(isinstance(value, str) and len(value) <= 256)
    # The private observation retains an exception class. Public output needs
    # only the fixed failure category, never a dynamically named class.
    category = value.split(":", 1)[0]
    return choice(
        "worker_deadline",
        "worker_observer_failure",
        "resource_observer_cleanup_incomplete",
        "capture_cleanup_incomplete",
        "capture_byte_bound",
        "controller_worker_failure",
    )(category)


RUN = fields(
    {
        "block": integer,
        "role": ROLE,
        "mode": MODE,
        "returncode": return_code,
        "capture_failure": capture_failure,
        "import": optional(fields({"wall_ns": number, "process_cpu_ns": number})),
        "phase_counts": optional(mapping(COUNTER_NAMES, integer)),
        **{
            key: optional(number)
            for key in (
                "self_cpu_seconds",
                "waited_child_cpu_seconds",
                "self_peak_rss_bytes",
                "largest_waited_child_peak_rss_bytes",
            )
        },
    },
    optional_fields={"worker_lifecycle_wall_ns": number, "resources": RESOURCE},
)

COMPARISONS = array(COMPARISON, 42)
PHASES = array(PHASE, 2 * len(TRACES) * len(PHASE_NAMES))
RUNS = array(RUN, 30)
