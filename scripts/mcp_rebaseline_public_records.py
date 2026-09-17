"""Typed public metrics; no arbitrary worker text crosses this boundary."""

from __future__ import annotations

from typing import Any

from scripts.mcp_rebaseline_network import NETWORK_METRICS
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
from scripts.mcp_rebaseline_statistics import PAIRED_METRICS
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
                *NETWORK_METRICS,
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


_RESOURCE_FIELDS = fields(
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
        "cpu_accounting_scope": choice("observed_process_tree"),
        "cpu_unavailable_samples": integer,
        "includes_load_generator": choice(False),
        "fixture_control_overhead_included": choice(True),
    }
)


def resource(value: Any) -> dict[str, Any]:
    """Admit the fixed Linux tree collector, including unavailable CPU reads."""
    result = _RESOURCE_FIELDS(value)
    # MCP's Linux component does not supply a Windows job CPU reader. Both
    # counters therefore describe the same unavailable process-tree snapshots.
    require(result["cpu_unavailable_samples"] == result["unavailable_samples"])
    return result


RESOURCE = resource
WARM_FAILURE = optional(
    choice(
        "observer_aborted",
        "protocol_deadline",
        "protocol_eof",
        "protocol_byte_bound",
        "protocol_frame_invalid",
        "protocol_short_write",
        "process_membership_invalid",
        "process_identity_invalid",
        "root_identity_changed",
        "observer_sequence_invalid",
        "worker_trace_failed",
        "process_identity_changed",
        "resource_samples_incomplete",
        "observer_operation_failed",
        "observer_report_failed",
        "observer_cleanup_failed",
        "observer_shutdown_deadline",
    )
)
WARM_RESOURCES = array(
    fields(
        {
            "trace_index": integer,
            "status": choice("complete", "incomplete"),
            "failure": WARM_FAILURE,
            "identity_verified": boolean,
            "expected_warm_attempts": integer,
            "warm_attempts": optional(integer),
            "resources": optional(RESOURCE),
        }
    ),
    len(TRACES),
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
    optional_fields={
        "worker_lifecycle_wall_ns": number,
        "resources": RESOURCE,
        "warm_resources": WARM_RESOURCES,
        "warm_resource_failure": WARM_FAILURE,
    },
)


def run_trace(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict) and "block" in value)
    block = integer(value["block"])
    require(block < 5)
    result = COMPARISON({key: item for key, item in value.items() if key != "block"})
    require(result["independent_runs"] == 1)
    return {"block": block, **result}


INTERVAL = fields(
    {
        "runs": integer,
        "median_ratio": number,
        "ci95_low": number,
        "ci95_high": number,
        "interval_method": choice("paired_run_block_bootstrap_2000"),
        "minimum_runs_met": boolean,
    }
)
PAIRED = array(
    fields(
        {
            "trace": TRACE,
            "status": choice("complete", "incomplete"),
            "offered_runs": choice(5),
            "matched_blocks": array(integer, 5),
            "resampling_unit": choice("independent_run_pair"),
            "ratio_direction": choice("candidate_over_baseline"),
            "tail_qualified": choice(False),
            "intervals": optional(fields({name: INTERVAL for name in PAIRED_METRICS})),
        }
    ),
    len(TRACES),
)
RUN_TRACES = array(run_trace, 30 * len(TRACES))
COMPARISONS = array(COMPARISON, 2 * 3 * len(TRACES))
PHASES = array(PHASE, 2 * len(TRACES) * len(PHASE_NAMES))
RUNS = array(RUN, 30)
