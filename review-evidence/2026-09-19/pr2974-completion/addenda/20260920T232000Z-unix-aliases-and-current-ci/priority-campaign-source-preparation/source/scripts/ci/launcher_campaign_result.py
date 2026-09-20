"""Unprivileged data-only admission of one retained campaign worker result.

The private controller envelope is not an export. Fixed keys and string values
are checked before an original worker document can be retained publicly. No
sanitizer rewrites measurements; unsafe documents yield only length/digest and
a fixed refusal. Failed safe documents remain evidence, never accepted blocks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from typing import Any

from scripts.ci.launcher_campaign_identity import unique_pairs
from scripts.native_slo_launcher_consumer import admit_block, read_block
from scripts.native_slo_launcher_offers import ROUTES
from scripts.native_slo_qualification import sampling_plan

_KEYS = set(
    [
        "schema",
        "passed",
        "arm",
        "block",
        "admitted",
        "producer_offered",
        "producer_returned",
        "fixture_cleanup_confirmed",
        "boundary_closed",
        "failed_stages",
        "identity_before",
        "identity_after",
        "cleanup_confirmed",
        "export_privacy_passed",
        "offers",
        "resources",
        "launcher",
        "raw",
        "host_sha256",
        "host_class_sha256",
        "platform",
        "policy_before_sha256",
        "policy_after_sha256",
        "installed_inventories",
        "source_commit",
        "source_tree",
        "build_commit",
        "build_tree",
        "wheel_sha256",
        "installed_manifest_sha256",
        "runtime_sha256",
        "runtime_rule_digest",
        "policy_fixture_sha256",
        "corpus_sha256",
        "producer_sha256",
        "providers_sha256",
        "interpreter_sha256",
        "package_version",
        "python_version",
        "default_native_features",
        "package_sha256",
        "wheel_members",
        "record_sha256",
        "record_members",
        "dependencies_sha256",
        "scope",
        "counts_per_route",
        "maximum",
        "start_monotonic_ns",
        "stop_monotonic_ns",
        "active_at_freeze",
        "complete",
        "faults",
        "rows",
        "overhead",
        "index",
        "route",
        "phase",
        "sample",
        "case",
        "outcome",
        "latency_ms",
        "preflight",
        "cold",
        "serial",
        "c16",
        "boundary",
        "routes",
        "contracts_passed",
        "process_startup_included",
        "stdout_and_exit_checked",
        "cold_state",
        "resident_cold_measured",
        "concurrency",
        "policy_fixture",
        "harness",
        "event",
        "registration_sha256",
        "configuration",
        "cases_validated",
        "cold_launcher",
        "route_attribution",
        "count",
        "p50_ms",
        "max_ms",
        "p95_ms",
        "p99_ms",
        "includes_load_generator_and_collector",
        "protected_live_members_requested",
        "original_calls",
        "original_returned",
        "observation_complete",
        "lifetime_cpu_complete",
        "full_resource_qualification",
        "tail_scope",
        "clock_scope",
        "sampled_resources",
        "lifetime_cpu",
        "final_tail_complete",
        "source",
        "includes_exited_members",
        "includes_external_services",
        "boundary_sha256",
        "usage_seconds",
        "user_seconds",
        "system_seconds",
        "live_inventory_scope",
        "live_inventory_identity",
        "sampled_memory_scope",
        "instantaneous_peak_proven",
        "collector",
        "samples",
        "unavailable_samples",
        "unavailable_sample_reasons",
        "unavailable_sample_reason_scope",
        "unavailable_sample_operations",
        "unavailable_sample_operation_scope",
        "metric_samples",
        "unavailable_metrics",
        "unavailable_metric_roles",
        "unavailable_metric_role_scope",
        "metric_minimum_met",
        "sample_minimum_met",
        "elapsed_seconds",
        "baseline",
        "peak",
        "rss_growth",
        "cpu_seconds",
        "cpu_ms_per_attempt",
        "cpu_includes_reaped_descendants",
        "short_exited_descendants_cpu_complete",
        "short_exited_descendants_cpu_scope",
        "includes_load_generator",
        "fixture_control_overhead_included",
        "rss_bytes",
        "private_bytes",
        "processes",
        "threads",
        "descriptors",
        "handles",
        "permission_denied",
        "platform_unsupported",
        "metric_unavailable",
        "process_history_bound",
        "invalid_cumulative_delta",
        "invalid_process_data",
        "inventory_changed",
        "process_lookup_failed",
        "process_tree_bound",
        "protected_group_inventory_unavailable",
        "os_error",
        "root",
        "descendant",
        "unknown",
        "lifetime_start",
        "sampler_start",
        "sampler_stop",
        "sampler_report",
        "lifetime_stop",
        "recorder_finish",
        "entry_projection",
        "row_bound",
        "entry_recorder",
        "return_projection",
        "exit_recorder",
        "restoration_conflict",
        "freeze_recorder",
        "original_raised",
        "finish_failed",
        "lifetime_cpu_unavailable",
    ]
)
_KEYS.update("INSTALLED_LAUNCHER." + prefix + route for route in ROUTES for prefix in ("", "c16.", "cold."))
_KEYS.update(
    operation + ":" + role
    for operation in (
        "create_root",
        "inventory_before",
        "rss_bytes",
        "private_bytes",
        "threads",
        "handles",
        "descriptors",
        "cpu_times",
        "linux_proc_cpu",
        "inventory_after",
    )
    for role in ("root", "descendant", "unknown")
)
_STRINGS = set(
    [
        "hol-guard.launcher-worker-intermediate.v1",
        "hol-guard.launcher-arm-intermediate.v1",
        "hol-guard.launcher-measurement-block.v1",
        "hol-guard.launcher-offers.v1",
        "hol-guard.launcher-resource-observation.v1",
        "baseline",
        "candidate",
        "linux-x64",
        "claude-code",
        "codex",
        "PreToolUse",
        "PostToolUse",
        "preflight",
        "cold",
        "serial",
        "c16",
        "benign",
        "block",
        "returned",
        "raised",
        "inflight",
        "boundary_admission",
        "installed_binding",
        "identity_before",
        "fixture_setup",
        "policy_before",
        "producer",
        "policy_after",
        "fixture_cleanup",
        "identity_after",
        "boundary_close",
        "INSTALLED_LAUNCHER",
        "fresh_launcher_process_resident_prepared",
        "explicit_allow_acknowledged",
        "registered_argv_and_env",
        "isolated_batch_counter_conservation",
        "benchmark_worker_and_descendants",
        "protected_cgroup_v2_kernel_lifetime",
        "protected_kernel_group",
        "pid_and_creation_time_before_and_after_each_sample",
        "sum_of_live_members_during_successful_sample_windows",
        "load_generator_process_tree",
        "daemon_fixture_process_tree",
        "psutil_with_linux_proc_cpu",
        "psutil_observed_descendants",
        "last_failed_attempt_after_two_attempts",
        "last_permission_denial_per_metric_in_each_returned_sample",
        "current_tree_and_waited_children_only",
        "observed_processes_only",
        "outside_original_launch_timers_inside_worker_CPU_and_scheduling",
        "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches",
        "no_admitted_kernel_lifetime_boundary",
    ]
)
_STRINGS.update(ROUTES)
_STRINGS.update(
    {
        "original producer returned; no independent descendant-retirement proof",
        "sampling surrounds the whole original launcher producer; original per-launch timers unchanged",
        "snapshot/start/stop work outside per-launch timers; "
        "concurrent sampler competes inside them; no cost subtraction",
    }
)
_HEX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]{0,63}\Z")


def validate_export(value: Any) -> None:
    pending = [(value, "", 0)]
    visited = 0
    while pending:
        node, key, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > 300_000:
            raise ValueError("export_structure")
        if type(node) is dict:
            if any(type(name) is not str or name not in _KEYS for name in node):
                raise ValueError("export_field")
            pending.extend((child, name, depth + 1) for name, child in node.items())
        elif type(node) is list:
            pending.extend((child, key, depth + 1) for child in node)
        elif type(node) is str:
            if (
                node not in _STRINGS
                and not _HEX.fullmatch(node)
                and not (key in {"package_version", "python_version"} and _VERSION.fullmatch(node))
            ):
                raise ValueError("export_value")
        elif type(node) is int and not -(2**63) <= node <= 2**63 - 1:
            raise ValueError("export_integer")
        elif (
            node is not None and type(node) is not bool and (type(node) not in {int, float} or not math.isfinite(node))
        ):
            raise ValueError("export_scalar")


def finalize(controller: dict[str, Any], *, configuration_sha256: str, identity: dict[str, Any]) -> dict[str, Any]:
    """Join original stdout bytes to controller facts without rerunning work."""
    encoded = controller.get("private_worker_stdout_base64")
    if type(encoded) is not str or len(encoded) > 4 * ((8 * 1024 * 1024 + 3) // 3):
        raise ValueError("controller_body_bound")
    body = base64.b64decode(encoded, validate=True)
    report: dict[str, Any] = {
        "schema": "hol-guard.launcher-arm-finalization.v1",
        "admitted": False,
        "counts_and_identity_admitted": False,
        "required_metrics_available": False,
        "qualification_complete": False,
        "source_bytes": {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()},
        "worker_document": None,
        "block": None,
        "refusal": None,
    }
    try:
        if controller.get("stdout") != report["source_bytes"]:
            raise ValueError("controller_body_identity")
        original = read_block(body)
        validate_export(original)
        report["worker_document"] = original
        if (
            controller.get("schema") != "hol-guard.launcher-host-controller.v1"
            or controller.get("configuration_sha256") != configuration_sha256
            or controller.get("outer_wall_seconds") != 4800
            or controller.get("worker_launched") is not True
            or type(controller.get("worker_exit")) is not int
            or controller["worker_exit"] != 0
            or controller.get("worker_reaped") is not True
            or controller.get("cleanup_complete") is not True
            or controller.get("group_empty_before_cleanup") is not True
            or controller.get("emergency_group_kill_used") is not False
            or controller.get("collection_failure") is not None
            or controller.get("fault") is not None
            or controller.get("stderr") != {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        ):
            raise ValueError("controller_not_complete")
        if type(original) is not dict or original.get("schema") != "hol-guard.launcher-worker-intermediate.v1":
            raise ValueError("worker_schema")
        arm = original["arm"]
        inventories = original["installed_inventories"]
        if (
            original.get("passed") is not True
            or arm.get("schema") != "hol-guard.launcher-arm-intermediate.v1"
            or any(
                arm.get(key) is not True
                for key in (
                    "admitted",
                    "producer_offered",
                    "producer_returned",
                    "fixture_cleanup_confirmed",
                    "boundary_closed",
                )
            )
            or arm.get("failed_stages") != []
            or type(inventories) is not list
            or len(inventories) != 2
            or inventories[0] != inventories[1]
        ):
            raise ValueError("worker_not_complete")
        if not (arm.get("policy_before_sha256") == arm.get("policy_after_sha256") == identity["policy_fixture_sha256"]):
            raise ValueError("worker_policy_join")
        inventory = inventories[0]
        if (
            type(inventory) is not dict
            or set(inventory)
            != {"package_sha256", "wheel_members", "record_sha256", "record_members", "dependencies_sha256", "scope"}
            or inventory["package_sha256"] != identity["installed_manifest_sha256"]
            or any(
                type(inventory[key]) is not int or not 1 <= inventory[key] <= 20_000
                for key in ("wheel_members", "record_members")
            )
            or any(
                type(inventory[key]) is not str or len(inventory[key]) != 64 or not _HEX.fullmatch(inventory[key])
                for key in ("record_sha256", "dependencies_sha256")
            )
            or inventory["scope"] != "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches"
        ):
            raise ValueError("worker_inventory_join")
        # Copy rather than retroactively mutate the retained original flags.
        block = dict(arm["block"])
        if block.get("cleanup_confirmed") is not False or block.get("export_privacy_passed") is not False:
            raise ValueError("worker_premature_admission")
        block.update(cleanup_confirmed=True, export_privacy_passed=True)
        joined = admit_block(block, identity, sampling_plan(runs=6, qualification=True))
        available = joined["resources"]["all_required_interval_metrics_available"] is True
        report.update(
            admitted=available,
            counts_and_identity_admitted=True,
            required_metrics_available=available,
            block=block,
            joined=joined,
            refusal=None if available else "required_metrics_unavailable",
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        # A fixed refusal never exposes user values from a failed parser/oracle.
        report["refusal"] = "data_admission_failed"
    return report


def read_controller(body: bytes) -> dict[str, Any]:
    if len(body) > 12 * 1024 * 1024:
        raise ValueError("controller_byte_bound")
    value = json.loads(body, object_pairs_hook=unique_pairs)
    if type(value) is not dict:
        raise ValueError("controller_schema")
    return value
