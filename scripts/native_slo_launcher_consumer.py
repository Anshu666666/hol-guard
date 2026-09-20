"""Strict data consumer for the selected installed priority-launcher tranche.

This reader runs no product code. It joins retained original observations and
source-bound setup receipts; filesystem/wheel admission remains the separate
driver's responsibility. All emitted values are closed labels or aggregates.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, cast

from scripts.native_slo_acceptance import resource_comparisons
from scripts.native_slo_contract import summarize
from scripts.native_slo_launcher_offers import PHASES, ROUTES, population
from scripts.native_slo_qualification import (
    compare_routes,
    confidence_summary,
    paired_order,
    sampling_gates,
    sampling_plan,
)

_IDENTITY_HEX = {
    "source_commit": 40,
    "source_tree": 40,
    "build_commit": 40,
    "build_tree": 40,
    "wheel_sha256": 64,
    "installed_manifest_sha256": 64,
    "runtime_sha256": 64,
    "runtime_rule_digest": 64,
    "policy_fixture_sha256": 64,
    "corpus_sha256": 64,
    "producer_sha256": 64,
    "providers_sha256": 64,
    "interpreter_sha256": 64,
}
_LIVE_METRICS = ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")


def read_block(body: bytes) -> Any:
    """Decode one bounded retained packet without ambiguous object keys."""
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("block_byte_bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("block_duplicate_key")
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise ValueError("block_nonfinite")

    result = json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
    pending = [(result, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > 300_000:
            raise ValueError("block_structure_bound")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and len(value) > 256:
            raise ValueError("block_string_bound")
    return result


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def _hex(value: Any, length: int = 64) -> bool:
    return type(value) is str and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _number(value: Any, *, positive: bool = False) -> bool:
    return type(value) in {int, float} and math.isfinite(value) and (value > 0 if positive else value >= 0)


def _integer(value: Any, *, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    _require(type(value) is dict, label)
    return value


def _identity(value: Any) -> Mapping[str, Any]:
    identity = _mapping(value, "identity_schema")
    _require(
        set(identity) == {*_IDENTITY_HEX, "package_version", "python_version", "default_native_features"},
        "identity_keys",
    )
    _require(all(_hex(identity[key], length) for key, length in _IDENTITY_HEX.items()), "identity_digest")
    for key in ("package_version", "python_version"):
        text = identity[key]
        _require(
            type(text) is str and 1 <= len(text) <= 64 and all(char.isalnum() or char in ".+-" for char in text),
            "identity_version",
        )
    _require(
        identity["source_tree"] == identity["build_tree"] and identity["default_native_features"] is True,
        "identity_build",
    )
    return identity


def _raw_key(route: str, phase: str) -> str:
    return "INSTALLED_LAUNCHER." + ("" if phase == "serial" else phase + ".") + route


def _offers(ledger: Mapping[str, Any], raw: Mapping[str, Any], plan: Mapping[str, int]) -> dict[str, Any]:
    counts = population(plan)
    maximum = 4 * sum(counts.values())
    _require(ledger.get("schema") == "hol-guard.launcher-offers.v1", "offer_schema")
    _require(ledger.get("counts_per_route") == counts and ledger.get("maximum") == maximum, "offer_population")
    _require(
        type(ledger.get("maximum")) is int and all(type(value) is int for value in ledger["counts_per_route"].values()),
        "offer_population_types",
    )
    _require(
        ledger.get("producer_returned") is True
        and ledger.get("complete") is True
        and type(ledger.get("active_at_freeze")) is int
        and ledger["active_at_freeze"] == 0
        and ledger.get("faults") == {},
        "offer_incomplete",
    )
    rows = ledger.get("rows")
    _require(type(rows) is list and len(rows) == maximum, "offer_count")
    rows = cast(list[Any], rows)
    seen: set[tuple[str, str, int, str]] = set()
    observed: dict[str, list[float]] = {}
    prior_order = -1
    for index, value in enumerate(rows):
        row = _mapping(value, "offer_row")
        _require(set(row) == {"index", "route", "phase", "sample", "case", "outcome", "latency_ms"}, "offer_row_keys")
        _require(type(row["index"]) is int and row["index"] == index, "offer_index")
        route, phase, sample, case = (row[key] for key in ("route", "phase", "sample", "case"))
        _require(
            route in ROUTES and phase in PHASES and type(sample) is int and case in {"benign", "block"},
            "offer_coordinate",
        )
        order = ROUTES.index(route) * len(PHASES) + PHASES.index(phase)
        _require(order >= prior_order, "offer_phase_order")
        prior_order = order
        offsets = {"cold": 2_000_000, "serial": 0, "c16": 1_000_000}
        valid = (
            sample == -1
            if phase == "preflight"
            else case == "benign" and offsets[phase] <= sample < offsets[phase] + counts[phase]
        )
        coordinate = (route, phase, sample, case)
        _require(valid and coordinate not in seen, "offer_duplicate_or_range")
        seen.add(coordinate)
        _require(row["outcome"] == "returned" and _number(row["latency_ms"]), "offer_result")
        if phase != "preflight":
            observed.setdefault(_raw_key(route, phase), []).append(row["latency_ms"])
    expected: set[tuple[str, str, int, str]] = set()
    for route in ROUTES:
        expected.update((route, "preflight", -1, case) for case in ("benign", "block"))
        for phase, offset in (("cold", 2_000_000), ("serial", 0), ("c16", 1_000_000)):
            expected.update((route, phase, offset + index, "benign") for index in range(counts[phase]))
    _require(seen == expected, "offer_missing_coordinate")
    _require(set(raw) == set(observed), "raw_route_roster")
    summaries: dict[str, Any] = {}
    for key, recorded in observed.items():
        values = raw[key]
        _require(
            type(values) is list and len(values) == len(recorded) and all(_number(value) for value in values),
            "raw_values",
        )
        _require(Counter(values) == Counter(recorded), "raw_offer_join")
        summaries[key] = confidence_summary(values)
    return {"offered": maximum, "returned": maximum, "raised": 0, "denials": 4, "measurements": summaries}


def _resources(report: Mapping[str, Any], ledger: Mapping[str, Any], offered: int) -> dict[str, Any]:
    _require(report.get("schema") == "hol-guard.launcher-resource-observation.v1", "resource_schema")
    clocks: list[Any] = [
        report.get("start_monotonic_ns"),
        ledger.get("start_monotonic_ns"),
        ledger.get("stop_monotonic_ns"),
        report.get("stop_monotonic_ns"),
    ]
    _require(
        all(_integer(value) for value in clocks) and clocks == sorted(clocks) and clocks[0] < clocks[-1],
        "resource_clock_join",
    )
    bracket = (
        report.get("scope") == "benchmark_worker_and_descendants"
        and report.get("includes_load_generator_and_collector") is True
        and type(report.get("original_calls")) is int
        and report["original_calls"] == 1
        and report.get("original_returned") is True
        and report.get("observation_complete") is True
        and report.get("final_tail_complete") is True
        and report.get("faults") == {}
    )
    lifetime = _mapping(report.get("lifetime_cpu", {}), "lifetime_schema")
    cpu_available = (
        bracket
        and report.get("lifetime_cpu_complete") is True
        and lifetime.get("source") == "protected_cgroup_v2_kernel_lifetime"
        and lifetime.get("includes_exited_members") is True
        and lifetime.get("includes_external_services") is False
        and _hex(lifetime.get("boundary_sha256"))
        and all(_number(lifetime.get(name)) for name in ("usage_seconds", "user_seconds", "system_seconds"))
        and _number(lifetime.get("usage_seconds"), positive=True)
    )
    sampled = _mapping(report.get("sampled_resources", {}), "sampled_schema")
    samples: Any = sampled.get("samples")
    missing = sampled.get("unavailable_samples")
    counts = _mapping(sampled.get("metric_samples", {}), "metric_samples")
    flags = _mapping(sampled.get("metric_minimum_met", {}), "metric_flags")
    unavailable = _mapping(sampled.get("unavailable_metrics", {}), "metric_unavailable")
    peak = _mapping(sampled.get("peak", {}), "metric_peak")
    live_scope = (
        bracket
        and report.get("protected_live_members_requested") is True
        and sampled.get("live_inventory_scope") == "protected_kernel_group"
        and sampled.get("live_inventory_identity") == "pid_and_creation_time_before_and_after_each_sample"
        and sampled.get("sampled_memory_scope") == "sum_of_live_members_during_successful_sample_windows"
        and sampled.get("instantaneous_peak_proven") is False
        and _integer(samples)
        and samples >= 30
        and type(missing) is int
        and missing == 0
    )
    minima = {
        name: bool(
            live_scope
            and _integer(counts.get(name))
            and counts[name] == samples
            and flags.get(name) is True
            and name not in unavailable
            and _number(peak.get(name), positive=True)
        )
        for name in _LIVE_METRICS
    }
    # The authoritative two-endpoint kernel interval replaces the explicitly
    # incomplete polled CPU source, never its missing-memory or sample flags.
    minima["cpu_seconds"] = bool(cpu_available and live_scope)
    return {
        "cpu_ms_per_attempt": lifetime["usage_seconds"] * 1000 / offered if cpu_available else None,
        "cpu_denominator": offered,
        "cpu_denominator_scope": "all_preflight_cold_serial_c16_offers_in_one_original_producer",
        "cpu_interval": "whole_worker_producer_bracket_including_sampler_ledger_and_original_receipt_waits",
        "cpu_excludes": "privileged_parent_controller_external_services_and_work_after_final_snapshot",
        "metric_minimum_met": minima,
        "short_exited_descendants_cpu_complete": bool(cpu_available),
        "interval_cpu_available": bool(cpu_available),
        "live_group_private_memory_available": minima["private_bytes"],
        "sampled_peak_only": True,
        "instantaneous_or_unobserved_peak_proven": False,
        "peak": {name: peak.get(name) if _number(peak.get(name)) else None for name in _LIVE_METRICS},
        "samples": samples if _integer(samples) else None,
        "unavailable_samples": missing if _integer(missing) else None,
        "all_required_interval_metrics_available": all(minima.values()),
        "boundary_sha256": lifetime.get("boundary_sha256") if _hex(lifetime.get("boundary_sha256")) else None,
        "clock_interval_ns": [clocks[0], clocks[-1]],
        "observer_cost_subtracted": False,
    }


def admit_block(document: Any, expected_identity: Mapping[str, Any], plan: Mapping[str, int]) -> dict[str, Any]:
    """Refuse count/source/result mismatches; retain missing metrics as false."""
    block = _mapping(document, "block_schema")
    _require(block.get("schema") == "hol-guard.launcher-measurement-block.v1", "block_schema")
    expected = _identity(dict(expected_identity))
    _require(
        _identity(block.get("identity_before")) == expected == _identity(block.get("identity_after")),
        "identity_changed",
    )
    _require(
        block.get("arm") in {"baseline", "candidate"} and _integer(block.get("block"), maximum=19), "block_coordinate"
    )
    _require(
        _hex(block.get("host_sha256"))
        and _hex(block.get("host_class_sha256"))
        and block.get("platform") == "linux-x64",
        "block_host",
    )
    _require(
        block.get("cleanup_confirmed") is True and block.get("export_privacy_passed") is True,
        "block_cleanup_or_privacy",
    )
    ledger = _mapping(block.get("offers"), "offer_schema")
    raw = _mapping(block.get("raw"), "raw_schema")
    joined = _offers(ledger, raw, plan)
    launcher = _mapping(block.get("launcher"), "launcher_schema")
    _require(
        launcher.get("boundary") == "INSTALLED_LAUNCHER"
        and launcher.get("contracts_passed") is True
        and launcher.get("process_startup_included") is True
        and launcher.get("stdout_and_exit_checked") is True
        and launcher.get("cold_state") == "fresh_launcher_process_resident_prepared"
        and launcher.get("resident_cold_measured") is False
        and launcher.get("concurrency") == [1, 16]
        and all(type(value) is int for value in launcher["concurrency"])
        and launcher.get("policy_fixture") == "explicit_allow_acknowledged",
        "launcher_contract",
    )
    routes = launcher.get("routes")
    _require(type(routes) is list and len(routes) == 4, "launcher_route_count")
    routes = cast(list[Any], routes)
    for name, row in zip(ROUTES, routes, strict=True):
        _require(type(row) is dict and name == f"{row.get('harness')}.{row.get('event')}", "launcher_route_order")
        _require(
            _hex(row.get("registration_sha256"))
            and row.get("cases_validated") == ["benign", "block"]
            and row.get("configuration") == "registered_argv_and_env"
            and row.get("route_attribution") == "isolated_batch_counter_conservation",
            "launcher_route_contract",
        )
        for label, phase in (("serial", "serial"), ("cold_launcher", "cold"), ("c16", "c16")):
            _require(row.get(label) == summarize(raw[_raw_key(name, phase)]), "launcher_summary_join")
    resources = _resources(_mapping(block.get("resources"), "resource_schema"), ledger, joined["offered"])
    return {
        **joined,
        "arm": block["arm"],
        "block": block["block"],
        "host_sha256": block["host_sha256"],
        "host_class_sha256": block["host_class_sha256"],
        "identity": dict(expected),
        "resources": resources,
    }


def compare_campaign(documents: Sequence[Any], identities: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Consume exactly six alternating pairs with the original CI predicates."""
    plan = sampling_plan(runs=6, qualification=True)
    _require(len(documents) == 12 and set(identities) == {"baseline", "candidate"}, "campaign_roster")
    left, right = (_identity(dict(identities[arm])) for arm in ("baseline", "candidate"))
    _require(
        left["wheel_sha256"] != right["wheel_sha256"] and left["source_commit"] != right["source_commit"],
        "campaign_distinct_arms",
    )
    _require(
        all(
            left[key] == right[key]
            for key in (
                "corpus_sha256",
                "producer_sha256",
                "policy_fixture_sha256",
                "python_version",
                "interpreter_sha256",
            )
        ),
        "campaign_common_inputs_changed",
    )
    admitted: dict[str, list[dict[str, Any]]] = {"baseline": [], "candidate": []}
    host_class = None
    pair_host = None
    previous_stop = -1
    boundaries: set[str] = set()
    for index, document in enumerate(documents):
        block_number, slot = divmod(index, 2)
        arm = paired_order(block_number)[slot]
        block = admit_block(document, identities[arm], plan)
        _require(block["arm"] == arm and block["block"] == block_number, "campaign_order")
        host_class = block["host_class_sha256"] if host_class is None else host_class
        _require(block["host_class_sha256"] == host_class, "campaign_hardware_class_changed")
        if slot == 0:
            pair_host = block["host_sha256"]
            previous_stop = -1
        _require(block["host_sha256"] == pair_host, "campaign_pair_host_changed")
        resources = block["resources"]
        start, stop = resources["clock_interval_ns"]
        _require(start > previous_stop, "campaign_interval_overlap")
        previous_stop = stop
        boundary = resources["boundary_sha256"]
        _require(boundary is not None and boundary not in boundaries, "campaign_boundary_reused_or_missing")
        boundaries.add(cast(str, boundary))
        admitted[arm].append(block)
    baseline, candidate = admitted["baseline"], admitted["candidate"]
    comparison: dict[str, Any] = compare_routes(
        [row["measurements"] for row in baseline], [row["measurements"] for row in candidate]
    )
    sampling = sampling_gates(comparison, runs=6)
    resources = resource_comparisons(baseline, candidate)
    complete_resources = all(
        row["resources"]["all_required_interval_metrics_available"] for row in [*baseline, *candidate]
    )
    latency = [comparison[_raw_key(route, "serial")]["p95"] for route in ROUTES]
    cpu_upper = resources["cpu_ms_per_attempt"].get("comparison", {}).get("ci95_high", math.inf)
    # Preserve the original predicate exactly. Its first disjunct uses ANY
    # route's gain, whereas the CPU-gain branch requires ALL latency ratios.
    gain_predicate = sampling["independent_runs"] and (
        (any(item["ci95_high"] <= 0.70 for item in latency) and cpu_upper <= 1.05)
        or (all(item["ci95_high"] <= 1.05 for item in latency) and cpu_upper <= 0.70)
    )
    ceilings: dict[str, bool] = {}
    for route in ROUTES:
        for phase, quantile, limit in (("serial", "p95", 50), ("serial", "p99", 100), ("c16", "p99", 200)):
            key = _raw_key(route, phase)
            ceilings[f"{key}.{quantile}"] = all(
                row["measurements"][key][f"{quantile}_ci95_ms"][1] <= limit for row in candidate
            )
    return {
        "schema": "hol-guard.launcher-comparison.v1",
        "platform": "linux-x64",
        "runs_per_arm": 6,
        "offered_per_arm": {arm: sum(row["offered"] for row in rows) for arm, rows in admitted.items()},
        "returned_per_arm": {arm: sum(row["returned"] for row in rows) for arm, rows in admitted.items()},
        "comparison": comparison,
        "sampling": sampling,
        "absolute_ceiling_checks": ceilings,
        "resource_comparisons": resources,
        "required_interval_metrics_available": complete_resources,
        "original_relative_gain_predicate": gain_predicate,
        "selected_tranche_accepted": all(sampling.values())
        and all(ceilings.values())
        and complete_resources
        and gain_predicate,
        "program_qualification_complete": False,
        "scope": "priority_launcher_closed_loop_and_sampled_linux_live_group_resources_only",
        "observer_cost_subtracted": False,
        "remaining": [
            "production_baseline_comparison",
            "other_platforms",
            "other_routes_sizes_modes_and_faults",
            "arrival_rate_saturation",
            "recovery_and_full_startup",
            "distribution_and_final_review",
        ],
    }
