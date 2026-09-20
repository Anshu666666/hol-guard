from __future__ import annotations

import copy
from typing import Any

import pytest

from scripts.native_slo_contract import summarize
from scripts.native_slo_launcher_consumer import admit_block, compare_campaign, read_block
from scripts.native_slo_launcher_offers import ROUTES, population
from scripts.native_slo_qualification import paired_order, sampling_plan


def identity(letter: str = "a") -> dict[str, Any]:
    result: dict[str, Any] = {
        key: letter * 40 for key in ("source_commit", "source_tree", "build_commit", "build_tree")
    }
    result.update(
        {
            key: letter * 64
            for key in (
                "wheel_sha256",
                "installed_manifest_sha256",
                "runtime_sha256",
                "rule_sha256",
                "corpus_sha256",
                "producer_sha256",
                "providers_sha256",
                "interpreter_sha256",
            )
        }
    )
    result.update(package_version="3.0.1", python_version="3.12.14", default_native_features=True)
    for key in ("corpus_sha256", "producer_sha256", "rule_sha256", "interpreter_sha256"):
        result[key] = "e" * 64
    return result


def block(plan: dict[str, int], *, arm: str = "baseline", number: int = 0, sequence: int = 0) -> dict[str, Any]:
    counts = population(plan)
    rows = []
    raw = {}
    routes = []
    latency = 20.0 if arm == "baseline" else 10.0
    for route in ROUTES:
        harness, event = route.split(".")
        report: dict[str, Any] = {
            "harness": harness,
            "event": event,
            "registration_sha256": "f" * 64,
            "cases_validated": ["benign", "block"],
            "configuration": "registered_argv_and_env",
            "route_attribution": "isolated_batch_counter_conservation",
        }
        for phase, offset in (("preflight", -1), ("cold", 2_000_000), ("serial", 0), ("c16", 1_000_000)):
            for index in range(counts[phase]):
                rows.append(
                    {
                        "index": len(rows),
                        "route": route,
                        "phase": phase,
                        "sample": -1 if phase == "preflight" else offset + index,
                        "case": "block" if phase == "preflight" and index == 1 else "benign",
                        "outcome": "returned",
                        "latency_ms": latency,
                    }
                )
            if phase != "preflight":
                key = "INSTALLED_LAUNCHER." + ("" if phase == "serial" else phase + ".") + route
                raw[key] = [latency] * counts[phase]
                report[{"cold": "cold_launcher", "serial": "serial", "c16": "c16"}[phase]] = summarize(raw[key])
        routes.append(report)
    start = sequence * 1000 + 1
    ident = identity("a" if arm == "baseline" else "b")
    sampled = {
        "live_inventory_scope": "protected_kernel_group",
        "live_inventory_identity": "pid_and_creation_time_before_and_after_each_sample",
        "sampled_memory_scope": "sum_of_live_members_during_successful_sample_windows",
        "instantaneous_peak_proven": False,
        "samples": 30,
        "unavailable_samples": 0,
        "metric_samples": {name: 30 for name in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")},
        "metric_minimum_met": {
            name: True for name in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
        },
        "unavailable_metrics": {"cpu_seconds": {"process_history_bound": 1}},
        "peak": {"private_bytes": 1000, "rss_bytes": 2000, "processes": 20, "threads": 30, "descriptors": 100},
    }
    return {
        "schema": "hol-guard.launcher-measurement-block.v1",
        "arm": arm,
        "block": number,
        "platform": "linux-x64",
        "host_sha256": f"{number + 100:064x}",
        "host_class_sha256": "c" * 64,
        "identity_before": ident,
        "identity_after": copy.deepcopy(ident),
        "cleanup_confirmed": True,
        "export_privacy_passed": True,
        "offers": {
            "schema": "hol-guard.launcher-offers.v1",
            "counts_per_route": counts,
            "maximum": len(rows),
            "producer_returned": True,
            "complete": True,
            "start_monotonic_ns": start + 1,
            "stop_monotonic_ns": start + 2,
            "active_at_freeze": 0,
            "faults": {},
            "rows": rows,
        },
        "launcher": {
            "boundary": "INSTALLED_LAUNCHER",
            "contracts_passed": True,
            "process_startup_included": True,
            "stdout_and_exit_checked": True,
            "cold_state": "fresh_launcher_process_resident_prepared",
            "resident_cold_measured": False,
            "concurrency": [1, 16],
            "policy_fixture": "explicit_allow_acknowledged",
            "routes": routes,
        },
        "raw": raw,
        "resources": {
            "schema": "hol-guard.launcher-resource-observation.v1",
            "scope": "benchmark_worker_and_descendants",
            "includes_load_generator_and_collector": True,
            "protected_live_members_requested": True,
            "original_calls": 1,
            "original_returned": True,
            "observation_complete": True,
            "final_tail_complete": True,
            "faults": {},
            "start_monotonic_ns": start,
            "stop_monotonic_ns": start + 3,
            "lifetime_cpu_complete": True,
            "lifetime_cpu": {
                "source": "protected_cgroup_v2_kernel_lifetime",
                "includes_exited_members": True,
                "includes_external_services": False,
                "boundary_sha256": f"{sequence:064x}",
                "usage_seconds": 2.0 if arm == "baseline" else 1.8,
                "user_seconds": 1.0,
                "system_seconds": 0.5,
            },
            "sampled_resources": sampled,
        },
    }


@pytest.fixture
def small() -> tuple[dict[str, Any], dict[str, int]]:
    plan = {"priority_per_run": 2, "cold_per_run": 2}
    return block(plan), plan


def test_original_population_joins_and_full_cpu_is_not_polled_cpu(small) -> None:
    value, plan = small
    result = admit_block(value, identity(), plan)
    assert result["offered"] == result["returned"] == 88
    assert result["denials"] == 4 and sum(row["count"] for row in result["measurements"].values()) == 80
    resources = result["resources"]
    assert resources["cpu_ms_per_attempt"] == 2000 / 88
    assert resources["all_required_interval_metrics_available"] is True
    assert resources["live_group_private_memory_available"] is True
    assert resources["instantaneous_or_unobserved_peak_proven"] is False
    assert resources["observer_cost_subtracted"] is False


@pytest.mark.parametrize(
    "field",
    [
        "source_commit",
        "source_tree",
        "build_commit",
        "wheel_sha256",
        "installed_manifest_sha256",
        "runtime_sha256",
        "rule_sha256",
        "corpus_sha256",
        "producer_sha256",
        "providers_sha256",
        "interpreter_sha256",
        "python_version",
        "package_version",
        "default_native_features",
    ],
)
def test_changed_source_installed_or_runtime_identity_refuses(small, field: str) -> None:
    value, plan = small
    value["identity_after"][field] = "f" * 64
    with pytest.raises(ValueError, match="identity"):
        admit_block(value, identity(), plan)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "extra",
        "duplicate",
        "raised",
        "inflight",
        "bool_sample",
        "bool_latency",
        "nan",
        "wrong_phase",
        "wrong_case",
        "row_order",
        "different_raw",
        "extra_raw",
        "summary",
        "lost_return",
        "active",
        "clock",
        "cleanup",
        "privacy",
    ],
)
def test_original_offer_raw_contract_and_interval_mismatch_refuses(small, change: str) -> None:
    value, plan = small
    rows = value["offers"]["rows"]
    if change == "missing":
        rows.pop()
    elif change == "extra":
        rows.append(copy.deepcopy(rows[-1]))
    elif change == "duplicate":
        rows[3]["sample"] = rows[2]["sample"]
    elif change in {"raised", "inflight"}:
        rows[0]["outcome"] = change
    elif change == "bool_sample":
        rows[4]["sample"] = False
    elif change == "bool_latency":
        rows[0]["latency_ms"] = True
    elif change == "nan":
        rows[0]["latency_ms"] = float("nan")
    elif change == "wrong_phase":
        rows[0]["phase"] = "serial"
    elif change == "wrong_case":
        rows[2]["case"] = "block"
    elif change == "row_order":
        rows[2], rows[4] = rows[4], rows[2]
    elif change == "different_raw":
        value["raw"][next(iter(value["raw"]))][0] += 1
    elif change == "extra_raw":
        value["raw"]["private"] = [1.0]
    elif change == "summary":
        value["launcher"]["routes"][0]["serial"]["p95_ms"] += 1
    elif change == "lost_return":
        value["offers"]["producer_returned"] = False
    elif change == "active":
        value["offers"]["active_at_freeze"] = 1
    elif change == "clock":
        value["resources"]["stop_monotonic_ns"] = 0
    elif change == "cleanup":
        value["cleanup_confirmed"] = False
    elif change == "privacy":
        value["export_privacy_passed"] = False
    with pytest.raises(ValueError):
        admit_block(value, identity(), plan)


@pytest.mark.parametrize(
    "change",
    [
        "ancestry",
        "missing_sample",
        "short_samples",
        "partial_private",
        "unavailable_private",
        "no_private",
        "rss_proxy",
        "bool_private",
        "missing_lifetime",
        "partial_tail",
        "fault",
        "outside_population",
        "negative_cpu",
    ],
)
def test_missing_metrics_are_preserved_as_unavailable_not_qualification(small, change: str) -> None:
    value, plan = small
    resource = value["resources"]
    sampled = resource["sampled_resources"]
    if change == "ancestry":
        sampled["live_inventory_scope"] = "process_ancestry"
    elif change == "missing_sample":
        sampled["unavailable_samples"] = 1
    elif change == "short_samples":
        sampled["samples"] = 29
    elif change == "partial_private":
        sampled["metric_samples"]["private_bytes"] = 29
    elif change == "unavailable_private":
        sampled["unavailable_metrics"]["private_bytes"] = {"permission_denied": 1}
    elif change in {"no_private", "rss_proxy"}:
        sampled["peak"]["private_bytes"] = None
    elif change == "bool_private":
        sampled["peak"]["private_bytes"] = True
    elif change == "missing_lifetime":
        resource["lifetime_cpu_complete"] = False
    elif change == "partial_tail":
        resource["final_tail_complete"] = False
    elif change == "fault":
        resource["faults"] = {"lifetime_stop": 1}
    elif change == "outside_population":
        resource["lifetime_cpu"]["includes_external_services"] = True
    elif change == "negative_cpu":
        resource["lifetime_cpu"]["usage_seconds"] = -1
    report = admit_block(value, identity(), plan)
    assert report["resources"]["all_required_interval_metrics_available"] is False


def test_full_declared_six_pair_consumer_uses_original_minima_and_confidence() -> None:
    plan = sampling_plan(runs=6, qualification=True)
    documents = [
        block(plan, arm=arm, number=number, sequence=2 * number + slot)
        for number in range(6)
        for slot, arm in enumerate(paired_order(number))
    ]
    result = compare_campaign(documents, {"baseline": identity("a"), "candidate": identity("b")})
    assert result["offered_per_arm"] == {"baseline": 80784, "candidate": 80784}
    assert all(result["sampling"].values()) and all(result["absolute_ceiling_checks"].values())
    assert result["original_relative_gain_predicate"] is True and result["selected_tranche_accepted"] is True
    assert result["program_qualification_complete"] is False
    for name, values in result["comparison"].items():
        expected = 102 if ".cold." in name else 10080 if ".c16." in name else 10002
        assert values["baseline_samples"] == values["candidate_samples"] == expected
        assert (
            values["p95"]["ci95_high"] == 0.5 and values["p95"]["interval_method"] == "paired_run_block_bootstrap_2000"
        )


@pytest.mark.parametrize("change", ["missing", "same_arm", "block_index", "host", "hardware", "overlap", "boundary"])
def test_actual_pairing_and_host_are_admitted_separately(small, change: str) -> None:
    del small
    plan = sampling_plan(runs=6, qualification=True)
    documents = [
        block(plan, arm=arm, number=number, sequence=2 * number + slot)
        for number in range(6)
        for slot, arm in enumerate(paired_order(number))
    ]
    if change == "missing":
        documents.pop()
    elif change == "same_arm":
        documents[1]["arm"] = "baseline"
    elif change == "block_index":
        documents[1]["block"] = 1
    elif change == "host":
        documents[1]["host_sha256"] = "d" * 64
    elif change == "hardware":
        documents[1]["host_class_sha256"] = "d" * 64
    elif change == "overlap":
        documents[1]["resources"]["start_monotonic_ns"] = 1
        documents[1]["offers"]["start_monotonic_ns"] = 2
    elif change == "boundary":
        documents[1]["resources"]["lifetime_cpu"]["boundary_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        compare_campaign(documents, {"baseline": identity("a"), "candidate": identity("b")})


@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"[" * 34 + b"0" + b"]" * 34,
        b'"' + b"x" * 257 + b'"',
        b" " * (8 * 1024 * 1024 + 1),
    ],
)
def test_reader_rejects_ambiguous_nonfinite_and_bounded_inputs(body: bytes) -> None:
    with pytest.raises(ValueError):
        read_block(body)
