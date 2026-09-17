from __future__ import annotations

import pytest

from scripts.native_slo_qualification import sampling_gates
from scripts.native_slo_registered_surfaces import SURFACE_EVENTS
from scripts.native_slo_surface_tail_contract import ROUTES, matrices, plan, route_for, workload


def test_exact_320_jobs_and_five_pairs_per_registration():
    full = matrices(mode="qualification", selection="all")
    assert len(full["first"]["include"]) == len(full["second"]["include"]) == 160
    entries = full["first"]["include"] + full["second"]["include"]
    assert len({(item["target"], item["route"], item["pair_index"]) for item in entries}) == 320
    assert len(ROUTES) == 16
    for route in ROUTES:
        assert route.event in SURFACE_EVENTS[route.harness]
        assert {item["pair_index"] for item in entries if item["route"] == route.identifier} == set(range(5))
    assert plan("qualification")["samples_per_arm"] * 5 == 1000
    assert plan("qualification")["priority_minimum_unchanged"] == 10000


def test_copilot_scopes_and_aliases_are_distinct():
    routes = [route for route in ROUTES if route.harness == "copilot"]
    assert len(routes) == len({route.series for route in routes}) == 4
    assert {route.scope for route in routes} == {"global", "project"}
    assert {route.event for route in routes} == {"preToolUse", "postToolUse"}


def test_full_and_broad_smoke_are_not_implicit():
    assert matrices(mode="qualification", selection="none")["enabled"] is False
    with pytest.raises(ValueError, match="one_route"):
        matrices(mode="smoke", selection="all")
    smoke = matrices(mode="smoke", selection=ROUTES[0].identifier)
    assert len(smoke["first"]["include"]) == 4
    assert smoke["second"]["include"] == []
    assert plan("smoke")["samples_per_arm"] == 2


@pytest.mark.parametrize(
    "invalid", ["../route", "cursor.PreToolUse.global", "codex.PreToolUse.global", "pi.PostToolUse.global"]
)
def test_only_actual_declared_command_slots_are_admitted(invalid):
    with pytest.raises(ValueError):
        route_for(invalid)


def test_priority_gate_is_not_lowered_to_the_companion_minimum():
    observed = {"INSTALLED_LAUNCHER.c1.codex.PreToolUse": {"baseline_samples": 1000, "candidate_samples": 1000}}
    assert sampling_gates(observed, runs=5)[next(iter(observed))] is False


def test_workload_identity_commits_case_class_scope_and_mode():
    digests = [workload(route, "qualification")["common_workload_digest"] for route in ROUTES]
    assert len(set(digests)) == 16
    route = route_for("cursor.beforeReadFile.global")
    assert route.case_id == "cursor/beforeReadFile/normal/small"
    assert route.preflight_count == 1
    assert workload(route, "smoke")["common_workload_digest"] not in digests
