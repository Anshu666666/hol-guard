from __future__ import annotations

import itertools
import json
import subprocess
import sys

import pytest

from scripts import native_slo_surface_tail_plan as module
from scripts.native_slo_surface_tail_aggregate import aggregate, pair_name, validate_pair
from scripts.native_slo_surface_tail_contract import matrices, plan, route_for
from tests.native_slo_pair_support import bundle_fixture, context_fixture
from tests.native_slo_surface_tail_support import pair

REPOSITORY = "hashgraph-online/hol-guard"
LABEL_SETS = tuple(
    tuple(
        label
        for label, present in zip([*sorted(module.FULL_LABELS), module.SMOKE_LABEL], flags, strict=True)
        if present
    )
    for flags in itertools.product((False, True), repeat=3)
)


def select(labels=(), *, event="pull_request", head=REPOSITORY, mode="qualification", selection="none"):
    return module.selected_scope(
        mode,
        selection,
        event_name=event,
        repository=REPOSITORY,
        head_repository=head,
        labels=labels,
    )


@pytest.mark.parametrize("labels", LABEL_SETS)
def test_real_label_selector_preserves_full_gate_and_gives_smoke_precedence(labels):
    mode, selection = select(labels)
    result = matrices(mode=mode, selection=selection)
    entries = result["first"]["include"] + result["second"]["include"]
    if module.SMOKE_LABEL in labels:
        assert (mode, selection) == ("smoke", "cursor.beforeShellExecution.global")
        assert len(entries) == 4 and {entry["pair_index"] for entry in entries} == {0}
        assert len({entry["target"] for entry in entries}) == 4
        assert {entry["route"] for entry in entries} == {selection}
        assert result["second"]["include"] == []
        route = route_for(selection)
        assert route.preflight_count == 2 and route.case_id == "cursor/beforeShellExecution/benign/small"
        sampling = plan(mode)
        assert sampling["samples_per_arm"] == 2 and sampling["runs"] == 1
        assert len(entries) * 2 * sampling["samples_per_arm"] == 16
        assert len(entries) * 2 * (sampling["samples_per_arm"] + route.preflight_count) == 32
        assert sampling["minimum_samples"] == 1000 and sampling["priority_minimum_unchanged"] == 10000
    elif module.FULL_LABELS.issubset(labels):
        assert (mode, selection) == ("qualification", "all") and len(entries) == 320
        assert {entry["pair_index"] for entry in entries} == set(range(5))
        assert plan(mode)["samples_per_arm"] == 200
    else:
        assert selection == "none" and entries == [] and result["enabled"] is False


@pytest.mark.parametrize("labels", LABEL_SETS)
@pytest.mark.parametrize("event,head", [("pull_request", "fork/hol-guard"), ("schedule", REPOSITORY)])
def test_forks_and_schedule_cannot_enable_tail_work_even_with_injected_labels(labels, event, head):
    assert select(labels, event=event, head=head, selection="all") == ("qualification", "none")


def test_empty_repository_names_are_not_same_repository_authorization():
    assert module.selected_scope(
        "smoke", "all", event_name="pull_request", repository="", head_repository="", labels=(module.SMOKE_LABEL,)
    ) == ("smoke", "none")


@pytest.mark.parametrize("event", [None, "workflow_dispatch"])
def test_direct_and_manual_selection_remain_explicit_and_broad_smoke_is_rejected(event):
    labels = (*module.FULL_LABELS, module.SMOKE_LABEL)
    for mode, selection in (("smoke", module.SMOKE_ROUTE), ("qualification", "all"), ("qualification", "none")):
        assert select(labels, event=event, mode=mode, selection=selection) == (mode, selection)
    mode, selection = select(labels, event=event, mode="smoke", selection="all")
    with pytest.raises(ValueError, match="one_route"):
        matrices(mode=mode, selection=selection)


def test_inconsistent_full_label_mode_fails_instead_of_offering_wrong_sampling():
    with pytest.raises(ValueError, match="require_qualification_mode"):
        select(tuple(module.FULL_LABELS), mode="smoke")


def test_cli_outputs_resolved_smoke_mode_even_when_main_plan_and_full_labels_are_qualification(tmp_path):
    output = tmp_path / "outputs"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            module.__file__,
            "--mode",
            "qualification",
            "--selection",
            "all",
            "--output",
            str(output),
            "--event-name",
            "pull_request",
            "--repository",
            REPOSITORY,
            "--head-repository",
            REPOSITORY,
            "--pr-labels-json",
            json.dumps([*module.FULL_LABELS, module.SMOKE_LABEL]),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert completed.stdout == completed.stderr == ""
    fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert fields["mode"] == "smoke" and fields["selection"] == module.SMOKE_ROUTE
    assert fields["enabled"] == fields["first_enabled"] == "true" and fields["second_enabled"] == "false"
    assert len(json.loads(fields["first"])["include"]) == 4


@pytest.mark.parametrize("actual,requested", [("smoke", "qualification"), ("qualification", "smoke")])
def test_sealed_pair_from_one_mode_cannot_enter_the_other_cohort(tmp_path, actual, requested):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    route = route_for(module.SMOKE_ROUTE)
    root = tmp_path / "pair"
    context, _, _ = pair(root, bundle_root, bundle, route, mode=actual)
    context.update(mode=requested, runs=plan(requested)["runs"])
    with pytest.raises(ValueError, match="manifest_context"):
        validate_pair(root, route=route, context=context, bundle=bundle)


def test_completed_label_smoke_cannot_pass_full_tail_minima(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    context = context_fixture(bundle_root, mode="smoke")
    context.pop("pair_index")
    route = route_for(module.SMOKE_ROUTE)
    pair(tmp_path / pair_name(route, context, 0), bundle_root, bundle, route, mode="smoke")
    result = aggregate(roots=tmp_path, bundle=bundle, context=context, route=route)
    assert result["collection_complete"] and result["comparison_available"]
    assert not result["tail_sampling_qualified"] and not result["ordinary_c1_scope_qualified"]
    assert result["qualification_complete"] is False and result["program_qualification_complete"] is False
