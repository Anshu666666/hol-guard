"""Attribution is finite, separate, and cannot manufacture comparable timings."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.package_benchmark_corpus import Case
from scripts.package_benchmark_phases import FUNCTIONS, LABELS, phase_report, validate_phases
from scripts.package_benchmark_protocol import preset, preset_arms, validate_worker_report
from tests.test_package_benchmark_controller import setup_controller, valid_report
from tests.test_package_benchmark_matrix import worker_cli_case

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="declared Linux component scope")


def synthetic_phases():
    return phase_report(SimpleNamespace(getstats=lambda: []), Path("/unused"), wall_ns=1000, process_ns=800)


def test_exact_two_current_routes_and_eight_offered_candidate_workers():
    expected = (
        Case("npm", 1000, 1000, "exact", "protect_dry_run").id,
        Case("npm", 10000, 10000, "exact", "evaluator").id,
    )
    assert preset("phase-validation") == preset("phase-attribution") == expected
    assert preset_arms("phase-validation") == preset_arms("phase-attribution") == ("candidate",)
    assert len(expected) * (1 + 3) == 8
    assert preset_arms("hot-route") == ("baseline", "candidate")


def test_inclusive_overlap_and_unassigned_cpu_are_not_double_counted(tmp_path):
    source = tmp_path / "src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_models.py"
    source.parent.mkdir(parents=True)
    code = compile("def build():\n    pass\n", str(source), "exec")
    scope = {}
    exec(code, scope)
    build = scope["build"].__code__
    field = "co_qualname" if hasattr(build, "co_qualname") else "co_name"
    build = build.replace(**{field: "SupplyChainBundleIndex.build"})
    profile = SimpleNamespace(
        getstats=lambda: [
            SimpleNamespace(code=build, callcount=1, reccallcount=0, totaltime=0.009, inlinetime=0.004),
            SimpleNamespace(
                code="unclassified private method text", callcount=4, reccallcount=0, totaltime=0.005, inlinetime=0.005
            ),
        ]
    )
    observed = phase_report(profile, tmp_path, wall_ns=30_000_000, process_ns=15_000_000)
    row = observed["functions"]["bundle_index"]
    assert row["inclusive_thread_cpu_ns"] == 9_000_000
    assert row["exclusive_thread_cpu_ns"] == 4_000_000
    assert observed["profiled_exclusive_thread_cpu_ns"] == 9_000_000
    assert observed["unattributed_profile_thread_cpu_ns"] == 5_000_000
    assert observed["process_minus_profile_cpu_ns"] == 6_000_000
    assert "private" not in repr(observed) and str(tmp_path) not in repr(observed)
    assert observed["headline_eligible"] is False


@pytest.mark.parametrize("mutation", ("unknown", "boolean", "sum", "scope", "negative", "inclusive", "uncalled"))
def test_reject_unknown_text_clocks_or_inconsistent_accounting(mutation):
    value = synthetic_phases()
    if mutation == "unknown":
        value["functions"]["secret_path"] = {}
    elif mutation == "boolean":
        value["route_process_cpu_ns"] = True
    elif mutation == "sum":
        value["unattributed_profile_thread_cpu_ns"] = 1
    elif mutation == "scope":
        value["clock"] = "process_cpu"
    elif mutation == "negative":
        value["route_wall_ns"] = -1
    elif mutation == "inclusive":
        value["functions"]["bundle_index"].update(calls=1, exclusive_thread_cpu_ns=5)
    else:
        value["functions"]["bundle_index"]["inclusive_thread_cpu_ns"] = 2
    with pytest.raises(ValueError, match="package_phase"):
        validate_phases(value)


def test_negative_process_difference_is_retained_without_a_fake_zero():
    value = synthetic_phases()
    value.update(
        profiled_exclusive_thread_cpu_ns=900, unattributed_profile_thread_cpu_ns=900, process_minus_profile_cpu_ns=-100
    )
    value["origins"]["categories"]["other_c"].update(functions=1, calls=1, exclusive_thread_cpu_ns=900)
    validate_phases(value)
    assert value["process_minus_profile_cpu_ns"] == -100


def test_attribution_schema_never_accepts_headline_latency_fields():
    offered = {
        "schema": "hol-guard.package-attempt.v2",
        "case_id": preset("phase-attribution")[0],
        "source": {},
        "fixture_sha256": "a" * 64,
        "signed_response_sha256": "b" * 64,
        "environment": {},
        "harness_sha256": "c" * 64,
        "measurement": "attribution",
    }
    value = valid_report(offered)
    value.update(phases=synthetic_phases(), operation_counts={})
    validate_worker_report(value, offered)
    value["cpu_ms"] = 1.0
    with pytest.raises(ValueError, match="unexpected_timing"):
        validate_worker_report(value, offered)


def test_candidate_only_controller_rejects_unapproved_count_before_launch(tmp_path, monkeypatch):
    from scripts import package_benchmark_matrix as controller

    args, calls = setup_controller(tmp_path, monkeypatch)
    args.preset, args.measurement, args.timeout_seconds = "phase-attribution", "attribution", 30
    with pytest.raises(ValueError, match="package_phase_plan_invalid"):
        controller.run(args)
    assert calls == []


def test_actual_instrumented_protect_preserves_oracle_and_single_parse(tmp_path):
    observed = worker_cli_case(Case("npm", 100, 100, "exact", "protect_dry_run"), tmp_path, measurement="attribution")
    assert observed["status"] == "completed" and observed["packages"] == observed["evidence_rows"] == 100
    assert "wall_ms" not in observed and "cpu_ms" not in observed
    value = observed["phases"]
    validate_phases(value)
    rows = value["functions"]
    assert set(rows) == set(LABELS)
    assert rows["protect"]["calls"] == 1
    assert rows["lockfile_parse"]["calls"] == 1
    for label in (
        "bundle_index",
        "evidence_transaction",
    ):
        assert rows[label]["calls"] > 0, label
    # Authentic fixture verification is before this unchanged measured route.
    assert rows["bundle_verification"]["calls"] == rows["rsa_signature_verify"]["calls"] == 0
    assert observed["operation_counts"]["lockfile_parse_result.parse_lockfile_text"] == 1
    import json

    journal = [json.loads(line) for line in (tmp_path / "journal.jsonl").read_text().splitlines()]
    residual_records = [row["private_profile_residual"] for row in journal if "private_profile_residual" in row]
    assert len(residual_records) == 1
    private = residual_records[0]
    assert 0 < len(private["functions"]) <= 50
    assert private["omitted_functions"] == private["eligible_functions"] - len(private["functions"])
    assert "private_profile_residual" not in observed
    assert all("identity" not in row for row in value["origins"]["categories"].values())
    for category in ("guard_python", "json_python", "sqlite_c", "bytes_text_c"):
        assert value["origins"]["categories"][category]["calls"] > 0
    assert (
        sum(row["exclusive_thread_cpu_ns"] for row in value["origins"]["categories"].values())
        == value["profiled_exclusive_thread_cpu_ns"]
    )
    # No private method names, source paths, payloads or signature bytes are emitted.
    assert all(
        label in FUNCTIONS or label in {"sqlite_calls", "rsa_signature_verify", "rsa_public_key_load"} for label in rows
    )


@pytest.mark.parametrize(
    "field",
    (
        "route_wall_ns",
        "route_process_cpu_ns",
        "profiled_exclusive_thread_cpu_ns",
        "selected_exclusive_thread_cpu_ns",
        "unattributed_profile_thread_cpu_ns",
    ),
)
def test_negative_phase_total_rejects_with_exact_bounded_metric(field):
    value = synthetic_phases()
    value[field] = -123
    with pytest.raises(ValueError, match=f"^package_phase_total_invalid:{field}:-123$"):
        validate_phases(value)


def test_invalid_phase_total_never_renders_untrusted_value():
    class PrivateValue:
        def __repr__(self):
            raise AssertionError("private value must not be rendered")

    value = synthetic_phases()
    value["route_wall_ns"] = PrivateValue()
    with pytest.raises(ValueError, match=r"^package_phase_total_invalid:route_wall_ns:type$"):
        validate_phases(value)
    value["route_wall_ns"] = -(10**100)
    with pytest.raises(ValueError, match=r"^package_phase_total_invalid:route_wall_ns:range$"):
        validate_phases(value)


def test_phase_ci_preserves_all_eight_observations_and_semantic_parity(tmp_path):
    from tests.test_package_rebaseline_ci import publish, write_scope

    for scope in ("phase-validation", "phase-attribution", "registry-resolved"):
        write_scope(tmp_path / "private", scope)
    result = publish(tmp_path, plan="phase-attribution")
    assert result["status"] == "completed" and result["instrumented_semantic_parity"] is True
    assert sum(len(scope["observations"]) for scope in result["scopes"][:2]) == 8
    assert all(scope["comparisons"] == [] and scope["summaries"] == [] for scope in result["scopes"][:2])
    assert all(row["arm"] == "candidate" for scope in result["scopes"][:2] for row in scope["observations"])


def test_phase_ci_rejects_changed_semantics(tmp_path):
    import json

    from tests.test_package_rebaseline_ci import publish, write_scope

    write_scope(tmp_path / "private", "phase-validation")
    write_scope(tmp_path / "private", "registry-resolved")
    aggregate = write_scope(tmp_path / "private", "phase-attribution")
    path = aggregate / "paired.json"
    report = json.loads(path.read_text())
    report["observations"][0]["evidence_sha256"] = "f" * 64
    path.write_text(json.dumps(report))
    result = publish(tmp_path, plan="phase-attribution")
    assert result["status"] == "incomplete" and result["instrumented_semantic_parity"] is False
    assert len(result["scopes"][1]["observations"]) == 6


@pytest.mark.parametrize("mode", ("ok", "timeout"))
def test_candidate_attribution_keeps_six_actual_attempts_without_pairs(tmp_path, monkeypatch, mode):
    from scripts import package_benchmark_matrix as controller

    args, calls = setup_controller(tmp_path, monkeypatch, mode=mode, runs=3)
    args.preset, args.measurement, args.timeout_seconds = "phase-attribution", "attribution", 30
    result = controller.run(args)
    assert len(calls) == len(result["observations"]) == 6
    assert all(row["arm"] == "candidate" for row in calls)
    assert result["comparisons"] == result["descriptive_summaries"] == []
    assert result["status"] == ("completed" if mode == "ok" else "incomplete")


def test_phase_ci_missing_semantic_file_keeps_existing_rows_but_fails(tmp_path):
    from tests.test_package_rebaseline_ci import publish, write_scope

    for scope in ("phase-validation", "phase-attribution", "registry-resolved"):
        write_scope(tmp_path / "private", scope)
    next((tmp_path / "private" / "phase-attribution" / "private_samples").glob("*.semantic.json")).unlink()
    result = publish(tmp_path, plan="phase-attribution")
    assert result["status"] == "incomplete"
    assert result["private_staging"]["missing_required"] == 1
    assert len(result["scopes"][1]["observations"]) == 6


def test_failed_candidate_row_cannot_be_rescued_by_completed_container(tmp_path):
    import json

    from tests.test_package_rebaseline_ci import publish, write_scope

    for scope in ("phase-validation", "phase-attribution", "registry-resolved"):
        aggregate = write_scope(tmp_path / "private", scope)
        if scope == "phase-attribution":
            path = aggregate / "paired.json"
            report = json.loads(path.read_text())
            report["observations"][0].update(status="censored", timed_out=True, returncode=-9)
            path.write_text(json.dumps(report))
    result = publish(tmp_path, plan="phase-attribution")
    assert result["status"] == result["scopes"][1]["status"] == "incomplete"
    assert result["scopes"][1]["observations"][0]["status"] == "censored"


def test_actual_phase_finalizer_uses_only_isolated_standard_library(tmp_path):
    import json
    import subprocess

    from tests.test_package_rebaseline_ci import CANDIDATE, write_scope

    for scope in ("phase-validation", "phase-attribution", "registry-resolved"):
        write_scope(tmp_path / "private", scope)
    output = tmp_path / "public.json"
    command = [
        sys.executable,
        "-I",
        "-S",
        str(Path(__file__).resolve().parents[1] / "scripts/package_rebaseline_ci.py"),
        "--private",
        str(tmp_path / "private"),
        "--public",
        str(output),
        "--staging",
        str(tmp_path / "staging"),
        "--candidate",
        CANDIDATE,
        "--plan",
        "phase-attribution",
    ]
    for scope in ("phase-validation", "phase-attribution", "registry-resolved"):
        command.extend(("--outcome", scope + "=success"))
    observed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    assert observed.returncode == 0, observed.stderr
    value = json.loads(output.read_text())
    assert value["status"] == "completed" and value["instrumented_semantic_parity"] is True
