from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_slo_evidence_files import atomic_exclusive
from scripts.native_slo_pair_io import canonical, read_public, write_public
from scripts.native_slo_qualification import paired_ratio_interval
from scripts.native_slo_surface_tail_aggregate import aggregate, compare, pair_name, validate_pair
from scripts.native_slo_surface_tail_contract import ROUTES, route_for
from scripts.native_slo_surface_tail_pair import archive_pair, collect_pair
from scripts.native_slo_surface_tail_record import numeric_commitment
from tests.native_slo_pair_support import SHA, TARGET, bundle_fixture, context_fixture
from tests.native_slo_surface_tail_support import block, pair


def test_all_five_pairs_conserve_other_minimum_and_original_estimator(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    context = context_fixture(bundle_root, mode="qualification")
    context.pop("pair_index")
    route = ROUTES[0]
    for index in range(5):
        pair(tmp_path / pair_name(route, context, index), bundle_root, bundle, route, index=index, mode="qualification")
    result = aggregate(roots=tmp_path, bundle=bundle, context=context, route=route)
    assert result["collection_complete"] and result["comparison_available"] and result["sampling_passed"]
    observed = result["comparisons"][route.series]
    assert observed["baseline_samples"] == observed["candidate_samples"] == 1000
    assert observed["p95"] == observed["p99"] == paired_ratio_interval([10.0] * 5, [7.0] * 5)
    assert result["ordinary_c1_scope_qualified"] is True
    assert result["qualification_complete"] is False
    assert result["program_qualification_complete"] is False


@pytest.mark.parametrize("change", ["route", "scope", "case", "count", "order", "cipher", "missing"])
def test_substitution_or_missing_evidence_cannot_count(tmp_path, change):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root, route = tmp_path / "pair", ROUTES[0]
    context, _, _ = pair(root, bundle_root, bundle, route)
    if change == "cipher":
        with (root / "encrypted/observations.hge").open("ab") as stream:
            stream.write(b"x")
    elif change == "missing":
        (root / "archive-receipt.json").unlink()
    else:
        path = root / "aggregate/pair-manifest.json"
        manifest = read_public(path)
        if change in {"route", "scope"}:
            manifest["workload"]["route"] = "copilot.preToolUse.project"
        elif change == "case":
            manifest["workload"]["case_id"] = "cursor.beforeShellExecution.dangerous.small"
        elif change == "count":
            manifest["arms"]["baseline"]["numeric"]["series_counts"][route.series] = 1
        else:
            manifest["offered_order"].reverse()
        path.write_bytes(canonical(manifest))
    with pytest.raises((ValueError, OSError)):
        validate_pair(root, route=route, context=context, bundle=bundle)


@pytest.mark.parametrize("mutation", ["delete", "replace"])
def test_archive_checks_exact_numeric_bytes_not_file_count(tmp_path, mutation):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root, route = tmp_path / "pair", ROUTES[0]
    context, _, args = pair(root, bundle_root, bundle, route, archive=False)
    path = root / "private_samples/00-baseline.json"
    if mutation == "delete":
        path.unlink()
    else:
        path.write_bytes(b'{"different":[1]}')
    for index in range(4):
        atomic_exclusive(root / f"private_samples/extra-{index}.json", b"{}")
    receipt = archive_pair(args)
    write_public(root / "archive-receipt.json", receipt)
    assert receipt["pair_binding"]["numeric_commitments_verified"] is False
    evidence, reports = validate_pair(root, route=route, context=context, bundle=bundle)
    assert evidence["collection_complete"] is False and reports == {}


def test_interruption_retains_offer_without_inventing_numeric_success(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root, route = tmp_path / "pair", ROUTES[0]
    context, _, args = pair(root, bundle_root, bundle, route, archive=False)
    for name in (
        "aggregate/pair-manifest.json",
        "private_samples/pair-manifest.json",
        "aggregate/00-candidate-offer.json",
    ):
        (root / name).unlink()
    write_public(root / "archive-receipt.json", archive_pair(args))
    evidence, reports = validate_pair(root, route=route, context=context, bundle=bundle)
    assert evidence["arms"] == {"baseline": "failed", "candidate": "unattempted"}
    assert not evidence["collection_complete"] and not reports


@pytest.mark.parametrize("field", ["cpu_model", "ram_bytes", "runner_image", "runner_image_os"])
def test_cross_pair_heterogeneous_cohorts_are_not_pooled(tmp_path, field):
    bundle = bundle_fixture(tmp_path / "bundle")
    route = ROUTES[0]
    reports = {
        arm: [block(bundle, arm, route, "qualification")[0] for _ in range(5)] for arm in ("baseline", "candidate")
    }
    reports["candidate"][3]["hardware"][field] = "different"
    with pytest.raises(ValueError, match="cohort_changed"):
        compare(reports, route=route, mode="qualification")


def test_intrinsic_review_has_separate_tail_statistics_without_ordinary_allow_claim(tmp_path):
    bundle = bundle_fixture(tmp_path / "bundle")
    route = route_for("cursor.beforeReadFile.global")
    reports = {
        arm: [block(bundle, arm, route, "qualification")[0] for _ in range(5)] for arm in ("baseline", "candidate")
    }
    result = compare(reports, route=route, mode="qualification")
    assert result["sampling_passed"] and result["comparison_available"]
    assert not result["ordinary_c1_target_applicable"] and not result["qualification_complete"]


def test_count_preserving_numeric_change_is_rejected(tmp_path):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, raw = block(bundle, "baseline", ROUTES[0])
    raw[ROUTES[0].series][0] = 99
    path = tmp_path / "raw.json"
    atomic_exclusive(path, canonical(raw))
    with pytest.raises(ValueError, match="numeric_summary"):
        numeric_commitment(path, report, ROUTES[0], "smoke")


def test_commitment_hashes_the_validated_snapshot_despite_later_path_replacement(tmp_path, monkeypatch):
    import hashlib

    from scripts import native_slo_surface_tail_record as module

    bundle = bundle_fixture(tmp_path / "bundle")
    report, raw = block(bundle, "baseline", ROUTES[0])
    path = tmp_path / "numbers.json"
    before = canonical(raw)
    atomic_exclusive(path, before)
    original = module.confidence_summary

    def swapped(values):
        path.write_bytes(before.replace(b"10.0", b"99.0"))
        return original(values)

    monkeypatch.setattr(module, "confidence_summary", swapped)
    commitment = numeric_commitment(path, report, ROUTES[0], "smoke")
    assert commitment["sha256"] == hashlib.sha256(before).hexdigest()
    assert commitment["sha256"] != hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("container", [None, "runtime", "hardware"])
def test_unknown_token_field_never_gets_a_public_success_copy(tmp_path, container):
    from scripts.native_slo_surface_tail_record import TailRecorder

    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "result"
    (root / "aggregate").mkdir(parents=True)
    (root / "private_samples").mkdir(mode=0o700)
    recorder = TailRecorder(root=root, context=context_fixture(bundle_root), route=ROUTES[0], bundle=bundle)
    recorder.offer("baseline")
    report, raw = block(bundle, "baseline", ROUTES[0])
    target = report if container is None else report[container]
    target["note"] = "PRIVATE_FIXTURE_SENTINEL"
    path = root / "private_samples/00-baseline.json"
    atomic_exclusive(path, canonical(raw))
    with pytest.raises(ValueError, match="fields_invalid"):
        recorder.completed("baseline", report, path)
    assert not (root / "aggregate/00-baseline.json").exists()
    assert all(b"PRIVATE_FIXTURE_SENTINEL" not in item.read_bytes() for item in (root / "aggregate").iterdir())


@pytest.mark.parametrize(
    "container,key,value",
    [
        ("hardware", "cpu_model", {"note": "review_sentinel"}),
        ("hardware", "cpu_count", True),
        ("hardware", "ram_bytes", "16000"),
        ("hardware", "load_average", [1.0, float("nan"), 2.0]),
        ("runtime", "architecture", {"note": "review_sentinel"}),
        ("runtime", "protocol_version", True),
        ("runtime", "rule_digest", "review_sentinel"),
    ],
)
def test_nested_or_wrong_typed_identity_leaves_never_get_published(tmp_path, container, key, value):
    from scripts.native_slo_surface_tail_record import TailRecorder

    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "result"
    (root / "aggregate").mkdir(parents=True)
    (root / "private_samples").mkdir(mode=0o700)
    recorder = TailRecorder(root=root, context=context_fixture(bundle_root), route=ROUTES[0], bundle=bundle)
    recorder.offer("baseline")
    report, raw = block(bundle, "baseline", ROUTES[0])
    report[container][key] = value
    path = root / "private_samples/00-baseline.json"
    atomic_exclusive(path, canonical(raw))
    with pytest.raises(ValueError):
        recorder.completed("baseline", report, path)
    assert not (root / "aggregate/00-baseline.json").exists()


def test_unexpected_artifact_clears_all_derived_acceptance_and_comparisons(tmp_path):
    from scripts.native_slo_surface_tail_aggregate import invalidate

    bundle = bundle_fixture(tmp_path / "bundle")
    route = ROUTES[0]
    reports = {
        arm: [block(bundle, arm, route, "qualification")[0] for _ in range(5)] for arm in ("baseline", "candidate")
    }
    result = compare(reports, route=route, mode="qualification")
    assert result["tail_sampling_qualified"] and result["ordinary_c1_scope_qualified"]
    invalidate(result, "unexpected_pair_evidence")
    assert "comparisons" not in result
    for key in (
        "sampling_passed",
        "tail_sampling_qualified",
        "ordinary_c1_scope_qualified",
        "ordinary_c1_target_passed",
        "collection_complete",
        "comparison_available",
    ):
        assert result[key] is False


def test_cli_unexpected_artifact_never_publishes_a_comparison(tmp_path, monkeypatch):
    from scripts.native_slo_surface_tail_aggregate import main

    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    roots, route = tmp_path / "pairs", ROUTES[0]
    context = context_fixture(bundle_root, mode="qualification")
    for index in range(5):
        pair(roots / pair_name(route, context, index), bundle_root, bundle, route, index=index, mode="qualification")
    (roots / "unexpected-copy").mkdir()
    output = tmp_path / "summary"
    monkeypatch.setattr(
        "sys.argv",
        [
            "tail-aggregate",
            "--pairs",
            str(roots),
            "--bundle",
            str(bundle_root),
            "--output",
            str(output),
            "--target",
            TARGET,
            "--candidate-sha",
            SHA,
            "--selection",
            route.identifier,
            "--mode",
            "qualification",
            "--run-id",
            "17",
            "--run-attempt",
            "2",
        ],
    )
    assert main() == 1
    result = read_public(output / f"{route.identifier}.json")
    assert result["reason"] == "unexpected_pair_evidence"
    assert not result["tail_sampling_qualified"] and not result["ordinary_c1_scope_qualified"]
    assert not (output / f"{route.identifier}-comparison.json").exists()


@pytest.mark.parametrize("bad_baseline", ["failed", "invalid_success", "containment"])
def test_failed_baseline_preserves_candidate_only_after_containment(tmp_path, monkeypatch, bad_baseline):
    from scripts import native_slo_surface_tail_pair as module

    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    observed = []
    route = ROUTES[0]

    def child(argv, **kwargs):
        arm = Path(argv[0]).parent.parent.name
        observed.append(arm)
        assert kwargs["timeout_seconds"] == 3600
        if arm == "baseline":
            return SimpleNamespace(
                returncode=0 if bad_baseline == "invalid_success" else 1,
                timed_out=False,
                containment_failed=bad_baseline == "containment",
                output_limit_exceeded=False,
                stdout='{"schema":"invalid"}',
            )
        report, raw = block(bundle, arm, route)
        atomic_exclusive(Path(argv[-1]), canonical(raw))
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=canonical(report).decode(),
        )

    monkeypatch.setattr(module, "run_isolated_hook_process", child)
    args = argparse.Namespace(
        bundle=bundle_root,
        output=tmp_path / "result",
        environments=tmp_path / "envs",
        target=TARGET,
        candidate_sha=SHA,
        route=route.identifier,
        pair_index=0,
        run_id=17,
        run_attempt=2,
        mode="smoke",
    )
    if bad_baseline == "containment":
        with pytest.raises(RuntimeError, match="containment"):
            collect_pair(args)
    else:
        result = collect_pair(args)
        assert result["arms"]["candidate"]["status"] == "completed"
        assert not result["collection_complete"]
    assert observed == (["baseline"] if bad_baseline == "containment" else ["baseline", "candidate"])
    assert (args.output / "private_samples/00-baseline-diagnostic.json").is_file()
