from __future__ import annotations

import json

import pytest

from scripts.native_slo_pair_aggregate import aggregate_pairs, exit_status
from scripts.native_slo_pair_archive import archive_pair
from scripts.native_slo_pair_comparison import compare_blocks
from scripts.native_slo_pair_io import canonical, read_public, write_public
from scripts.native_slo_pair_record import expected_counts, validate_context
from scripts.native_slo_pair_validation import validate_pair
from scripts.native_slo_qualification import sampling_plan
from tests.native_slo_pair_support import TARGET, block_fixture, bundle_fixture, context_fixture, pair_fixture


def test_five_pair_plan_conserves_global_minima():
    counts = expected_counts(sampling_plan(runs=5, qualification=True))
    assert len(counts) == 38 and sum(counts.values()) == 29564
    assert counts["NATIVE_CLIENT.claude-code.PostToolUse"] == 2000
    assert counts["INSTALLED_LAUNCHER.c16.codex.PreToolUse"] == 2000
    assert counts["NATIVE_CLIENT.cold_oneshot"] == 20
    assert counts["NATIVE_CLIENT.policy_readiness"] == 22


@pytest.mark.parametrize("mutation", [{"runs": 1}, {"pair_index": 5}, {"run_id": True}, {"mode": "qualified"}])
def test_context_rejects_downsampling_or_identity_coercion(tmp_path, mutation):
    root = tmp_path / "bundle"
    bundle_fixture(root)
    context = context_fixture(root, mode="qualification") | mutation
    with pytest.raises(ValueError):
        validate_context(context)


def test_all_five_pairs_use_identical_estimator_and_never_promote_missing_scopes(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    pairs = tmp_path / "pairs"
    reports = {"baseline": [], "candidate": []}
    for index in range(5):
        root = pairs / f"pair-{TARGET}-{index}-17-2"
        context, _, _ = pair_fixture(root, bundle_root, bundle, index=index, mode="qualification")
        for arm in reports:
            reports[arm].append(read_public(root / "aggregate" / f"{index:02d}-{arm}.json"))
    context.pop("pair_index")
    result = aggregate_pairs(pair_roots=pairs, bundle_root=bundle_root, context=context)
    expected = compare_blocks(
        reports,
        mode="qualification",
        runs=5,
        artifact_digests={arm: bundle["arms"][arm]["wheel_sha256"] for arm in reports},
    )
    assert result["collection_complete"] is True and result["comparison_available"] is True
    assert result["comparison"] == expected
    assert result["sampling_passed"] is True
    assert result["qualification_complete"] is False and result["program_qualification_complete"] is False
    assert exit_status(result, "qualification") == 1
    assert result["completed_blocks"] == {"baseline": 5, "candidate": 5}


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "cipher", "manifest", "count", "hardware", "failure"])
def test_missing_tampered_or_incomparable_pairs_never_qualify(tmp_path, mutation):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    pairs = tmp_path / "pairs"
    root = pairs / f"pair-{TARGET}-0-17-2"
    context, _, _ = pair_fixture(root, bundle_root, bundle, failed_arm="baseline" if mutation == "failure" else None)
    context.pop("pair_index")
    if mutation == "missing":
        (root / "archive-receipt.json").unlink()
    elif mutation == "duplicate":
        (pairs / "unexpected-pair").mkdir()
    elif mutation == "cipher":
        with (root / "encrypted/observations.hge").open("ab") as stream:
            stream.write(b"x")
    elif mutation == "manifest":
        path = root / "aggregate/pair-manifest.json"
        value = json.loads(path.read_text())
        value["offered_order"] = ["candidate", "baseline"]
        path.write_bytes(canonical(value))
    elif mutation in {"count", "hardware"}:
        path = root / "aggregate/00-candidate.json"
        value = json.loads(path.read_text())
        if mutation == "count":
            next(iter(value["measurements"].values()))["count"] -= 1
        else:
            value["hardware"]["cpu_count"] = 8
        path.write_bytes(canonical(value))
    result = aggregate_pairs(pair_roots=pairs, bundle_root=bundle_root, context=context)
    assert result["collection_complete"] is False and result["comparison_available"] is False
    assert result["sampling_passed"] is False and exit_status(result, "smoke") == 1
    if mutation == "failure":
        assert result["pairs"][0]["arms"] == {"baseline": "failed", "candidate": "completed"}
        assert result["completed_blocks"] == {"baseline": 0, "candidate": 1}


@pytest.mark.parametrize("change", ["delete", "replace"])
def test_archive_checks_exact_numeric_snapshot_despite_extra_journals(tmp_path, change):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "pair"
    context, _, args = pair_fixture(root, bundle_root, bundle, archive=False)
    numeric = root / "private_samples/00-baseline.json"
    if change == "delete":
        numeric.unlink()
    else:
        numeric.write_text('{"substitute":[1]}')
    for index in range(4):
        (root / "private_samples" / f"retained-{index}.jsonl").write_text('{"partial":')
    receipt = archive_pair(args)
    assert receipt["status"] == "encrypted" and receipt["pair_binding"]["numeric_commitments_verified"] is False
    write_public(root / "archive-receipt.json", receipt)
    evidence, reports = validate_pair(root, context, bundle)
    assert evidence["archive_complete"] is True and evidence["collection_complete"] is False
    assert reports == {}


def test_controller_interruption_keeps_unattempted_arm_and_partial_journal(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "pair"
    _, _, args = pair_fixture(root, bundle_root, bundle, archive=False)
    (root / "aggregate/pair-manifest.json").unlink()
    (root / "private_samples/pair-manifest.json").unlink()
    (root / "aggregate/00-candidate-offer.json").unlink()
    (root / "private_samples/00-baseline-numeric.jsonl").write_text('{"latency_ms":10}\n{"cut":')
    receipt = archive_pair(args)
    manifest = read_public(root / "aggregate/pair-manifest.json")
    assert manifest["arms"]["baseline"] == {"status": "failed", "reason": "pair_controller_interrupted"}
    assert manifest["arms"]["candidate"] == {"status": "unattempted"}
    assert manifest["collection_complete"] is False and receipt["status"] == "encrypted"
    assert (root / "private_samples/pair-manifest.json").read_bytes() == (
        root / "aggregate/pair-manifest.json"
    ).read_bytes()


def test_copied_public_manifest_after_interruption_is_retained_exactly(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "pair"
    _, _, args = pair_fixture(root, bundle_root, bundle, archive=False)
    (root / "private_samples/pair-manifest.json").unlink()
    assert archive_pair(args)["status"] == "encrypted"
    assert (root / "private_samples/pair-manifest.json").read_bytes() == (
        root / "aggregate/pair-manifest.json"
    ).read_bytes()


@pytest.mark.parametrize(
    "value", [{"message": "/home/private/file"}, {"raw": "material"}, {"nested": {"message": "a" * 97}}]
)
def test_public_pair_evidence_rejects_instead_of_silently_redacting(tmp_path, value):
    with pytest.raises(ValueError, match="not_safe"):
        write_public(tmp_path / "report.json", value)
    assert not (tmp_path / "report.json").exists()


def test_exact_summary_conservation_catches_count_preserving_numeric_change(tmp_path):
    from scripts.native_slo_pair_record import numeric_commitment

    bundle = bundle_fixture(tmp_path / "bundle")
    plan = sampling_plan(runs=1, qualification=False)
    report, raw = block_fixture(bundle, "baseline", plan)
    raw[next(iter(raw))][0] = 999
    path = tmp_path / "numbers.json"
    path.write_bytes(canonical(raw))
    with pytest.raises(ValueError, match="summary_mismatch"):
        numeric_commitment(path, report, plan)


@pytest.mark.parametrize("field", ["cpu_model", "ram_bytes", "runner_image", "runner_image_os"])
def test_heterogeneous_hosted_runner_cohorts_are_not_pooled(tmp_path, field):
    from copy import deepcopy

    bundle = bundle_fixture(tmp_path / "bundle")
    plan = sampling_plan(runs=5, qualification=True)
    reports = {arm: [deepcopy(block_fixture(bundle, arm, plan)[0]) for _ in range(5)] for arm in bundle["arms"]}
    reports["candidate"][4]["hardware"][field] = 32 if field == "ram_bytes" else "different"
    with pytest.raises(RuntimeError, match="hardware identity"):
        compare_blocks(
            reports,
            mode="qualification",
            runs=5,
            artifact_digests={arm: bundle["arms"][arm]["wheel_sha256"] for arm in reports},
        )


def test_every_missing_full_index_remains_explicit(tmp_path):
    bundle_root = tmp_path / "bundle"
    bundle_fixture(bundle_root)
    context = context_fixture(bundle_root, mode="qualification")
    context.pop("pair_index")
    result = aggregate_pairs(pair_roots=tmp_path / "absent", bundle_root=bundle_root, context=context)
    assert result["expected_pairs"] == 5
    assert [pair["pair_index"] for pair in result["pairs"]] == list(range(5))
    assert all(pair["reason"] == "pair_missing_or_invalid" for pair in result["pairs"])
    assert result["completed_blocks"] == {"baseline": 0, "candidate": 0}
    assert exit_status(result, "qualification") == 1


@pytest.mark.parametrize(
    "key", ["build_sha", "runtime_sha256", "dependency_versions_sha256", "target", "package_origin", "mode"]
)
def test_worker_runtime_or_dependency_drift_cannot_complete_an_arm(tmp_path, key):
    from scripts.native_slo_pair_record import validate_runtime

    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["runtime"][key] = "different"
    with pytest.raises(ValueError):
        validate_runtime(report, bundle["arms"]["candidate"], target=TARGET)


def test_archive_context_and_private_manifest_remain_recoverable(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from scripts.native_slo_evidence_archive import open_archive

    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    root = tmp_path / "pair"
    _, _, args = pair_fixture(root, bundle_root, bundle, archive=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    import hashlib

    args.recipient_id = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    args.public_key = tmp_path / "recipient.pem"
    args.public_key.write_bytes(public)
    receipt = archive_pair(args)
    files, _ = open_archive((root / "encrypted/observations.hge").read_bytes(), private)
    recovered = dict(files)
    assert receipt["pair_binding"]["numeric_commitments_verified"] is True
    assert (
        receipt["pair_binding"]["pair_manifest_sha256"] == hashlib.sha256(recovered["pair-manifest.json"]).hexdigest()
    )
    assert recovered["pair-manifest.json"] == (root / "aggregate/pair-manifest.json").read_bytes()
    for arm in ("baseline", "candidate"):
        assert recovered[f"00-{arm}.json"] == (root / "private_samples" / f"00-{arm}.json").read_bytes()


def test_evidence_hash_rejects_nonregular_files_without_waiting(tmp_path):
    import os

    from scripts.native_slo_pair_io import digest_file

    if os.name == "nt":
        pytest.skip("POSIX FIFO fixture; Windows uses the retained handle reader")
    path = tmp_path / "evidence.json"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="file_invalid"):
        digest_file(path, 4096)
