from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts import native_slo_evidence_archive as archive
from scripts import scanner_pilot_ci as ci
from scripts.native_slo_evidence_format import canonical, digest
from scripts.scanner_pilot_protocol import BudgetExceededError, planned
from tests.scanner_pilot_fixtures import SOURCE_SHA, encoded, snapshot


@pytest.fixture
def recipient(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(ci, "RECIPIENT", digest(der))
    path = tmp_path / "recipient.pem"
    path.write_bytes(public)
    return path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def evidence(tmp_path, *, selection="smoke"):
    output = tmp_path / "evidence"
    private = output / "private_samples"
    private.mkdir(parents=True)
    for name, data in encoded(snapshot(selection=selection)):
        (private / name).write_bytes(data)
    return output


def seal(output, recipient):
    return ci.seal_evidence(
        output,
        public_key=recipient,
        source_sha=SOURCE_SHA,
        case="working_provider_large",
        run=0,
        selection="smoke",
        run_id=1,
        run_attempt=1,
    )


def test_init_retains_all_planned_work_before_setup_and_refuses_reuse(tmp_path):
    output = tmp_path / "evidence"
    ci.initialize(output, source_sha=SOURCE_SHA, case="working_provider_large", run=0, selection="smoke")
    value = json.loads((output / "private_samples/plan.json").read_text())
    assert value["attempts"] == planned("working_provider_large", 0)
    assert len(value["attempts"]) == 24
    with pytest.raises(FileExistsError):
        ci.initialize(output, source_sha=SOURCE_SHA, case="working_provider_large", run=0, selection="smoke")


def test_exact_encrypted_snapshot_and_public_association_round_trip(tmp_path, recipient):
    output = evidence(tmp_path)
    before = (output / "private_samples/plan.json").read_bytes()
    assert seal(output, recipient[0])
    ci.verify_retention(output)
    files, _ = archive.open_archive((output / "observations.hge").read_bytes(), recipient[1])
    assert dict(files)["plan.json"] == before
    summary = json.loads((output / "public/summary.json").read_text())
    assert summary["private_files"] == len(files)
    assert summary["commitments_sha256"] == digest(
        canonical([{"name": name, "bytes": len(data), "sha256": digest(data)} for name, data in files])
    )


def test_post_snapshot_path_replacement_does_not_change_sealed_or_projected_bytes(tmp_path, recipient, monkeypatch):
    output = evidence(tmp_path)
    target = output / "private_samples/plan.json"
    original = target.read_bytes()
    encrypt = ci.encrypt_samples

    def replace_after_snapshot(**kwargs):
        observer = kwargs["snapshot_observer"]

        def observe(files):
            observer(files)
            target.write_bytes(b'{"changed":"private replacement"}')

        kwargs["snapshot_observer"] = observe
        return encrypt(**kwargs)

    monkeypatch.setattr(ci, "encrypt_samples", replace_after_snapshot)
    assert seal(output, recipient[0])
    ci.verify_retention(output)
    files, _ = archive.open_archive((output / "observations.hge").read_bytes(), recipient[1])
    assert dict(files)["plan.json"] == original and target.read_bytes() != original


def test_failure_after_projection_cannot_be_admitted_by_aggregator(tmp_path, recipient, monkeypatch):
    output = evidence(tmp_path)
    monkeypatch.setattr(archive, "seal", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("seal failed")))
    with pytest.raises(ValueError):
        seal(output, recipient[0])
    # Projection succeeded; encrypted archive did not. Never derive a passing
    # cohort from this individually well-formed numeric summary.
    assert json.loads((output / "public/summary.json").read_text())["collection_complete"]
    with pytest.raises(ValueError):
        ci.admitted_public(output / "public")
    aggregate = tmp_path / "aggregate.json"
    assert not ci.combine(output, aggregate, selection="smoke", source_sha=SOURCE_SHA, shards_outcome="success")
    value = json.loads(aggregate.read_text())
    assert value["invalid_shards"] == 1 and not value["minimum_independent_runs_met"]
    assert all(row["comparison"] is None and not row["benefit_gate_passed"] for row in value["cohorts"])


@pytest.mark.parametrize("mutation", ["recipient", "count", "summary", "context"])
def test_retention_mismatch_rejected_before_comparison(tmp_path, recipient, mutation):
    output = evidence(tmp_path)
    seal(output, recipient[0])
    if mutation == "summary":
        (output / "public/summary.json").write_bytes(b"{}")
    elif mutation == "context":
        target = output / "public/retention.json"
        value = json.loads(target.read_text())
        value["run"] = 1
        target.write_bytes(canonical(value))
    else:
        target = output / "public/archive-receipt.json"
        value = json.loads(target.read_text())
        value["recipient_key_id" if mutation == "recipient" else "files"] = "0" * 64 if mutation == "recipient" else 1
        target.write_bytes(canonical(value))
    with pytest.raises(ValueError):
        ci.admitted_public(output / "public")


def test_failed_encrypted_upload_clears_derived_claims_even_with_valid_local_receipt(tmp_path, recipient):
    output = evidence(tmp_path)
    seal(output, recipient[0])
    aggregate = tmp_path / "aggregate.json"
    assert not ci.combine(output, aggregate, selection="smoke", source_sha=SOURCE_SHA, shards_outcome="failure")
    value = json.loads(aggregate.read_text())
    assert not value["upstream_retention_passed"] and not value["collection_complete"]
    assert all(row["comparison"] is None and not row["benefit_gate_passed"] for row in value["cohorts"])


def test_excess_summary_inventory_retains_failed_aggregate_without_comparing_subset(tmp_path, monkeypatch):
    for label in ("expected", "unexpected"):
        child = tmp_path / "shards" / label
        child.mkdir(parents=True)
        (child / "summary.json").write_text("{}")
    monkeypatch.setattr(ci, "admitted_public", lambda *_: pytest.fail("excess inventory must not admit a subset"))
    target = tmp_path / "aggregate.json"
    assert not ci.combine(
        tmp_path / "shards", target, selection="smoke", source_sha=SOURCE_SHA, shards_outcome="success"
    )
    report = json.loads(target.read_text())
    assert report["status"] == "aggregate_file_bound" and report["summary_files_observed_minimum"] == 2
    assert report["planned_attempts"] == 24 and report["invalid_shards"] == 1
    assert not report["collection_complete"] and not report["minimum_independent_runs_met"]
    assert all(row["comparison"] is None and not row["benefit_gate_passed"] for row in report["cohorts"])


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only flock/alarm collector")
def test_controller_budget_retains_unoffered_plan_and_fixed_failure(tmp_path, monkeypatch):
    from scripts import scanner_pilot_worker as worker
    from scripts import secret_scan_benchmark_fixtures as fixtures

    monkeypatch.setitem(sys.modules, "secret_scan_benchmark_fixtures", fixtures)
    monkeypatch.setattr(worker, "identities", lambda *_args: {})

    def create(target, _case):
        target.mkdir()
        return {"files": 4, "input_bytes": 1048576, "file_occurrences": 4}

    monkeypatch.setattr(fixtures, "create_fixture", create)
    monkeypatch.setattr(worker, "preflight", lambda *_args: (_ for _ in ()).throw(BudgetExceededError()))
    output = tmp_path / "evidence"
    ci.initialize(output, source_sha=SOURCE_SHA, case="working_provider_large", run=0, selection="smoke")
    assert not worker.collect(
        Path(__file__).resolve().parents[1],
        tmp_path / "not-launched",
        output / "private_samples",
        expected_source=SOURCE_SHA,
        lock=tmp_path / "test.lock",
    )
    assert len(json.loads((output / "private_samples/plan.json").read_text())["attempts"]) == 24
    assert not list((output / "private_samples").glob("*.offered.json"))
    assert json.loads((output / "private_samples/worker.json").read_text())["failure"] == "controller_deadline"
