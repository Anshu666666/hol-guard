"""Package CI retains failures privately and emits only a finite public table."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts import native_slo_evidence_archive as archive
from scripts import package_rebaseline_ci as ci
from scripts.native_slo_evidence_files import read_samples
from scripts.package_benchmark_corpus import BASELINE, digest, manifest
from scripts.package_benchmark_evidence import write_private
from scripts.package_benchmark_protocol import preset, preset_arms
from tests.test_package_benchmark_controller import valid_report

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux package component CI")
CANDIDATE = "1" * 40


def write_scope(private, scope, *, failed_composer=False, unknown_field=False):
    _, runs, measurement, timeout = next(item for values in ci.PLANS.values() for item in values if item[0] == scope)
    aggregate = private / scope / "aggregate"
    aggregate.mkdir(mode=0o700, parents=True)
    samples = private / scope / "private_samples"
    samples.mkdir(mode=0o700)
    rows = []
    sources = {
        arm: {
            "commit": BASELINE if arm == "baseline" else CANDIDATE,
            "source_sha256": "a" * 64,
            "uv_lock_sha256": "b" * 64,
        }
        for arm in ("baseline", "candidate")
    }
    metadata = {
        **manifest(),
        "selected_cases": list(preset(scope)),
        "runs": runs,
        "samples_per_run": 1,
        "measurement": measurement,
        "timeout_seconds": timeout,
        "timeout_scope": "whole_worker_including_setup_and_postvalidation",
        "offered_attempts": len(preset(scope)) * runs * len(preset_arms(scope)),
        "source": sources,
        "environment": {"synthetic": True},
        "harness_sha256": "c" * 64,
    }
    write_private(aggregate / "manifest.json", metadata)
    for case in preset(scope):
        write_private(samples / (case + ".fixture.json"), {"synthetic": True})
        for run in range(runs):
            for arm in preset_arms(scope):
                offered = {
                    "schema": "hol-guard.package-attempt.v2",
                    "case_id": case,
                    "source": sources[arm],
                    "fixture_sha256": digest(case),
                    "signed_response_sha256": digest(case + "signed"),
                    **{key: metadata[key] for key in ("measurement", "environment", "harness_sha256")},
                }
                row = {
                    **valid_report(offered),
                    "arm": arm,
                    "run": run,
                    "sample": 0,
                    "returncode": 0,
                    "timed_out": False,
                    "containment_failed": False,
                    "output_limit_exceeded": False,
                }
                if case.startswith("bundle_kernel."):
                    row.update(lookups=100, matched=50)
                if ".registry-resolved." in case:
                    from scripts.package_benchmark_registry import REGISTRY_HEADERS, RegistryTransport

                    registry = RegistryTransport(100)
                    registry.observed = [
                        {"url": url, "method": "GET", "headers": REGISTRY_HEADERS, "timeout": 1}
                        for url in registry.expected
                    ]
                    row["registry_transport"] = registry.report()
                if measurement == "attribution":
                    from tests.test_package_benchmark_phases import synthetic_phases

                    row.update(operation_counts={}, phases=synthetic_phases())
                if measurement == "timing":
                    row.update(wall_ms=2.0 if arm == "baseline" else 1.0, cpu_ms=1.0)
                if failed_composer and ".composer." in case and arm == "baseline":
                    row.update(status="failed", returncode=1, mismatch="package_count")
                if unknown_field and not rows:
                    row["raw_stdout"] = "PRIVATE_MARKER"
                write_private(samples / f"{case}.r{run:02d}.s0000.{arm}.jsonl", offered)
                write_private(samples / f"{case}.r{run:02d}.s0000.{arm}.jsonl", row, append=True)
                if row["status"] == "completed" and not case.startswith("bundle_kernel."):
                    write_private(samples / f"{case}.r{run:02d}.s0000.{arm}.semantic.json", {"synthetic": True})
                rows.append(row)
    value = {
        "schema": "hol-guard.package-pairs.v2",
        "status": "incomplete" if failed_composer else "completed",
        "observations": rows,
    }
    write_private(aggregate / ("incomplete.json" if failed_composer else "paired.json"), value)
    return aggregate


def publish(tmp_path, *, plan="format-preflight", outcomes=None):
    return ci.publish(
        tmp_path / "private",
        tmp_path / "public" / "component.json",
        tmp_path / "staging",
        candidate=CANDIDATE,
        plan=plan,
        outcomes=outcomes or {item[0]: "success" for item in ci.PLANS[plan]},
    )


def test_complete_preflight_retains_exact_expected_observation_count(tmp_path):
    write_scope(tmp_path / "private", "format-preflight")
    result = publish(tmp_path)
    assert result["status"] == "completed"
    assert len(result["scopes"][0]["observations"]) == 40
    assert len(result["scopes"][0]["comparisons"]) == 20
    assert result["installed_qualified"] is result["native_benefit_proven"] is result["tail_qualified"] is False


def test_baseline_composer_failure_keeps_candidate_and_other_pairs(tmp_path):
    write_scope(tmp_path / "private", "format-preflight", failed_composer=True)
    result = publish(tmp_path, outcomes={"format-preflight": "failure"})
    scope = result["scopes"][0]
    assert result["status"] == "incomplete" and len(scope["observations"]) == 40
    assert result["private_staging"]["status"] == "complete"
    composer = [row for row in scope["observations"] if ".composer." in row["case_id"]]
    assert [row["status"] for row in composer] == ["failed", "completed", "failed", "completed"]
    assert sum(row["comparable"] for row in scope["comparisons"]) == 18
    assert all(row["reason"] == "incomplete_pair" for row in scope["comparisons"] if ".composer." in row["case_id"])


@pytest.mark.parametrize(
    "fault", ("wrong-candidate", "unknown-output", "invalid-json", "stale-success", "unsafe-harness", "timeout-scope")
)
def test_invalid_scope_cannot_leak_or_be_rescued_by_success_file(tmp_path, fault):
    aggregate = write_scope(tmp_path / "private", "format-preflight", unknown_field=fault == "unknown-output")
    if fault == "invalid-json":
        (aggregate / "paired.json").write_text("PRIVATE_MARKER")
    elif fault in {"wrong-candidate", "unsafe-harness", "timeout-scope"}:
        path = aggregate / "manifest.json"
        metadata = json.loads(path.read_text())
        if fault == "wrong-candidate":
            metadata["source"]["candidate"]["commit"] = "2" * 40
        elif fault == "timeout-scope":
            metadata["timeout_scope"] = "production_parser_deadline"
        else:
            metadata["harness_sha256"] = "PRIVATE_MARKER"
        path.write_text(json.dumps(metadata))
    elif fault == "stale-success":
        write_private(aggregate / "incomplete.json", {"status": "incomplete"})
    result = publish(tmp_path)
    assert result["status"] == "incomplete"
    assert not result["scopes"][0]["comparisons"]
    assert "PRIVATE_MARKER" not in json.dumps(result)


def test_interrupted_run_keeps_private_offered_record_without_inventing_results(tmp_path):
    directory = tmp_path / "private" / "format-preflight" / "private_samples"
    directory.mkdir(mode=0o700, parents=True)
    identifier = preset("format-preflight")[0]
    original = {"status": "offered", "private": "PRIVATE_MARKER"}
    write_private(directory / f"{identifier}.r00.s0000.baseline.jsonl", original)
    result = publish(tmp_path, outcomes={"format-preflight": "cancelled"})
    assert result["status"] == "incomplete" and result["scopes"][0]["observations"] == []
    assert "PRIVATE_MARKER" not in json.dumps(result)
    records = read_samples(tmp_path / "staging" / "format-preflight")
    assert len(records) == 2
    assert json.loads(records[0][1]) == original


def test_staged_partial_journal_survives_the_existing_encrypted_archive(tmp_path):
    directory = tmp_path / "private" / "format-preflight" / "private_samples"
    directory.mkdir(mode=0o700, parents=True)
    identifier = preset("format-preflight")[0]
    path = directory / f"{identifier}.r00.s0000.baseline.jsonl"
    ci.atomic_exclusive(path, b'{"private":"PRIVATE_MARKER"}\n{"partial":')
    result = publish(tmp_path, outcomes={"format-preflight": "failure"})
    records = read_samples(tmp_path / "staging" / "format-preflight")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    recipient = archive.digest(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    encoded = archive.seal(records, public, recipient, context={"source_sha": CANDIDATE})
    assert archive.open_archive(encoded, private)[0] == records
    assert b"PRIVATE_MARKER" not in encoded and "PRIVATE_MARKER" not in json.dumps(result)
    assert records[0][1] == path.read_bytes()


def test_diagnostic_has_three_separate_scopes_and_bounded_archive_groups(tmp_path):
    for scope, _, _, _ in ci.PLANS["diagnostic"]:
        write_scope(tmp_path / "private", scope)
    result = publish(tmp_path, plan="diagnostic")
    assert result["status"] == "completed"
    assert [len(item["observations"]) for item in result["scopes"]] == [72, 2, 10]
    assert set(result["private_staging"]["groups"]) == set(ci.ARCHIVE_GROUPS["diagnostic"])
    for group in ci.ARCHIVE_GROUPS["diagnostic"]:
        assert read_samples(tmp_path / "staging" / group)
    hot = result["scopes"][-1]["summaries"][0]
    assert hot["wall_reduction"]["samples"] == 5 and hot["tail_qualified"] is False


def test_aggregate_success_cannot_hide_a_missing_offered_journal(tmp_path):
    write_scope(tmp_path / "private", "format-preflight")
    sample = next((tmp_path / "private" / "format-preflight" / "private_samples").glob("*.jsonl"))
    sample.unlink()
    result = publish(tmp_path)
    assert result["status"] == "incomplete"
    assert result["private_staging"]["missing_required"] == 1


def test_completed_non_kernel_attempt_requires_its_private_semantic_record(tmp_path):
    write_scope(tmp_path / "private", "format-preflight")
    sample = next((tmp_path / "private" / "format-preflight" / "private_samples").glob("*.semantic.json"))
    sample.unlink()
    result = publish(tmp_path)
    assert result["status"] == "incomplete"
    assert result["private_staging"]["status"] == "incomplete"
    assert result["private_staging"]["missing_required"] == 1


def test_staging_rejects_symlinks_in_known_paths(tmp_path):
    directory = tmp_path / "private" / "format-preflight" / "private_samples"
    directory.mkdir(mode=0o700, parents=True)
    external = tmp_path / "external.json"
    external.write_text("PRIVATE_MARKER")
    (directory / (preset("format-preflight")[0] + ".fixture.json")).symlink_to(external)
    result = publish(tmp_path)
    assert result["status"] == "incomplete" and result["private_staging"]["status"] == "incomplete"
    assert not list((tmp_path / "staging").rglob("record-*.json"))


def test_workflow_has_two_bounded_independent_jobs_and_only_fixed_upload_paths():
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/package-performance-rebaseline.yml"
    ).read_text()
    assert "fail-fast: false" in workflow and "max-parallel: 2" in workflow
    assert "plan: format-preflight\n            timeout: 25" in workflow
    assert "plan: diagnostic\n            timeout: 30" in workflow
    assert BASELINE in workflow and "persist-credentials: false" in workflow
    assert "--preset hot-route --runs 5 --samples 1 --max-attempts 10" in workflow
    assert "--all-cases" not in workflow and "performance-measurement.lock" not in workflow
    uploads = workflow.split("uses: actions/upload-artifact@")[1:]
    assert len(uploads) == 2
    for upload in uploads:
        assert "private_samples" not in upload and "archive-private" not in upload and "**" not in upload
