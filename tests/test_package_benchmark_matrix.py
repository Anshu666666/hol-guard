"""Finite package corpus and failure-preserving paired evidence; no timings."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.package_benchmark_corpus import FORMATS, Case, bundle, digest, fixture, lockfile, manifest, matrix
from scripts.package_benchmark_evidence import compare_pair, sign_fixture, write_private
from scripts.package_benchmark_oracle import OracleMismatchError, normalized, validate_evaluation

ROOT = Path(__file__).resolve().parents[1]


def test_matrix_is_finite_independent_and_does_not_relabel_boundaries():
    cases = matrix()
    assert len(cases) == len({case.id for case in cases}) == 567
    assert sum(case.mode in {"absent", "exact", "deny"} for case in cases) == 540
    assert sum(case.mode == "unresolved" for case in cases) == 18
    assert sum(case.route == "bundle_kernel" for case in cases) == 9
    assert manifest()["matrix_digest"] == digest([case.to_dict() for case in cases])
    with pytest.raises(ValueError, match="boundary"):
        Case("npm", 100, 100, "unversioned", "evaluator")
    with pytest.raises(ValueError, match="case_invalid"):
        Case("npm", 101, 100, "exact", "evaluator")


@pytest.mark.parametrize("fmt", FORMATS, ids=lambda fmt: fmt.name)
def test_valid_format_fixtures_contain_distinct_dependencies_and_exact_bundle_cardinality(fmt):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _parse_lockfile_text_result

    case = Case(fmt.name, 100, 1000, "exact", "evaluator")
    source = lockfile(case)
    parsed = _parse_lockfile_text_result(fmt.filename, source)
    assert parsed.complete
    assert len(parsed.entries) == len({item.package_name for item in parsed.entries}) == 100
    assert len(bundle(case)["packages"]) == 1000
    assert fixture(case)["files"][fmt.filename] == source


def test_unversioned_fixture_forces_highest_risk_selection():
    payload = bundle(Case("npm", 100, 100, "unversioned", "bundle_kernel"))
    first, second = payload["packages"][:2]
    assert first["name"] == second["name"]
    assert first["version"] != second["version"]
    assert first["riskScore"] < second["riskScore"]
    assert first["defaultAction"] == "monitor" and second["defaultAction"] == "block"


def test_semantic_normalization_keeps_unknown_fields_reasons_and_completeness():
    actual = {
        "package_intent_hash": "ephemeral",
        "workspace_fingerprint": "bound-separately",
        "new_field": "kept",
        "packages": [
            {
                "lockfileParseElapsedMs": 1.2,
                "lockfileParserVersion": "complete-v2",
                "lockfileParseComplete": False,
                "reasons": [{"code": "deadline_exceeded"}],
            }
        ],
    }
    assert normalized(actual) == {
        "new_field": "kept",
        "packages": [
            {
                "lockfileParserVersion": "complete-v2",
                "lockfileParseComplete": False,
                "reasons": [{"code": "deadline_exceeded"}],
            }
        ],
    }


@pytest.mark.parametrize(
    "field", ("case_id", "fixture_sha256", "signed_response_sha256", "environment", "harness_sha256", "measurement")
)
def test_comparison_rejects_wrong_pair_identity(field):
    baseline = {"status": "completed", field: "one"}
    candidate = {**baseline, field: "two"}
    result = compare_pair(baseline, candidate)
    assert result == {"comparable": False, "reason": "pair_identity_mismatch", "field": field}


@pytest.mark.parametrize("status", ("offered", "setup_started", "measurement_started", "failed", "censored"))
def test_partial_results_never_become_comparable(status):
    assert compare_pair({"status": status}, {"status": "completed"}) == {
        "comparable": False,
        "reason": "incomplete_pair",
    }


@pytest.mark.parametrize("field", ("semantic_sha256", "evidence_sha256", "entry_sha256", "protect_sha256"))
def test_comparison_retains_intentional_contract_differences(field):
    baseline = {"status": "completed", "parser_version": "complete-v1", field: "before"}
    candidate = {**baseline, "parser_version": "complete-v2", field: "after"}
    value = compare_pair(baseline, candidate)
    assert value["comparable"] is False and value["reason"] == "contract_difference"
    assert value["baseline_parser"] == "complete-v1" and value["candidate_parser"] == "complete-v2"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux private-file admission")
def test_private_writer_preserves_prior_evidence_and_rejects_links(tmp_path):
    path = tmp_path / "evidence.json"
    write_private(path, {"offered": True})
    with pytest.raises(FileExistsError):
        write_private(path, {"overwritten": True})
    assert json.loads(path.read_text()) == {"offered": True}
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        write_private(alias, {}, append=True)


def worker_case(case, tmp_path, monkeypatch, *, measurement="validation"):
    from scripts.package_benchmark_worker import run

    # Restore the worker's explicit no-network assignments when this in-process
    # correctness test ends. Production invokes it only in an isolated child.
    monkeypatch.setattr(socket, "create_connection", socket.create_connection)
    monkeypatch.setattr(socket.socket, "connect", socket.socket.connect)
    monkeypatch.setattr(socket.socket, "connect_ex", socket.socket.connect_ex)
    value = fixture(case)
    response, trusted = sign_fixture(value["bundle"])
    fixture_file = tmp_path / "fixture.json"
    write_private(fixture_file, {"fixture": value, "response": response, "trusted_fingerprint": trusted})
    return run(
        argparse.Namespace(
            source_root=ROOT,
            fixture=fixture_file,
            journal=tmp_path / "journal.jsonl",
            semantic=tmp_path / "semantic.json",
            temporary_root=tmp_path,
            measurement=measurement,
        )
    )


def worker_cli_case(case, tmp_path, *, measurement="validation"):
    """Use the actual fresh-worker boundary, outside pytest's shared profiler."""
    value = fixture(case)
    response, trusted = sign_fixture(value["bundle"])
    fixture_file = tmp_path / "fixture.json"
    write_private(fixture_file, {"fixture": value, "response": response, "trusted_fingerprint": trusted})
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/package_benchmark_worker.py"),
            "--source-root",
            str(ROOT),
            "--fixture",
            str(fixture_file),
            "--journal",
            str(tmp_path / "journal.jsonl"),
            "--semantic",
            str(tmp_path / "semantic.json"),
            "--temporary-root",
            str(tmp_path),
            "--measurement",
            measurement,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout
    assert not completed.stderr
    result = json.loads(completed.stdout)
    assert result["bundle_admission_verified_before_route"] is True
    assert result["fixture_sha256"] == digest(value)
    assert result["signed_response_sha256"] == digest(response)
    assert result["measurement"] == measurement
    return result


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="initial package runner declares Linux only")
@pytest.mark.parametrize("fmt", tuple(fmt for fmt in FORMATS if fmt.name != "composer"), ids=lambda fmt: fmt.name)
def test_actual_evaluator_correctness_without_timing(fmt, tmp_path, monkeypatch):
    value = worker_case(Case(fmt.name, 100, 100, "exact", "evaluator"), tmp_path, monkeypatch)
    assert value["status"] == "completed" and value["entries"] == 100
    assert "wall_ms" not in value and "cpu_ms" not in value


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="initial package runner declares Linux only")
@pytest.mark.parametrize("mode", ("absent", "deny", "unresolved", "unversioned"))
def test_actual_modes_have_frozen_outcomes_without_timing(mode, tmp_path, monkeypatch):
    route = "bundle_kernel" if mode == "unversioned" else "evaluator"
    value = worker_case(Case("npm", 100, 100, mode, route), tmp_path, monkeypatch)
    assert value["status"] == "completed"
    assert "wall_ms" not in value and "cpu_ms" not in value


def test_composer_transitive_coverage_gap_is_not_a_fast_success():
    # Frozen baseline witness: only its direct anchor survives the slash-path
    # filter. Keep this oracle independent of whether candidate code is fixed.
    with pytest.raises(OracleMismatchError, match="package_count"):
        validate_evaluation(
            Case("composer", 100, 100, "exact", "evaluator"),
            {"decision": "block", "policy_action": "block", "packages": [{"name": "bench-anchor"}]},
            [],
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="initial package runner declares Linux only")
def test_actual_protect_dry_run_without_timing_or_install(tmp_path, monkeypatch):
    value = worker_case(Case("npm", 100, 100, "exact", "protect_dry_run"), tmp_path, monkeypatch)
    assert value["status"] == "completed" and value["protect_sha256"]
    assert "wall_ms" not in value and "cpu_ms" not in value
