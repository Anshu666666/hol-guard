"""Independent immutable reproductions preserve security gates and raw artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from scripts.ci import codeql_foundation_diagnostic as diagnostic

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/codeql-foundation-diagnostic.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_diagnostic_is_bounded_read_only_and_cannot_choose_an_arbitrary_source() -> None:
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request", "workflow_dispatch"}
    assert triggers["pull_request"]["branches"] == ["release/3.2"]
    assert triggers["workflow_dispatch"] is None
    job = workflow["jobs"]["snapshot"]
    assert "github.repository == 'hashgraph-online/hol-guard'" in job["if"]
    assert "github.event.pull_request.number == 2954" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert job["timeout-minutes"] == 30
    assert job["strategy"] == {
        "fail-fast": False,
        "max-parallel": 3,
        "matrix": {
            "profile": [
                {
                    "name": "foundation",
                    "label": "Foundation e449",
                    "commit": diagnostic.FOUNDATION_SHA,
                    "root": "foundation-src",
                    "artifact": "codeql-foundation-e449",
                },
                {
                    "name": "implementation",
                    "label": "Implementation abf",
                    "commit": diagnostic.IMPLEMENTATION_SHA,
                    "root": "implementation-src",
                    "artifact": "codeql-implementation-abf",
                },
            ],
            "language": ["actions", "javascript-typescript", "python"],
        },
    }
    assert all(not step.get("continue-on-error", False) for step in job["steps"])
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]) for step in job["steps"] if "uses" in step)


def test_executing_workflow_and_each_snapshot_have_separate_checkout_roots() -> None:
    steps = _workflow()["jobs"]["snapshot"]["steps"]
    checkouts = [step["with"] for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 2
    definition, source = checkouts
    assert "github.event.pull_request.head.sha || github.sha" in definition["ref"]
    assert definition["sparse-checkout-cone-mode"] is False
    assert set(definition["sparse-checkout"].splitlines()) == {
        "/.github/workflows/codeql-foundation-diagnostic.yml",
        "/scripts/ci/codeql_foundation_diagnostic.py",
    }
    assert source["ref"] == "${{ matrix.profile.commit }}"
    assert source["path"] == "${{ matrix.profile.root }}"
    assert all(row["repository"] == "hashgraph-online/hol-guard" for row in checkouts)
    assert all(row["persist-credentials"] is False for row in checkouts)
    init = next(step for step in steps if step.get("id") == "init")
    analyze = next(step for step in steps if step.get("id") == "analyze")
    assert init["with"]["source-root"] == source["path"]
    assert analyze["with"]["checkout_path"] == "${{ github.workspace }}/" + source["path"]
    assert "foundation-src" not in definition["sparse-checkout"]
    assert "implementation-src" not in definition["sparse-checkout"]
    verify = next(step for step in steps if "diagnostic.py verify" in step.get("run", ""))
    assert verify["env"]["DIAGNOSTIC_PROFILE"] == "${{ matrix.profile.name }}"
    assert verify["env"]["DIAGNOSTIC_SOURCE"] == "${{ matrix.profile.root }}"
    assert '--profile "$DIAGNOSTIC_PROFILE" --source-root "$DIAGNOSTIC_SOURCE"' in verify["run"]


def test_original_query_scope_is_retained_without_pr2954_filter_or_security_upload() -> None:
    job = _workflow()["jobs"]["snapshot"]
    assert job["env"]["CODEQL_ACTION_DIFF_INFORMED_QUERIES"] == "false"
    init = next(step for step in job["steps"] if step.get("id") == "init")
    analyze = next(step for step in job["steps"] if step.get("id") == "analyze")
    assert init["uses"].endswith("@" + diagnostic.CODEQL_ACTION_SHA)
    assert analyze["uses"].endswith("@" + diagnostic.CODEQL_ACTION_SHA)
    assert init["with"]["tools"] == (
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst"
    )
    assert init["with"]["build-mode"] == "none"
    assert "queries" not in init["with"] and "packs" not in init["with"]
    assert yaml.safe_load(init["with"]["config"]) == {
        "paths-ignore": ["src/codex_plugin_scanner/guard/stable_digest.py"]
    }
    # The pinned action maps deprecated false to failure-only, so false is unsafe here.
    assert analyze["with"]["upload"] == "never"
    assert analyze["with"]["upload-database"] is False
    assert analyze["with"]["wait-for-processing"] is False
    assert not analyze["with"].get("skip-queries", False)


def test_failed_analysis_still_collects_and_uploads_only_results_and_manifest() -> None:
    steps = _workflow()["jobs"]["snapshot"]["steps"]
    collect = next(step for step in steps if "INIT_OUTCOME" in step.get("env", {}))
    artifact = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert collect["if"] == artifact["if"] == "${{ always() }}"
    assert collect["env"]["DIAGNOSTIC_PROFILE"] == "${{ matrix.profile.name }}"
    assert collect["env"]["DIAGNOSTIC_SOURCE"] == "${{ matrix.profile.root }}"
    assert '--profile "$DIAGNOSTIC_PROFILE"' in collect["run"]
    assert collect["env"]["INIT_OUTCOME"] == "${{ steps.init.outcome }}"
    assert collect["env"]["ANALYZE_OUTCOME"] == "${{ steps.analyze.outcome }}"
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in artifact["with"]["name"]
    assert artifact["with"]["path"].splitlines() == [
        "${{ runner.temp }}/codeql-foundation-results/*.sarif",
        "${{ runner.temp }}/codeql-foundation-results/diagnostic.json",
    ]
    assert artifact["with"]["if-no-files-found"] == "error"
    assert artifact["with"]["retention-days"] == 14
    assert artifact["with"]["include-hidden-files"] is False


@pytest.fixture
def pinned_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        diagnostic,
        "source_identity",
        lambda _, profile_name="foundation": {
            "available": True,
            "commit": diagnostic.PROFILES[profile_name].commit,
            "tree": diagnostic.PROFILES[profile_name].tree,
            "tracked_clean": True,
            "matches_pin": True,
        },
    )


def _write_sarif(root: Path, body: object | None = None) -> bytes:
    raw = (
        json.dumps(
            body if body is not None else {"version": "2.1.0", "runs": [{"results": [{"ruleId": "example/high"}]}]},
            indent=3,
        ).encode()
        + b"\n\n"
    )
    (root / "python.sarif").write_bytes(raw)
    return raw


@pytest.mark.parametrize("profile_name", ["foundation", "implementation"])
def test_complete_diagnostic_retains_exact_bytes_without_clearing_findings(
    tmp_path: Path, pinned_source: None, profile_name: str
) -> None:
    raw = _write_sarif(tmp_path)
    report = diagnostic.collect(tmp_path, tmp_path, "python", "2.27.0", "success", "success", profile_name=profile_name)
    assert report["diagnostic_analysis_complete"] is True
    assert report["original_security_alerts_resolved"] is False
    assert report["sarif"] == {
        "file": "python.sarif",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "runs": 1,
        "results": 1,
    }
    assert (tmp_path / "python.sarif").read_bytes() == raw
    assert json.loads((tmp_path / "diagnostic.json").read_text()) == report


@pytest.mark.parametrize(
    ("version", "init", "analyze", "expected"),
    [
        ("", "failure", "skipped", {"codeql_version_unproven", "initialization_incomplete", "analysis_incomplete"}),
        ("2.27.0", "success", "failure", {"analysis_incomplete"}),
        ("2.28.0", "success", "success", {"codeql_version_unproven"}),
    ],
)
def test_partial_analysis_remains_failed_despite_valid_sarif(
    tmp_path: Path, pinned_source: None, version: str, init: str, analyze: str, expected: set[str]
) -> None:
    _write_sarif(tmp_path)
    report = diagnostic.collect(tmp_path, tmp_path, "python", version, init, analyze)
    assert set(report["errors"]) == expected
    assert report["diagnostic_analysis_complete"] is False
    assert report["sarif"]["results"] == 1
    assert json.loads((tmp_path / "diagnostic.json").read_text()) == report


def test_missing_analysis_writes_actionable_incomplete_manifest(tmp_path: Path, pinned_source: None) -> None:
    report = diagnostic.collect(tmp_path, tmp_path / "not-created", "python", "", "failure", "skipped")
    assert report["diagnostic_analysis_complete"] is False
    assert "sarif_unavailable" in report["errors"]
    assert (tmp_path / "not-created/diagnostic.json").is_file()


@pytest.mark.parametrize("body", [{}, {"version": "2.1.0", "runs": []}, {"version": "2.1.0", "runs": [{}]}, []])
def test_malformed_sarif_cannot_be_reported_as_a_complete_scan(tmp_path: Path, body: object) -> None:
    raw = _write_sarif(tmp_path, body)
    identity, errors = diagnostic.sarif_identity(tmp_path / "python.sarif")
    assert errors == ["sarif_invalid"]
    assert identity["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / "python.sarif").read_bytes() == raw


def test_oversized_sarif_does_not_receive_a_misleading_partial_file_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostic, "MAX_SARIF_BYTES", 16)
    (tmp_path / "python.sarif").write_bytes(b"x" * 17)
    identity, errors = diagnostic.sarif_identity(tmp_path / "python.sarif")
    assert errors == ["sarif_size_limit"]
    assert "sha256" not in identity


def test_git_source_pin_rejects_dirty_files_and_changed_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, capture_output=True)
    fixture = tmp_path / "fixture.py"
    fixture.write_text("VALUE = 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "fixture.py"], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        check=True,
        capture_output=True,
    )
    identity = diagnostic.source_identity(tmp_path)
    assert identity["matches_pin"] is False
    monkeypatch.setitem(
        diagnostic.PROFILES,
        "foundation",
        replace(diagnostic.PROFILES["foundation"], commit=identity["commit"], tree=identity["tree"]),
    )
    assert diagnostic.source_identity(tmp_path)["matches_pin"] is True
    fixture.write_text("VALUE = 2\n")
    assert diagnostic.source_identity(tmp_path)["matches_pin"] is False
    report = diagnostic.collect(tmp_path, tmp_path / "results", "python", "2.27.0", "success", "success")
    assert "foundation_identity_mismatch" in report["errors"]
    assert report["diagnostic_analysis_complete"] is False


def test_collector_cli_returns_failure_after_preserving_incomplete_manifest(
    tmp_path: Path, pinned_source: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "codeql_foundation_diagnostic.py",
            "collect",
            "--source-root",
            str(tmp_path),
            "--results-root",
            str(tmp_path),
            "--language",
            "python",
            "--init-outcome",
            "failure",
            "--analyze-outcome",
            "skipped",
        ],
    )
    assert diagnostic.main() == 1
    report = json.loads((tmp_path / "diagnostic.json").read_text())
    assert report["diagnostic_analysis_complete"] is False
    assert report["initialization_outcome"] == "failure"


def test_verifier_cli_rejects_unavailable_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["codeql_foundation_diagnostic.py", "verify", "--source-root", str(tmp_path)])
    with pytest.raises(SystemExit) as failure:
        diagnostic.main()
    assert failure.value.code == 1


@pytest.mark.parametrize("profile_name", ["foundation", "implementation"])
@pytest.mark.parametrize("language", ["actions", "javascript-typescript", "python"])
def test_each_snapshot_language_retains_its_own_original_alert_and_analysis_provenance(
    tmp_path: Path, pinned_source: None, profile_name: str, language: str
) -> None:
    raw = _write_sarif(tmp_path)
    (tmp_path / "python.sarif").rename(tmp_path / diagnostic.SARIF_FILES[language])
    report = diagnostic.collect(tmp_path, tmp_path, language, "2.27.0", "success", "success", profile_name=profile_name)
    expected = {
        "foundation": {
            "commit": "e449594e86c717e66e14598a4130475de79c536f",
            "tree": "b6a17d026500c1821d02b5a9202b544be0874377",
            "merge": "b9395b11c216a52a0bea9eb937d7cd7cf6b2770b",
            "run": 35181898004,
            "check": 105075778732,
            "high": 2,
            "jobs": {"actions": 105075647482, "javascript-typescript": 105075647388, "python": 105075647242},
        },
        "implementation": {
            "commit": "abf319d5a345d761d88e26ba787026e98370c26f",
            "tree": "62eb319323cc7c9de7513af6ef7f05009d411189",
            "merge": "70b456e93a77fff48522ee7aa6ddeec6d157f6e6",
            "run": 35229526605,
            "check": 105229882410,
            "high": 3,
            "jobs": {"actions": 105229666643, "javascript-typescript": 105229666837, "python": 105229666277},
        },
    }[profile_name]
    assert report["profile"] == profile_name
    assert report["expected_commit"] == report["source"]["commit"] == expected["commit"]
    assert report["expected_tree"] == report["source"]["tree"] == expected["tree"]
    assert report["original_analyzed_merge"] == expected["merge"]
    assert report["original_workflow_run"] == expected["run"]
    assert report["original_analysis_job"] == expected["jobs"][language]
    assert report["original_alert_check"] == expected["check"]
    assert report["original_high_alert_count"] == expected["high"]
    assert report["original_alert_overlap_known"] is False
    assert report["original_security_alerts_resolved"] is False
    assert report["sarif"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads((tmp_path / "diagnostic.json").read_text()) == report


def test_six_matrix_jobs_have_distinct_source_language_and_artifact_scopes() -> None:
    job = _workflow()["jobs"]["snapshot"]
    matrix = job["strategy"]["matrix"]
    pairs = [(profile, language) for profile in matrix["profile"] for language in matrix["language"]]
    assert len(pairs) == 6
    assert len({(profile["commit"], language) for profile, language in pairs}) == 6
    assert len({(profile["artifact"], language) for profile, language in pairs}) == 6
    assert {profile["name"] for profile, _ in pairs} == set(diagnostic.PROFILES)
    assert all(profile["commit"] == diagnostic.PROFILES[profile["name"]].commit for profile, _ in pairs)
    artifact = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert artifact["with"]["name"] == (
        "${{ matrix.profile.artifact }}-${{ matrix.language }}-${{ github.run_id }}-${{ github.run_attempt }}"
    )


@pytest.mark.parametrize("actual_profile", ["foundation", "implementation"])
def test_one_clean_snapshot_cannot_satisfy_the_other_snapshot_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, actual_profile: str
) -> None:
    actual = diagnostic.PROFILES[actual_profile]

    def git_result(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=f"{actual.commit}\n{actual.tree}\n")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(diagnostic.subprocess, "run", git_result)
    other_profile = "implementation" if actual_profile == "foundation" else "foundation"
    assert diagnostic.source_identity(tmp_path, actual_profile)["matches_pin"] is True
    assert diagnostic.source_identity(tmp_path, other_profile)["matches_pin"] is False
    _write_sarif(tmp_path)
    report = diagnostic.collect(
        tmp_path, tmp_path, "python", "2.27.0", "success", "success", profile_name=other_profile
    )
    assert report["errors"] == [f"{other_profile}_identity_mismatch"]
    assert report["diagnostic_analysis_complete"] is False
    assert report["source"]["commit"] == actual.commit
    assert report["expected_commit"] == diagnostic.PROFILES[other_profile].commit
    assert report["sarif"]["results"] == 1
    assert json.loads((tmp_path / "diagnostic.json").read_text()) == report


@pytest.mark.parametrize("profile", ["release/3.2", diagnostic.IMPLEMENTATION_SHA, "custom", ""])
def test_cli_rejects_refs_and_nonallowlisted_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    monkeypatch.setattr("sys.argv", ["diagnostic", "verify", "--source-root", str(tmp_path), "--profile", profile])
    with pytest.raises(SystemExit) as failure:
        diagnostic.main()
    assert failure.value.code == 2


def test_implementation_cli_preserves_failed_phase_and_its_three_unresolved_alerts(
    tmp_path: Path, pinned_source: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _write_sarif(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "diagnostic",
            "collect",
            "--profile",
            "implementation",
            "--source-root",
            str(tmp_path),
            "--results-root",
            str(tmp_path),
            "--language",
            "python",
            "--observed-version",
            "2.27.0",
            "--init-outcome",
            "success",
            "--analyze-outcome",
            "failure",
        ],
    )
    assert diagnostic.main() == 1
    report = json.loads((tmp_path / "diagnostic.json").read_text())
    assert report["profile"] == "implementation"
    assert report["errors"] == ["analysis_incomplete"]
    assert report["original_high_alert_count"] == 3
    assert report["original_security_alerts_resolved"] is False
    assert report["sarif"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / "python.sarif").read_bytes() == raw
