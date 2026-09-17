"""The foundation reproduction preserves security gates and actionable artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
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
    job = workflow["jobs"]["foundation"]
    assert "github.repository == 'hashgraph-online/hol-guard'" in job["if"]
    assert "github.event.pull_request.number == 2954" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert job["timeout-minutes"] == 30
    assert job["strategy"] == {
        "fail-fast": False,
        "max-parallel": 3,
        "matrix": {"language": ["actions", "javascript-typescript", "python"]},
    }
    assert all(not step.get("continue-on-error", False) for step in job["steps"])
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]) for step in job["steps"] if "uses" in step)


def test_executing_workflow_and_foundation_have_separate_checkout_roots() -> None:
    steps = _workflow()["jobs"]["foundation"]["steps"]
    checkouts = [step["with"] for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 2
    definition, source = checkouts
    assert "github.event.pull_request.head.sha || github.sha" in definition["ref"]
    assert definition["sparse-checkout-cone-mode"] is False
    assert set(definition["sparse-checkout"].splitlines()) == {
        "/.github/workflows/codeql-foundation-diagnostic.yml",
        "/scripts/ci/codeql_foundation_diagnostic.py",
    }
    assert source["ref"] == diagnostic.FOUNDATION_SHA
    assert source["path"] == "foundation-src"
    assert all(row["repository"] == "hashgraph-online/hol-guard" for row in checkouts)
    assert all(row["persist-credentials"] is False for row in checkouts)
    init = next(step for step in steps if step.get("id") == "init")
    analyze = next(step for step in steps if step.get("id") == "analyze")
    assert init["with"]["source-root"] == source["path"]
    assert analyze["with"]["checkout_path"] == "${{ github.workspace }}/" + source["path"]
    assert "foundation-src" not in definition["sparse-checkout"]


def test_original_query_scope_is_retained_without_pr2954_filter_or_security_upload() -> None:
    job = _workflow()["jobs"]["foundation"]
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
    steps = _workflow()["jobs"]["foundation"]["steps"]
    collect = next(step for step in steps if "INIT_OUTCOME" in step.get("env", {}))
    artifact = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert collect["if"] == artifact["if"] == "${{ always() }}"
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
        lambda _: {
            "available": True,
            "commit": diagnostic.FOUNDATION_SHA,
            "tree": diagnostic.FOUNDATION_TREE,
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


def test_complete_diagnostic_retains_exact_bytes_without_clearing_findings(tmp_path: Path, pinned_source: None) -> None:
    raw = _write_sarif(tmp_path)
    report = diagnostic.collect(tmp_path, tmp_path, "python", "2.27.0", "success", "success")
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
    monkeypatch.setattr(diagnostic, "FOUNDATION_SHA", identity["commit"])
    monkeypatch.setattr(diagnostic, "FOUNDATION_TREE", identity["tree"])
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
