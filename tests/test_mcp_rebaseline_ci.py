from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import mcp_rebaseline_ci as ci  # noqa: E402
from scripts.mcp_rebaseline_report import write_private  # noqa: E402
from scripts.native_slo_evidence_archive import encrypt_samples  # noqa: E402
from tests.mcp_public_fixture import complete_report  # noqa: E402

CANDIDATE = "a" * 40


def _report():
    return complete_report()


@pytest.mark.parametrize("case", ["valid", "missing", "wrong_source", "extra_raw", "oversized", "step_failed"])
def test_publication_requires_complete_exact_candidate_and_bounded_aggregate(tmp_path, case):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    report = _report()
    if case == "wrong_source":
        report["source_and_environment"]["sources"]["candidate"]["commit"] = "b" * 40
    if case == "extra_raw":
        report["raw_stdout"] = "PRIVATE_FIXTURE_SENTINEL"
    if case == "oversized":
        report["comparisons"] = ["PRIVATE_FIXTURE_SENTINEL" * 100000]
    if case != "missing":
        write_private(private / "aggregate.json", report)
    output = tmp_path / "public" / "component.json"
    observed = ci.publish(
        private, output, candidate=CANDIDATE, outcome="failure" if case == "step_failed" else "success"
    )
    assert observed["qualification"] is False
    assert observed["installed_or_cross_platform_qualification"] is False
    assert (observed["status"] == "passed") == (case == "valid")
    assert "PRIVATE_FIXTURE_SENTINEL" not in output.read_text()
    if case == "step_failed":
        assert all(not comparison["headline_eligible"] for comparison in observed["comparisons"])
    if case not in {"valid", "step_failed"}:
        assert observed["measurements"] is None
        assert observed["expected_worker_attempts"] == 30
        assert observed["expected_tool_call_attempts"] == 10080


def test_archive_reuses_existing_public_recipient_and_retains_partial_attempt(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    write_private(private / "0-baseline-plain.begin.json", {"block": 0, "role": "baseline", "mode": "plain"})
    write_private(private / "0-baseline-plain.raw.journal.jsonl", {"fixture": "PRIVATE_FIXTURE_SENTINEL"})
    archive = tmp_path / "encrypted" / "observations.hge"
    receipt = encrypt_samples(
        source=private,
        output=archive,
        public_key=ROOT / "docs/guard/rust-performance/qualification-recipient.pem",
        recipient_id="db2d2f3b5002f740768855101840eb4a02ee146d0838d92f8611256f93a7379e",
        context={"source_sha": CANDIDATE, "run_id": 1, "run_attempt": 1},
    )
    assert receipt["status"] == "encrypted" and receipt["files"] == 2
    assert b"PRIVATE_FIXTURE_SENTINEL" not in archive.read_bytes()
    assert b"0-baseline-plain.begin.json" not in archive.read_bytes()


def test_actual_worker_retains_request_journal_and_real_default_oracle(tmp_path):
    output = tmp_path / "worker.json"
    process = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/mcp_rebaseline_worker.py"),
            "--source",
            str(ROOT),
            "--output",
            str(output),
            "--calls",
            "2",
            "--diagnostic",
            "--traces",
            "catalog10",
            "inline_approval10ms",
            "loopback_tcp10ms",
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert process.returncode == 0, process.stderr.decode()
    observed = json.loads(output.read_text())
    assert observed["status"] == "passed"
    assert observed["phase_counts"]["quiet_frame_wait"] == 6
    journal = output.with_suffix(".journal.jsonl")
    assert journal.stat().st_mode & 0o777 == 0o600
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    requests = [row for row in rows if row["kind"] == "request"]
    assert len(requests) == 12
    calls = [row for row in requests if row["method"] == "tools/call"]
    assert [row["policy_action"] for row in calls] == ["warn", "warn", "allow", "allow", "warn", "warn"]
    assert all(row["wire_bytes"] > 0 and row["request_sha256"] for row in calls)
    assert all(row["network_service_wall_ns"] >= 10_000_000 for row in calls[-2:])


def test_actual_finalizer_needs_only_isolated_standard_library(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    write_private(private / "aggregate.json", _report())
    output = tmp_path / "public.json"
    observed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "scripts/mcp_rebaseline_ci.py"),
            "--private",
            str(private),
            "--public",
            str(output),
            "--candidate",
            CANDIDATE,
            "--matrix-outcome",
            "success",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert observed.returncode == 0, observed.stderr
    report = json.loads(output.read_text())
    assert report["status"] == "passed" and report["schema"] == "hol-guard.mcp-rebaseline.v2"
    assert len(report["run_trace_summaries"]) == 240 and len(report["paired_comparisons"]) == 8


def test_workflow_pins_sources_and_preserves_private_evidence_after_failed_matrix():
    text = (ROOT / ".github/workflows/mcp-performance-rebaseline.yml").read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["on"]) == {"pull_request", "workflow_dispatch"}
    assert "secrets." not in text and "pull_request_target" not in text
    job = workflow["jobs"]["source-stdio"]
    assert job["runs-on"] == "ubuntu-latest"
    steps = job["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts[0]["with"]["ref"] == "${{ env.MCP_CANDIDATE_SHA }}"
    assert checkouts[1]["with"]["ref"] == ci.BASELINE
    assert all(step["with"]["persist-credentials"] == "false" for step in checkouts)
    matrix = next(step for step in steps if step.get("id") == "matrix")
    assert "--runs 5 --calls 13" in matrix["run"]
    assert '--expected-candidate "$MCP_CANDIDATE_SHA"' in matrix["run"]
    assert '--lock "$RUNNER_TEMP/mcp-rebaseline.lock"' in matrix["run"]
    after = steps[steps.index(matrix) + 1 :]
    assert all(step.get("if") == "always()" for step in after)
    archive = next(step for step in after if step["name"] == "Encrypt private component observations")
    assert "native_slo_evidence_archive.py encrypt" in archive["run"]
    assert "--public-key" in archive["run"] and "--private-key" not in archive["run"]
    uploads = [step["with"]["path"].splitlines() for step in after if "uses" in step]
    assert {path for group in uploads for path in group} == {
        "mcp-evidence/public/component.json",
        "mcp-evidence/archive-receipt.json",
        "mcp-evidence/encrypted/observations.hge",
    }
