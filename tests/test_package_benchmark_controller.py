"""Controller faults cannot be promoted to successful paired evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

from scripts import package_benchmark_matrix as controller
from scripts.package_benchmark_corpus import BASELINE, Case, matrix, shards
from scripts.package_benchmark_protocol import IDENTITY_FIELDS, descriptive_summary, preset, validate_worker_report

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="declared Linux diagnostic runner")


def valid_report(offered):
    return {
        "schema": offered["schema"],
        **{key: offered[key] for key in IDENTITY_FIELDS},
        "status": "completed",
        "complete": True,
        "installed_artifact": False,
        "native_activation_authorized": False,
        "cpu_scope": "self_plus_waited_children",
        "worker_address_space_limit": 4 * 1024**3,
        "worker_file_size_limit": 64 * 1024**2,
        "semantic_sha256": "a" * 64,
        "evidence_sha256": "b" * 64,
        "protect_sha256": "c" * 64,
        "entry_sha256": "d" * 64,
        "input_sha256": "e" * 64,
        "parser_version": "complete-v2",
        "packages": 100,
        "evidence_rows": 100,
        "entries": 100,
        "input_bytes": 2000,
        "decision": "block",
    }


def setup_controller(tmp_path, monkeypatch, *, mode="ok", runs=1):
    from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch

    baseline, candidate = tmp_path / "baseline", tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    args = argparse.Namespace(
        baseline_root=baseline,
        candidate_root=candidate,
        candidate_sha="1" * 40,
        python=sys.executable,
        output=tmp_path / "results",
        case=[Case("npm", 100, 100, "exact", "evaluator").id],
        all_cases=False,
        preset=None,
        runs=runs,
        samples=1,
        max_attempts=100,
        timeout_seconds=15,
        measurement="validation",
    )
    reads = []

    def identity(root):
        reads.append(root)
        return {
            "commit": BASELINE if root == baseline else args.candidate_sha,
            "source_sha256": "changed" if mode == "source-change" and len(reads) > 2 else "stable",
        }

    monkeypatch.setattr(controller, "source_identity", identity)
    monkeypatch.setattr(controller, "environment_identity", lambda: {"environment": "shared"})
    monkeypatch.setattr(controller, "harness_identity", lambda _root: "f" * 64)
    monkeypatch.setattr(controller, "sign_fixture", lambda value: ({"bundle": value}, "a" * 64))
    calls = []

    def invoke(command, **kwargs):
        assert kwargs["timeout_seconds"] == 15 and kwargs["output_limit"] == 64 * 1024
        journal = Path(command[command.index("--journal") + 1])
        offered = json.loads(journal.read_text().splitlines()[0])
        calls.append(offered)
        report = valid_report(offered)
        bad = len(calls) == 1
        if mode == "wrong-arm" and bad:
            report["source"] = {"commit": "wrong"}
        if mode == "unknown-output" and bad:
            report["raw_stdout"] = "must-not-escape"
        if mode == "partial" and bad:
            report["status"] = "measurement_started"
        if mode == "mismatch" and bad:
            report = {"schema": offered["schema"], "status": "failed", "mismatch": "package_count"}
        return launch.BoundedHookProcessResult(
            1 if mode == "mismatch" and bad else 0,
            json.dumps(report),
            mode == "output-limit" and bad,
            mode == "timeout" and bad,
            containment_failed=mode == "containment" and bad,
            stderr="never-publish-this-stderr",
        )

    monkeypatch.setattr(launch, "run_isolated_hook_process", invoke)
    return args, calls


def test_frozen_presets_and_opt_in_shards_cover_exact_workloads():
    assert len(preset("format-preflight")) == 20
    assert len(preset("cardinality")) == 36
    assert len(preset("hot-route")) == len(preset("unresolved")) == 1
    partition = shards()
    assert len(partition) == 63 and all(len(values) == 9 for values in partition.values())
    assert sorted(item for values in partition.values() for item in values) == sorted(case.id for case in matrix())


def test_independent_pairs_alternate_and_never_invent_validation_timings(tmp_path, monkeypatch):
    args, calls = setup_controller(tmp_path, monkeypatch, runs=2)
    report = controller.run(args)
    assert [item["arm"] for item in calls] == ["baseline", "candidate", "candidate", "baseline"]
    assert report["status"] == "completed"
    assert all(item["comparable"] for item in report["comparisons"])
    assert "wall_reduction" not in report["descriptive_summaries"][0]
    assert not list((args.output / "private_samples").glob("*.work"))


@pytest.mark.parametrize("mode", ("wrong-arm", "unknown-output", "partial", "mismatch", "output-limit", "timeout"))
def test_contained_failures_retain_both_arms_but_no_success_comparison(tmp_path, monkeypatch, mode):
    args, calls = setup_controller(tmp_path, monkeypatch, mode=mode)
    report = controller.run(args)
    assert len(calls) == 2 and report["status"] == "incomplete"
    assert report["comparisons"][0]["comparable"] is False
    assert report["observations"][0]["status"] == ("censored" if mode == "timeout" else "failed")
    assert not (args.output / "aggregate" / "paired.json").exists()
    assert "must-not-escape" not in json.dumps(report) and "never-publish" not in json.dumps(report)
    for path in (args.output / "private_samples").glob("*.jsonl"):
        records = [json.loads(line) for line in path.read_text().splitlines()]
        assert records[0]["status"] == "offered"
        assert records[-1]["status"] in {"failed", "censored", "completed"}


def test_containment_failure_stops_before_second_arm(tmp_path, monkeypatch):
    args, calls = setup_controller(tmp_path, monkeypatch, mode="containment")
    with pytest.raises(RuntimeError, match="containment_failed"):
        controller.run(args)
    assert len(calls) == 1
    assert json.loads((args.output / "aggregate" / "incomplete.json").read_text())["reason"] == "containment_failed"
    assert not (args.output / "aggregate" / "paired.json").exists()


def test_source_change_has_unconditional_failure_marker(tmp_path, monkeypatch):
    args, calls = setup_controller(tmp_path, monkeypatch, mode="source-change")
    with pytest.raises(ValueError, match="source_identity_changed"):
        controller.run(args)
    assert len(calls) == 2
    assert json.loads((args.output / "aggregate" / "incomplete.json").read_text())["status"] == "incomplete"
    assert not (args.output / "aggregate" / "paired.json").exists()


def test_existing_output_is_never_overwritten(tmp_path, monkeypatch):
    args, calls = setup_controller(tmp_path, monkeypatch)
    args.output.mkdir()
    sentinel = args.output / "sentinel"
    sentinel.write_text("keep")
    with pytest.raises(FileExistsError):
        controller.run(args)
    assert not calls and sentinel.read_text() == "keep"
    assert list(args.output.iterdir()) == [sentinel]


@pytest.mark.parametrize("value", (float("nan"), float("inf"), -1, 0, True, "1"))
def test_worker_rejects_invalid_timing_values(value):
    offered = {"schema": "hol-guard.package-attempt.v2", **dict.fromkeys(IDENTITY_FIELDS, "fixture")}
    offered.update(case_id=Case("npm", 100, 100, "exact", "evaluator").id, measurement="timing")
    report = {**valid_report(offered), "wall_ms": value, "cpu_ms": 1.0}
    with pytest.raises(ValueError, match="timing_invalid"):
        validate_worker_report(report, offered)


def test_no_favorable_subset_summary():
    rows = [
        {"case_id": "case", "comparable": True, "wall_reduction": 0.5, "cpu_reduction": 0.4},
        {"case_id": "case", "comparable": False},
    ]
    summary = descriptive_summary(rows)[0]
    assert summary["offered_pairs"] == 2 and summary["comparable_pairs"] == 1
    assert "wall_reduction" not in summary and summary["tail_qualified"] is False
