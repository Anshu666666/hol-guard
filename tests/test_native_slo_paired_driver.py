from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import qualify_guard_native


def test_paired_driver_preserves_alternating_environments_and_rejects_unqualified_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, candidate = tmp_path / "baseline-python", tmp_path / "candidate-python"
    baseline.symlink_to(sys.executable)
    candidate.symlink_to(sys.executable)
    calls: list[str] = []

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        arm = "baseline" if argv[0] == str(baseline) else "candidate"
        assert argv[argv.index("--receipt-profile") + 1] == ("baseline_2e672d2" if arm == "baseline" else "candidate")
        calls.append(arm)
        raw_file = Path(argv[argv.index("--raw-file") + 1])
        raw_file.write_text("{}")
        report = {
            "schema": "hol-guard.native-qualification-block.v1",
            "runtime": {"runtime_sha256": arm, "package_record_sha256": arm, "python_version": "3.12.14"},
            "corpus_digest": "same-corpus",
            "hardware": {"platform": "linux-x64", "cpu_model": "same-cpu"},
            "resources": {"sample_minimum_met": False},
            "measurements": {
                "DAEMON_INGRESS.claude-code.PostToolUse": {
                    "count": 2,
                    "p95_ms": 10 if arm == "baseline" else 7,
                    "p99_ms": 12,
                }
            },
        }
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=json.dumps(report),
        )

    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", run)
    args = argparse.Namespace(
        baseline_python=baseline,
        candidate_python=candidate,
        baseline_artifact=None,
        candidate_artifact=None,
        runs=3,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    result = qualify_guard_native._run_pair(args)
    assert calls == ["baseline", "candidate", "candidate", "baseline", "baseline", "candidate"]
    assert result["qualification_complete"] is False
    assert result["sampling_passed"] is False
    assert (args.output_dir / "aggregate" / "comparison.json").is_file()
    assert len(list((args.output_dir / "private_samples").iterdir())) == 6


def test_paired_failure_prints_the_same_sanitized_evidence_as_its_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    failure = {
        "schema": "hol-guard.native-qualification-failure.v1",
        "category": "AttributeError",
        "reason": "qualification_fixture.unclassified_failure",
        "origin": "native_slo_faults.__enter__",
        "line": 74,
    }
    completed = SimpleNamespace(
        returncode=1,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout=json.dumps(failure),
        stderr="private runtime output must never be printed",
    )
    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", lambda *_args, **_kwargs: completed)
    args = argparse.Namespace(
        baseline_python=tmp_path / "baseline-python",
        candidate_python=tmp_path / "candidate-python",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=1,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    with pytest.raises(RuntimeError, match="paired block failed"):
        qualify_guard_native._run_pair(args)
    printed = capsys.readouterr().err
    artifact = args.output_dir / "aggregate" / "00-baseline-failure.json"
    emitted = [json.loads(line) for line in printed.splitlines()]
    assert len(emitted) == 2
    assert emitted[0] == json.loads(artifact.read_text())
    assert emitted[0]["origin"] == "native_slo_faults.__enter__"
    assert emitted[1]["arm"] == "candidate"
    incomplete = json.loads((args.output_dir / "aggregate" / "incomplete.json").read_text())
    assert incomplete["failed_blocks"] == emitted
    assert incomplete["comparison_available"] is False and incomplete["sampling_passed"] is False
    assert completed.stderr not in printed


def _arguments(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        baseline_python=tmp_path / "baseline-python",
        candidate_python=tmp_path / "candidate-python",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=1,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )


@pytest.mark.parametrize("relative", ["aggregate/comparison.json", "private_samples/00-baseline.json"])
def test_previous_run_evidence_cannot_be_mixed_with_a_new_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    args = _arguments(tmp_path)
    prior = args.output_dir / relative
    prior.parent.mkdir(parents=True)
    prior.write_text('{"qualification_complete":true}')
    monkeypatch.setattr(
        qualify_guard_native,
        "run_isolated_hook_process",
        lambda *_args, **_kwargs: pytest.fail("stale run must not launch"),
    )
    with pytest.raises(ValueError, match="fresh aggregate and private"):
        qualify_guard_native._run_pair(args)
    assert prior.read_text() == '{"qualification_complete":true}'
    assert not (args.output_dir / "aggregate/incomplete.json").exists()


@pytest.mark.parametrize("containment_failed", [False, True])
def test_contained_failure_preserves_other_arm_without_comparison_but_lost_containment_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, containment_failed: bool
) -> None:
    args = _arguments(tmp_path)
    calls: list[str] = []

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        arm = "baseline" if argv[0] == str(args.baseline_python) else "candidate"
        calls.append(arm)
        if arm == "baseline":
            return SimpleNamespace(
                returncode=1,
                timed_out=False,
                containment_failed=containment_failed,
                output_limit_exceeded=False,
                stdout="{}",
            )
        raw = Path(argv[argv.index("--raw-file") + 1])
        raw.write_text('{"retained_numeric_observation":[1.0]}')
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=json.dumps({"schema": "hol-guard.native-qualification-block.v1", "fixture": "candidate_complete"}),
        )

    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", run)
    with pytest.raises(RuntimeError, match="paired block failed"):
        qualify_guard_native._run_pair(args)
    assert calls == (["baseline"] if containment_failed else ["baseline", "candidate"])
    public = args.output_dir / "aggregate"
    assert not (public / "comparison.json").exists()
    if not containment_failed:
        assert json.loads((public / "00-candidate.json").read_text())["fixture"] == "candidate_complete"
        incomplete = json.loads((public / "incomplete.json").read_text())
        assert incomplete["completed_blocks"] == {"baseline": 0, "candidate": 1}
        assert incomplete["qualification_complete"] is False and incomplete["comparison_available"] is False
