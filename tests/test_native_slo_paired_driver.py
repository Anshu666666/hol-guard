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
        calls.append(arm)
        raw_file = Path(argv[argv.index("--raw-file") + 1])
        raw_file.write_text("{}")
        report = {
            "schema": "hol-guard.native-qualification-block.v1",
            "runtime": {"runtime_sha256": arm, "package_record_sha256": arm},
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
