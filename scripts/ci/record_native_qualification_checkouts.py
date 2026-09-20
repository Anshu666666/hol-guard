"""Bind qualification to exact unchanged checkouts without altering either arm."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
CANDIDATE_SHA = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
CANDIDATE_TREE = "c10faac2d156cac06f9f803d63f50d15e3ca82bf"


class _Arguments(argparse.Namespace):
    baseline: Path = Path()
    candidate: Path = Path()
    phase: str = ""
    output: Path = Path()


def _git(directory: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def inspect(directory: Path, expected_sha: str, expected_tree: str | None = None) -> dict[str, object]:
    try:
        sha = _git(directory, "rev-parse", "HEAD")
        tree = _git(directory, "rev-parse", "HEAD^{tree}")
        clean = not _git(directory, "status", "--porcelain", "--untracked-files=no")
    except (OSError, subprocess.CalledProcessError):
        return {"available": False, "matches_expected": False}
    return {
        "available": True,
        "commit": sha,
        "tree": tree,
        "tracked_files_unchanged": clean,
        "matches_expected": sha == expected_sha and (expected_tree is None or tree == expected_tree) and clean,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--baseline", type=Path, required=True)
    _ = parser.add_argument("--candidate", type=Path, required=True)
    _ = parser.add_argument("--phase", choices=("before", "after"), required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    args = _Arguments()
    _ = parser.parse_args(namespace=args)
    baseline = inspect(args.baseline, BASELINE_SHA)
    candidate = inspect(args.candidate, CANDIDATE_SHA, CANDIDATE_TREE)
    result: dict[str, object] = {
        "schema": "hol-guard.native-qualification-checkouts.v1",
        "phase": args.phase,
        "workflow_commit": os.environ.get("VALIDATION_WORKFLOW_SHA"),
        "workflow_run": os.environ.get("VALIDATION_RUN_ID"),
        "workflow_attempt": os.environ.get("VALIDATION_RUN_ATTEMPT"),
        "binding_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline": baseline,
        "candidate": candidate,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _ = args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if baseline["matches_expected"] is True and candidate["matches_expected"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
