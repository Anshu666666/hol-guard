"""Bind qualification to exact unchanged checkouts without altering either arm."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
CANDIDATE_SHA = "d104ac325eba464bd82bd3fcae5c736de60fe1fb"
CANDIDATE_TREE = "944c35612ff6b6018e82c5fdeb020be4859da596"

# These identify local review provenance only; no runtime Git lookup uses them.
COLLECTOR_INPUT_LOCAL_COMMIT = "4d3d6cbc690e5941f2de8ec8f2b4a54fb9ef5d0c"
COLLECTOR_INPUT_LOCAL_TREE = "b9a968c7924fca6a8411cfc34c64232dc6452c5d"
COLLECTOR_INPUT_FILES = {
    "builder": (
        "scripts/build_native_qualification_artifacts.py",
        "f9d1e701dbed3743212d527065f9c1091220915deab0a6909bdc0152a60bca80",
        "ff0a2d62ef5fa4cb51fee875ec492f40bc70f095",
    ),
    "binding": (
        "scripts/native_slo_collector_binding.py",
        "2056e1b7b6eea88444ec509db5c59de111ef8894691d65c21277e2d5f7901f23",
        "95832872c1fd3e1aefe4c3187ad7e07d91fe0438",
    ),
    "observer": (
        "scripts/native_slo_config_observer.py",
        "e829970c61dab9372c8ca80412584c4a0e5edbdedca895b6c5308e66405a6245",
        "e36c436d0ba1db483a18152fb434fa36784b97f3",
    ),
    "faults": (
        "scripts/native_slo_faults.py",
        "1cfeb0830cdfb077e43b84832ded3d857a5e355d1d00bae29b365035ba180f3b",
        "0ae50328cad0d311b58f7467a09f3da878d9e2f8",
    ),
}


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
    collector_root = Path(__file__).resolve().parents[2]
    collector = inspect(collector_root, os.environ.get("VALIDATION_WORKFLOW_SHA", ""))
    try:
        copied_hashes = {
            role: hashlib.sha256((collector_root / name).read_bytes()).hexdigest()
            for role, (name, _expected_hash, _expected_blob) in COLLECTOR_INPUT_FILES.items()
        }
        copied_blobs = {
            role: _git(collector_root, "rev-parse", f"HEAD:{name}")
            for role, (name, _expected_hash, _expected_blob) in COLLECTOR_INPUT_FILES.items()
        }
    except (OSError, subprocess.CalledProcessError):
        copied_hashes = {}
        copied_blobs = {}
    expected_hashes = {role: digest for role, (_name, digest, _blob) in COLLECTOR_INPUT_FILES.items()}
    expected_blobs = {role: blob for role, (_name, _digest, blob) in COLLECTOR_INPUT_FILES.items()}
    provenance_matches = copied_hashes == expected_hashes and copied_blobs == expected_blobs
    result: dict[str, object] = {
        "schema": "hol-guard.native-qualification-checkouts.v1",
        "phase": args.phase,
        "workflow_commit": os.environ.get("VALIDATION_WORKFLOW_SHA"),
        "workflow_run": os.environ.get("VALIDATION_RUN_ID"),
        "workflow_attempt": os.environ.get("VALIDATION_RUN_ATTEMPT"),
        "binding_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline": baseline,
        "candidate": candidate,
        "collector": collector,
        "collector_input_local_commit": COLLECTOR_INPUT_LOCAL_COMMIT,
        "collector_input_local_tree": COLLECTOR_INPUT_LOCAL_TREE,
        "collector_input_digests": copied_hashes,
        "collector_input_blobs": copied_blobs,
        "collector_input_provenance_matches": provenance_matches,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _ = args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    valid = (
        baseline["matches_expected"] is True
        and candidate["matches_expected"] is True
        and collector["matches_expected"] is True
        and provenance_matches
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
