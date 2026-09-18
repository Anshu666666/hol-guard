"""Bind one cache diagnostic to untouched D104 and original-baseline sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
BASELINE_TREE = "a577c6c03270ec55ef028213711b859e410f076d"
CANDIDATE_SHA = "d104ac325eba464bd82bd3fcae5c736de60fe1fb"
CANDIDATE_TREE = "944c35612ff6b6018e82c5fdeb020be4859da596"
WRAPPER_REVIEW_LOCAL_COMMIT = "1b62e34add527f9cadffb74d5fa7f957f8efad76"
# Local review provenance is a label only. No hosted Git lookup uses that SHA.
WRAPPER_FILES = {
    "scripts/ci/native_loopback_cache.py": (
        "e93fa5b5a52c6dc006caedc15788012531d9d1282bd2046830297afe144ab284",
        "05e271661c9e088edf8fc185788a40f4320e0b90",
    ),
    "scripts/ci/native_loopback_resolver.py": (
        "bf39a3a1e14abb0c8c8c117a958bade0a5349a2d27314a9ce9f73abdb5b38fb7",
        "b75641d07fe9eabc9314b205c65d5630dd77131a",
    ),
    "scripts/ci/native_loopback_lookup.py": (
        "734b714583edf2270776056f4d51eb004904406727372cb904f00f87f91c783b",
        "0532beb40d542840a4334a5d836bcfa536e927f2",
    ),
}
FROZEN_COLLECTOR_FILES = {
    "scripts/build_native_qualification_artifacts.py": (
        "33e81f4dff74d45d90ba7630346dc00a588a70774710ea08781defa0b5e88756"
    ),
    "scripts/qualify_guard_native.py": "91e7b82219c0c68e38ed3cbbc022d23558b001f4b8bac9f369d5510b7ed70d74",
    "scripts/native_slo_qualification.py": "f5a6cd59aee828619e70c2f37208683ac5b6d765d9abffca0ccab854e4c7471b",
    "scripts/native_slo_contract.py": "81c352745f4205de3ac9cb7d51c58616e2f5340921722cacd0ce4dc584f68bb1",
    "scripts/native_slo_acceptance.py": "d58c236a005a4db828b20b48cd0e948b4ade7e6d4928e5d4740b2b3cb5ad59cd",
    "scripts/native_slo_workloads.py": "a86a14c5166928b1aabdfb954d3920233ed70d3ac813e5a1ea6c98cadcd0a344",
    "tests/fixtures/guard-native-qualification/corpus.v1.json": (
        "3e15505ecf970103f9b9f64077f4a681b85b3c900b50576706b18e9aea6c34b9"
    ),
    "docs/guard/contracts/hook-data-plane-ownership.v2.json": (
        "9c09084497b88ed930e9dbfb61697504a38ab0acbc7fc04c151dfd1e07e88215"
    ),
}


def _git(directory: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *arguments], check=True, capture_output=True, text=True, timeout=15
    ).stdout.strip()


def inspect(
    directory: Path, expected_sha: str, expected_tree: str | None = None, *, include_untracked: bool = False
) -> dict[str, object]:
    try:
        sha = _git(directory, "rev-parse", "HEAD")
        tree = _git(directory, "rev-parse", "HEAD^{tree}")
        untracked = "all" if include_untracked else "no"
        clean = not _git(directory, "status", "--porcelain", "--untracked-files=" + untracked)
        root_matches = Path(_git(directory, "rev-parse", "--show-toplevel")).resolve() == directory.resolve()
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "matches_expected": False}
    return {
        "available": True,
        "commit": sha,
        "tree": tree,
        "tracked_files_unchanged": clean,
        "checkout_root_matches": root_matches,
        "matches_expected": bool(re.fullmatch(r"[0-9a-f]{40}", expected_sha))
        and sha == expected_sha
        and (expected_tree is None or tree == expected_tree)
        and clean
        and root_matches,
    }


def _digests(root: Path, names: Iterable[str]) -> dict[str, str]:
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    baseline = inspect(args.baseline, BASELINE_SHA, BASELINE_TREE)
    candidate = inspect(args.candidate, CANDIDATE_SHA, CANDIDATE_TREE)
    validation = inspect(root, os.environ.get("VALIDATION_WORKFLOW_SHA", ""), include_untracked=True)
    try:
        wrapper_hashes = _digests(root, WRAPPER_FILES)
        wrapper_blobs = {name: _git(root, "rev-parse", f"HEAD:{name}") for name in WRAPPER_FILES}
        collector_hashes = _digests(args.candidate, FROZEN_COLLECTOR_FILES)
    except (OSError, subprocess.SubprocessError):
        wrapper_hashes, wrapper_blobs, collector_hashes = {}, {}, {}
    wrapper_matches = wrapper_hashes == {name: value[0] for name, value in WRAPPER_FILES.items()} and wrapper_blobs == {
        name: value[1] for name, value in WRAPPER_FILES.items()
    }
    collector_matches = collector_hashes == FROZEN_COLLECTOR_FILES
    result = {
        "schema": "hol-guard.native-macos-diagnostic-checkouts.v1",
        "phase": args.phase,
        "scope": "new_two_macos_cache_diagnostic_smoke_cohort",
        "qualification_pass": False,
        "workflow_commit": os.environ.get("VALIDATION_WORKFLOW_SHA"),
        "workflow_run": os.environ.get("VALIDATION_RUN_ID"),
        "workflow_attempt": os.environ.get("VALIDATION_RUN_ATTEMPT"),
        "binding_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline": baseline,
        "candidate": candidate,
        "validation": validation,
        "wrapper_review_local_commit": WRAPPER_REVIEW_LOCAL_COMMIT,
        "wrapper_sha256": wrapper_hashes,
        "wrapper_git_blobs": wrapper_blobs,
        "wrapper_matches_reviewed_bytes": wrapper_matches,
        "collector_root": "candidate",
        "collector_commit": CANDIDATE_SHA,
        "frozen_collector_sha256": collector_hashes,
        "frozen_collector_matches_original": collector_matches,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    valid = (
        all(row["matches_expected"] is True for row in (baseline, candidate, validation))
        and wrapper_matches
        and collector_matches
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
