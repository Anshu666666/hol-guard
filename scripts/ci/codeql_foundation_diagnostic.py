"""Bind a no-upload CodeQL reproduction to its immutable source and raw SARIF."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

FOUNDATION_SHA = "e449594e86c717e66e14598a4130475de79c536f"
FOUNDATION_TREE = "b6a17d026500c1821d02b5a9202b544be0874377"
OBSERVED_MERGE_SHA = "b9395b11c216a52a0bea9eb937d7cd7cf6b2770b"
IMPLEMENTATION_SHA = "abf319d5a345d761d88e26ba787026e98370c26f"
IMPLEMENTATION_TREE = "62eb319323cc7c9de7513af6ef7f05009d411189"
IMPLEMENTATION_MERGE_SHA = "70b456e93a77fff48522ee7aa6ddeec6d157f6e6"
CURRENT_FOUNDATION_SHA = "cdd14176ef0e0a258d4655c64210524d7047a257"
CURRENT_FOUNDATION_TREE = "efb4e859e19b5456f2bdfbac17b2de784adf36a7"
CURRENT_FOUNDATION_MERGE_SHA = "c92e557349cabd633db408912c644471c002ee4d"
PREPARED_IMPLEMENTATION_SHA = "d8bde000de992009be3b2ed009347d2b3707ef0d"
PREPARED_IMPLEMENTATION_TREE = "1967a2127a325ae340d313bf73e80c60abb4d1f6"
CODEQL_ACTION_SHA = "8aad20d150bbac5944a9f9d289da16a4b0d87c1e"
CODEQL_VERSION = "2.27.0"
OBSERVED_CLI_BUILD = "b47b3e59262c95aff4eeb84ac72d09e25a9c37e9"
SARIF_FILES = {"actions": "actions.sarif", "javascript-typescript": "javascript.sarif", "python": "python.sarif"}
QUERY_PACKS = {"actions": "0.6.35", "javascript-typescript": "2.4.5", "python": "1.8.10"}
MAX_SARIF_BYTES = 128 * 1024 * 1024
MAX_DEFINITION_BYTES = 1024 * 1024
WORKFLOW_FILE = ".github/workflows/codeql-foundation-diagnostic.yml"


@dataclass(frozen=True)
class SnapshotProfile:
    commit: str
    tree: str
    analyzed_merge: str | None
    workflow_run: int | None
    alert_check: int | None
    high_alerts: int | None
    analysis_jobs: dict[str, int | None]


# Only these fixed snapshots may be selected; the CLI accepts no Git ref.
# Historical profiles retain their observed provenance without being rerun by
# the current matrix. A prepared snapshot has no original security observation.
PROFILES = {
    "foundation": SnapshotProfile(
        FOUNDATION_SHA,
        FOUNDATION_TREE,
        OBSERVED_MERGE_SHA,
        35181898004,
        105075778732,
        2,
        {"actions": 105075647482, "javascript-typescript": 105075647388, "python": 105075647242},
    ),
    "implementation": SnapshotProfile(
        IMPLEMENTATION_SHA,
        IMPLEMENTATION_TREE,
        IMPLEMENTATION_MERGE_SHA,
        35229526605,
        105229882410,
        3,
        {"actions": 105229666643, "javascript-typescript": 105229666837, "python": 105229666277},
    ),
    "foundation-cdd": SnapshotProfile(
        CURRENT_FOUNDATION_SHA,
        CURRENT_FOUNDATION_TREE,
        CURRENT_FOUNDATION_MERGE_SHA,
        35269310464,
        105364546143,
        8,
        {"actions": 105364320958, "javascript-typescript": 105364320271, "python": 105364320646},
    ),
    "implementation-d8": SnapshotProfile(
        PREPARED_IMPLEMENTATION_SHA,
        PREPARED_IMPLEMENTATION_TREE,
        None,
        None,
        None,
        None,
        {"actions": None, "javascript-typescript": None, "python": None},
    ),
}


def _definition_bytes(path: Path) -> bytes:
    """Read the fixed diagnostic definition with a finite allocation bound."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("diagnostic definition is not a regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_DEFINITION_BYTES + 1)
    if len(raw) > MAX_DEFINITION_BYTES:
        raise ValueError("diagnostic definition exceeds its size limit")
    return raw


def stage_definition(source_root: Path, staging_root: Path, environment_file: Path) -> dict[str, str]:
    """Keep only this collector outside the source before the fixed root checkout."""
    source_root = source_root.resolve()
    staging_root = staging_root.resolve()
    if source_root != Path.cwd().resolve() or staging_root.is_relative_to(source_root):
        raise ValueError("diagnostic staging must be outside the checked-out workspace")
    raw = _definition_bytes(Path(__file__))
    workflow = _definition_bytes(source_root / WORKFLOW_FILE)
    staging_root.mkdir(parents=True, exist_ok=False)
    staged = staging_root / "codeql_foundation_diagnostic.py"
    _ = staged.write_bytes(raw)
    staged.chmod(0o500)
    digest = hashlib.sha256(raw).hexdigest()
    if hashlib.sha256(_definition_bytes(staged)).hexdigest() != digest:
        raise ValueError("diagnostic collector copy changed")
    fields = {
        "DIAGNOSTIC_COLLECTOR_SHA256": digest,
        "DIAGNOSTIC_WORKFLOW_SHA256": hashlib.sha256(workflow).hexdigest(),
        # The pinned action supports an exact gzip/base64 workflow definition.
        # Its normal file lookup would fail after checking out the older tree.
        "CODE_SCANNING_WORKFLOW_FILE": base64.b64encode(gzip.compress(workflow, mtime=0)).decode("ascii"),
    }
    with environment_file.open("a", encoding="utf-8") as stream:
        for key, value in fields.items():
            _ = stream.write(f"{key}={value}\n")
    return {key: value for key, value in fields.items() if key != "CODE_SCANNING_WORKFLOW_FILE"}


def extraction_layout(source_root: Path, results_root: Path | None = None) -> dict[str, object]:
    """Prove the configured root/cwd and collector layout without claiming log evidence."""
    root = source_root.resolve()
    collector = Path(__file__).resolve()
    expected_collector = os.environ.get("DIAGNOSTIC_COLLECTOR_SHA256", "")
    expected_workflow = os.environ.get("DIAGNOSTIC_WORKFLOW_SHA256", "")
    collector_sha = ""
    workflow_sha = ""
    untracked_count: int | None = None
    try:
        collector_sha = hashlib.sha256(_definition_bytes(collector)).hexdigest()
        encoded = os.environ.get("CODE_SCANNING_WORKFLOW_FILE", "")
        if len(encoded) > MAX_DEFINITION_BYTES * 2:
            raise ValueError("workflow definition exceeds its size limit")
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            workflow = stream.read(MAX_DEFINITION_BYTES + 1)
        if not workflow or len(workflow) > MAX_DEFINITION_BYTES:
            raise ValueError("workflow definition exceeds its size limit")
        workflow_sha = hashlib.sha256(workflow).hexdigest()
        untracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--others", "-z"],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        untracked_count = len([entry for entry in untracked.split(b"\0") if entry])
    except (OSError, ValueError, EOFError, zlib.error, subprocess.SubprocessError):
        pass
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    report: dict[str, object] = {
        "source_root_is_workspace": bool(workspace) and root == Path(workspace).resolve(),
        "working_directory_is_source_root": root == Path.cwd().resolve(),
        "collector_outside_source_root": not collector.is_relative_to(root),
        "collector_sha256": collector_sha,
        "collector_matches_captured_sha256": bool(expected_collector) and collector_sha == expected_collector,
        "workflow_definition_sha256": workflow_sha,
        "workflow_matches_captured_sha256": bool(expected_workflow) and workflow_sha == expected_workflow,
        "results_outside_source_root": results_root is None or not results_root.resolve().is_relative_to(root),
        "untracked_file_count": untracked_count,
        "extractor_invocation_log_verified": False,
    }
    report["verified"] = (
        all(
            report[key] is True
            for key in (
                "source_root_is_workspace",
                "working_directory_is_source_root",
                "collector_outside_source_root",
                "collector_matches_captured_sha256",
                "workflow_matches_captured_sha256",
                "results_outside_source_root",
            )
        )
        and untracked_count == 0
    )
    return report


def source_materialization(root: Path) -> dict[str, object]:
    """Reject an absent source tree even when sparse Git state reports it clean."""
    try:
        sparse = subprocess.run(
            ["git", "-C", str(root), "config", "--type=bool", "--get", "core.sparseCheckout"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if sparse.returncode not in (0, 1):
            raise ValueError("sparse checkout configuration is unavailable")
        sparse_active = sparse.returncode == 0 and sparse.stdout.strip() == b"true"
        tracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-v", "-z"],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        entries = [entry for entry in tracked.split(b"\0") if entry]
        skip_worktree = sum(entry[:1].upper() == b"S" for entry in entries)
        assume_unchanged = sum(entry[:1].islower() for entry in entries)
        # lexists counts a tracked symlink itself, including a dangling link.
        missing = sum(not os.path.lexists(root / os.fsdecode(entry[2:])) for entry in entries)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"available": False, "verified": False}
    return {
        "available": True,
        "sparse_checkout": sparse_active,
        "tracked_file_count": len(entries),
        "skip_worktree_count": skip_worktree,
        "assume_unchanged_count": assume_unchanged,
        "missing_tracked_file_count": missing,
        "verified": bool(entries) and not (sparse_active or skip_worktree or assume_unchanged or missing),
    }


def source_identity(root: Path, profile_name: str = "foundation") -> dict[str, object]:
    """Read tracked Git identity without executing repository programs or hooks."""
    profile = PROFILES[profile_name]
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        commit, tree = result.stdout.splitlines()
        clean = (
            subprocess.run(
                ["git", "-C", str(root), "diff", "--quiet", "--no-ext-diff", "HEAD", "--"],
                check=False,
                capture_output=True,
                timeout=10,
            ).returncode
            == 0
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"available": False, "matches_pin": False}
    materialization = source_materialization(root)
    return {
        "available": True,
        "commit": commit,
        "tree": tree,
        "tracked_clean": clean,
        "materialization": materialization,
        "matches_pin": commit == profile.commit and tree == profile.tree and clean and materialization["verified"],
    }


def sarif_identity(path: Path) -> tuple[dict[str, object], list[str]]:
    """Hash unchanged result bytes; reject incomplete or unexpectedly large reports."""
    if path.is_symlink():
        return {}, ["sarif_not_regular"]
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_SARIF_BYTES + 1)
    except OSError:
        return {}, ["sarif_unavailable"]
    if len(raw) > MAX_SARIF_BYTES:
        return {"exceeds_bytes": MAX_SARIF_BYTES}, ["sarif_size_limit"]
    identity: dict[str, object] = {"file": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        decoded = cast(object, json.loads(raw))
        if not isinstance(decoded, dict):
            raise ValueError("invalid SARIF document")
        report = cast(dict[str, object], decoded)
        run_values = report.get("runs")
        if report.get("version") != "2.1.0" or not isinstance(run_values, list) or not run_values:
            raise ValueError("invalid SARIF envelope")
        runs = cast(list[object], run_values)
        results_count = 0
        for run in runs:
            if not isinstance(run, dict):
                raise ValueError("invalid SARIF run")
            results = cast(dict[str, object], run).get("results")
            if not isinstance(results, list):
                raise ValueError("missing result collection")
            results_count += len(cast(list[object], results))
        identity["runs"] = len(runs)
        identity["results"] = results_count
    except (KeyError, TypeError, ValueError, RecursionError):
        return identity, ["sarif_invalid"]
    return identity, []


def collect(
    source_root: Path,
    results_root: Path,
    language: str,
    observed_version: str,
    init_outcome: str,
    analyze_outcome: str,
    *,
    profile_name: str = "foundation",
    enforce_layout: bool = False,
) -> dict[str, object]:
    """Always retain an incomplete manifest when setup, analysis or identity fails."""
    profile = PROFILES[profile_name]
    identity = source_identity(source_root, profile_name)
    sarif, errors = sarif_identity(results_root / SARIF_FILES[language])
    layout = extraction_layout(source_root, results_root) if enforce_layout else {"verified": False, "required": False}
    if enforce_layout and not layout["verified"]:
        errors.append("extraction_layout_unproven")
    if not identity["matches_pin"]:
        errors.append(f"{profile_name}_identity_mismatch")
    if observed_version != CODEQL_VERSION:
        errors.append("codeql_version_unproven")
    if init_outcome != "success":
        errors.append("initialization_incomplete")
    if analyze_outcome != "success":
        errors.append("analysis_incomplete")
    report: dict[str, object] = {
        "schema": "guard.codeql-snapshot-diagnostic.v1",
        "profile": profile_name,
        "source": identity,
        "extraction_layout": layout,
        "expected_commit": profile.commit,
        "expected_tree": profile.tree,
        "original_analyzed_merge": profile.analyzed_merge,
        "original_workflow_run": profile.workflow_run,
        "original_analysis_job": profile.analysis_jobs[language],
        "original_alert_check": profile.alert_check,
        "original_high_alert_count": profile.high_alerts,
        "observation_provenance_available": profile.workflow_run is not None,
        "original_alert_overlap_known": False,
        "language": language,
        "codeql_action": CODEQL_ACTION_SHA,
        "expected_cli_version": CODEQL_VERSION,
        "original_cli_build": OBSERVED_CLI_BUILD if profile.workflow_run is not None else None,
        "observed_cli_version": observed_version[:64],
        "original_bundled_query_pack_version": QUERY_PACKS[language] if profile.workflow_run is not None else None,
        "query_selection": "bundle_default_queries",
        "original_paths_ignore": (
            ["src/codex_plugin_scanner/guard/stable_digest.py"] if profile.workflow_run is not None else None
        ),
        "diagnostic_paths_ignore": ["src/codex_plugin_scanner/guard/stable_digest.py"],
        "diff_filter": False,
        "security_result_upload": "never",
        "database_upload": False,
        "workflow_run": os.environ.get("GITHUB_RUN_ID", ""),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "workflow_commit": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "initialization_outcome": init_outcome[:32],
        "analysis_outcome": analyze_outcome[:32],
        "sarif": sarif,
        "errors": errors,
        "diagnostic_analysis_complete": not errors,
        # A successful diagnostic produces findings; it does not clear alerts.
        "original_security_alerts_resolved": False,
    }
    results_root.mkdir(parents=True, exist_ok=True)
    _ = (results_root / "diagnostic.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


class Arguments(argparse.Namespace):
    phase: str = ""
    source_root: Path = Path(".")
    staging_root: Path | None = None
    environment_file: Path | None = None
    enforce_layout: bool = False
    profile: str = "foundation"
    results_root: Path | None = None
    language: str | None = None
    observed_version: str = ""
    init_outcome: str = ""
    analyze_outcome: str = ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("phase", choices=("stage", "verify", "collect"))
    _ = parser.add_argument("--source-root", type=Path, required=True)
    _ = parser.add_argument("--staging-root", type=Path)
    _ = parser.add_argument("--environment-file", type=Path)
    _ = parser.add_argument("--enforce-layout", action="store_true")
    _ = parser.add_argument("--profile", choices=tuple(PROFILES), default="foundation")
    _ = parser.add_argument("--results-root", type=Path)
    _ = parser.add_argument("--language", choices=tuple(SARIF_FILES))
    _ = parser.add_argument("--observed-version", default="")
    _ = parser.add_argument("--init-outcome", default="")
    _ = parser.add_argument("--analyze-outcome", default="")
    args = Arguments()
    _ = parser.parse_args(namespace=args)
    if args.phase == "stage":
        if args.staging_root is None or args.environment_file is None:
            parser.error("stage requires --staging-root and --environment-file")
        print(json.dumps(stage_definition(args.source_root, args.staging_root, args.environment_file)))
        return 0
    if args.phase == "verify":
        if args.enforce_layout and not extraction_layout(args.source_root)["verified"]:
            parser.exit(1, "The immutable source is not isolated at the actual extractor working directory.\n")
        if not source_identity(args.source_root, args.profile)["matches_pin"]:
            parser.exit(1, "Source identity does not match the selected immutable diagnostic profile.\n")
        return 0
    if args.results_root is None or args.language is None:
        parser.error("collect requires --results-root and --language")
    report = collect(
        args.source_root,
        args.results_root,
        args.language,
        args.observed_version,
        args.init_outcome,
        args.analyze_outcome,
        profile_name=args.profile,
        enforce_layout=args.enforce_layout,
    )
    completion = {"diagnostic_analysis_complete": report["diagnostic_analysis_complete"], "errors": report["errors"]}
    print(json.dumps(completion))
    return 0 if report["diagnostic_analysis_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
