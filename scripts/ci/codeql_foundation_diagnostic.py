"""Bind a no-upload CodeQL reproduction to its immutable source and raw SARIF."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import cast

FOUNDATION_SHA = "e449594e86c717e66e14598a4130475de79c536f"
FOUNDATION_TREE = "b6a17d026500c1821d02b5a9202b544be0874377"
OBSERVED_MERGE_SHA = "b9395b11c216a52a0bea9eb937d7cd7cf6b2770b"
CODEQL_ACTION_SHA = "8aad20d150bbac5944a9f9d289da16a4b0d87c1e"
CODEQL_VERSION = "2.27.0"
SARIF_FILES = {"actions": "actions.sarif", "javascript-typescript": "javascript.sarif", "python": "python.sarif"}
QUERY_PACKS = {"actions": "0.6.35", "javascript-typescript": "2.4.5", "python": "1.8.10"}
MAX_SARIF_BYTES = 128 * 1024 * 1024


def source_identity(root: Path) -> dict[str, object]:
    """Read tracked Git identity without executing repository programs or hooks."""
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
    return {
        "available": True,
        "commit": commit,
        "tree": tree,
        "tracked_clean": clean,
        "matches_pin": commit == FOUNDATION_SHA and tree == FOUNDATION_TREE and clean,
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
) -> dict[str, object]:
    """Always retain an incomplete manifest when setup, analysis or identity fails."""
    identity = source_identity(source_root)
    sarif, errors = sarif_identity(results_root / SARIF_FILES[language])
    if not identity["matches_pin"]:
        errors.append("foundation_identity_mismatch")
    if observed_version != CODEQL_VERSION:
        errors.append("codeql_version_unproven")
    if init_outcome != "success":
        errors.append("initialization_incomplete")
    if analyze_outcome != "success":
        errors.append("analysis_incomplete")
    report: dict[str, object] = {
        "schema": "guard.codeql-foundation-diagnostic.v1",
        "source": identity,
        "expected_commit": FOUNDATION_SHA,
        "expected_tree": FOUNDATION_TREE,
        "original_analyzed_merge": OBSERVED_MERGE_SHA,
        "original_workflow_run": 35181898004,
        "original_alert_check": 105075778732,
        "language": language,
        "codeql_action": CODEQL_ACTION_SHA,
        "expected_cli_version": CODEQL_VERSION,
        "observed_cli_version": observed_version[:64],
        "original_bundled_query_pack_version": QUERY_PACKS[language],
        "query_selection": "bundle_default_queries",
        "original_paths_ignore": ["src/codex_plugin_scanner/guard/stable_digest.py"],
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
    results_root: Path | None = None
    language: str | None = None
    observed_version: str = ""
    init_outcome: str = ""
    analyze_outcome: str = ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("phase", choices=("verify", "collect"))
    _ = parser.add_argument("--source-root", type=Path, required=True)
    _ = parser.add_argument("--results-root", type=Path)
    _ = parser.add_argument("--language", choices=tuple(SARIF_FILES))
    _ = parser.add_argument("--observed-version", default="")
    _ = parser.add_argument("--init-outcome", default="")
    _ = parser.add_argument("--analyze-outcome", default="")
    args = Arguments()
    _ = parser.parse_args(namespace=args)
    if args.phase == "verify":
        if not source_identity(args.source_root)["matches_pin"]:
            parser.exit(1, "Foundation source identity does not match the immutable diagnostic pin.\n")
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
    )
    completion = {"diagnostic_analysis_complete": report["diagnostic_analysis_complete"], "errors": report["errors"]}
    print(json.dumps(completion))
    return 0 if report["diagnostic_analysis_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
