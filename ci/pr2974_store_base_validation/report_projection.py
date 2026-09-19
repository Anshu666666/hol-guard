"""Emit a bounded, checksum-framed summary while retaining all original report files."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, write_json


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def main() -> None:
    paths = [path for path in sorted(REPORT.rglob("*")) if path.is_file()
             and path.name not in {"log-projection.json", "log-projection-error.json",
                                   "log-projection-packet.json", "log-projection-packet.json.gz"}]
    records = {}
    summaries = {}
    snapshots = {}
    for path in paths:
        name = path.relative_to(REPORT).as_posix()
        raw = path.read_bytes()
        records[name] = {"sha256": digest(raw), "bytes": len(raw)}
        if path.suffix != ".json":
            continue
        value = json.loads(raw)
        if isinstance(value, dict) and "comparison" in value and "raw_origins" in value:
            keys = (
                "schema", "root", "side", "lane", "cases", "mode", "terminal", "exit_code", "passed",
                "collection_complete", "actual_cases", "actual_selector_counts", "expected_cases",
                "raw_nodes_unique", "normalized_nodes_unique", "source_commit", "source_tree",
                "manifest_sha256", "observer_sha256", "helper_sha256", "errors", "refused_execution",
                "observed_source_files_unchanged", "execution_collection_matches_prior",
                "prior_collection_sha256", "used_class_module_fixtures_requiring_review",
                "body_reports", "collect_reports", "pytest_argv", "test_execution_credit",
            )
            snapshot = {key: value[key] for key in keys if key in value}
            rows = value["comparison"]
            snapshot["comparison_sha256"] = digest(canonical(rows))
            snapshot["ordered_comparison_row_sha256"] = [digest(canonical(row)) for row in rows]
            snapshot["ordered_raw_nodes"] = [row["nodeid"] for row in value["raw_origins"]]
            snapshot["complete_snapshot_file"] = records[name]
            snapshot["complete_ast_fixture_and_origin_records_retained_in_artifact"] = True
            snapshots[name] = snapshot
        elif name in {
            "job-outcome.json", "steps.json", "finite-result.json", "baseline-candidate-collection-comparison.json",
            "source-gates-result.json", "physical-line-bounds.json", "corpus-binding-currentness.json",
            "gitleaks-result.json", "gitleaks-binary.json", "range-proof.json",
            "host.json", "uv-binary.json", "test-temp-root.json", "command-source-inverse.json", "surface-source-inverse.json",
            "scoped-types-observation-error.json", "store-base-source-inverse.json", "store-base-source-contract.json",
            "store-base-lint-correction-inverse.json", "type-interpreter-origin.json",
        } or name.startswith("codex-seam-"):
            summaries[name] = value
        elif name in {"environment-before.json", "environment-after.json", "build-environment.json"}:
            summaries[name] = {key: value[key] for key in (
                "python_version", "executable", "prefix", "base_prefix", "launchers", "installed_count",
                "installed_versions", "backend_environment", "editable_project", "package_origin",
                "package_origin_sha256", "all_versions_match_frozen_lock",
            ) if key in value}
        elif name == "package-members.json":
            summaries[name] = {
                "full_member_report": records[name],
                "all_actual_members_verified": value.get("all_actual_members_verified"),
                "all_wheel_record_rows_verified": value.get("all_wheel_record_rows_verified"),
                "harness_in_artifacts": value.get("harness_in_artifacts"),
            }
    outcome = json.loads((REPORT / "job-outcome.json").read_bytes())
    failed_logs = {}
    for step in outcome.get("steps", []):
        if step.get("passed"):
            continue
        name = step["name"] + ".log"
        path = REPORT / name
        if path.is_file():
            raw = path.read_bytes()
            failed_logs[name] = {"complete_file": records[name], "tail_utf8": raw[-6000:].decode("utf-8", "replace"),
                                 "tail_only": len(raw) > 6000}
    packet = {
        "schema": "pr2974-store-base-validation-result-projection-v1",
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "original_files": records, "summaries": summaries, "collection_execution_projections": snapshots,
        "failed_command_log_tails": failed_logs,
        "full_original_snapshots_junit_logs_and_receipts_retained_in_artifact": True,
        "projection_is_not_a_substitute_for_original_artifact_bytes": True,
        "qualification_complete": False,
    }
    raw = canonical(packet)
    assert len(raw) <= 1048576, ("Projection output exceeds the fixed bound", len(raw))
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    assert len(compressed) <= 262144, ("Compressed projection exceeds the fixed bound", len(compressed))
    encoded = base64.b64encode(compressed).decode("ascii")
    assert len(encoded) <= 350000
    pieces = [encoded[index:index + 6000] for index in range(0, len(encoded), 6000)]
    framing = {
        "schema": "pr2974-store-base-validation-log-frame-v1", "run_id": os.environ["GITHUB_RUN_ID"],
        "job": outcome.get("job"), "harness_sha": os.environ["GITHUB_SHA"],
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "raw_bytes": len(raw), "raw_sha256": digest(raw), "gzip_bytes": len(compressed),
        "gzip_sha256": digest(compressed), "base64_chars": len(encoded), "parts": len(pieces),
        "qualification_complete": False,
    }
    (REPORT / "log-projection-packet.json").write_bytes(raw)
    (REPORT / "log-projection-packet.json.gz").write_bytes(compressed)
    write_json(REPORT / "log-projection.json", framing)
    print("PR2974_STORE_BASE_RESULT_BEGIN " + json.dumps(framing, sort_keys=True), flush=True)
    for index, piece in enumerate(pieces, 1):
        print(f"PR2974_STORE_BASE_RESULT_PART {index:04d}/{len(pieces):04d} {piece}", flush=True)
    print("PR2974_STORE_BASE_RESULT_END " + json.dumps(framing, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        write_json(REPORT / "log-projection-error.json", {"error": repr(error), "qualification_complete": False})
        raise
