"""Finite private archive staging and bounded public package CI diagnostics."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.native_slo_evidence_files import atomic_exclusive, read_file
from scripts.native_slo_evidence_format import MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, canonical
from scripts.package_benchmark_corpus import BASELINE, digest, manifest
from scripts.package_benchmark_evidence import compare_pair, write_private
from scripts.package_benchmark_protocol import (
    MISMATCH_FIELDS,
    descriptive_summary,
    preset,
    preset_arms,
    validate_worker_report,
)

PLANS = {
    "phase-attribution": (
        ("phase-validation", 1, "validation", 30),
        ("phase-attribution", 3, "attribution", 30),
        ("registry-resolved", 1, "validation", 30),
    ),
    "format-preflight": (("format-preflight", 1, "validation", 20),),
    "diagnostic": (
        ("cardinality", 1, "timing", 15),
        ("unresolved", 1, "validation", 15),
        ("hot-route", 5, "timing", 15),
    ),
}
ARCHIVE_GROUPS = {
    "phase-attribution": ("phase-validation", "phase-attribution", "registry-resolved"),
    "format-preflight": ("format-preflight",),
    "diagnostic": ("cardinality-d100", "cardinality-d1000", "cardinality-d10000", "unresolved", "hot-route"),
}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CONTROLLER_FIELDS = {"arm", "run", "sample", "returncode", "timed_out", "containment_failed", "output_limit_exceeded"}
_TIMEOUT_SCOPE = "whole_worker_including_setup_and_postvalidation"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(read_file(path, 4 * 1024**2, private=True))
    if not isinstance(value, dict):
        raise ValueError("aggregate_invalid")
    return value


def expected_paths(scope: str, runs: int) -> list[tuple[str | None, str]]:
    paths: list[tuple[str | None, str]] = [
        (None, "aggregate/" + name) for name in ("manifest.json", "paired.json", "incomplete.json")
    ]
    for identifier in preset(scope):
        paths.append((identifier, "private_samples/" + identifier + ".fixture.json"))
        for run in range(runs):
            for arm in preset_arms(scope):
                prefix = f"private_samples/{identifier}.r{run:02d}.s0000.{arm}"
                paths.extend(((identifier, prefix + ".jsonl"), (identifier, prefix + ".semantic.json")))
    return paths


def stage(private: Path, staging: Path, *, plan: str, required_semantics: set[tuple[str, str]]) -> dict[str, object]:
    """Copy only finite known files, without following links or reading work dirs."""
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    groups: dict[str, list[tuple[str, Path]]] = {name: [] for name in ARCHIVE_GROUPS[plan]}
    missing_required = 0
    for scope, runs, _, _ in PLANS[plan]:
        for identifier, relative in expected_paths(scope, runs):
            path = private / scope / relative
            if not path.exists() and not path.is_symlink():
                if (
                    relative.endswith((".fixture.json", ".jsonl"))
                    or relative == "aggregate/manifest.json"
                    or (scope, relative) in required_semantics
                ):
                    missing_required += 1
                continue
            selected = (
                (scope,)
                if scope != "cardinality"
                else (
                    tuple(f"cardinality-d{size}" for size in (100, 1000, 10000))
                    if identifier is None
                    else ("cardinality-" + identifier.rsplit(".", 2)[1],)
                )
            )
            for name in selected:
                groups[name].append((scope + "/" + relative, path))
    counts: dict[str, object] = {}
    for name, items in groups.items():
        directory = staging / name
        directory.mkdir(mode=0o700)
        total = 0
        inventory = []
        if len(items) + 1 > MAX_FILES:
            raise ValueError("archive_bounds_exceeded")
        for index, (relative, path) in enumerate(items):
            data = read_file(path, MAX_FILE_BYTES, private=True)
            total += len(data)
            if total > MAX_TOTAL_BYTES - 96 * 1024:
                raise ValueError("archive_bounds_exceeded")
            destination = f"record-{index:03d}" + path.suffix
            atomic_exclusive(directory / destination, data)
            inventory.append({"name": destination, "original": relative, "bytes": len(data)})
        if inventory:
            atomic_exclusive(directory / "staging-manifest.json", canonical({"scope": name, "files": inventory}))
        counts[name] = {"files": len(inventory), "bytes": total}
    return {
        "status": "incomplete" if missing_required else "complete",
        "missing_required": missing_required,
        "groups": counts,
    }


def _scope(
    private: Path, *, scope: str, runs: int, measurement: str, timeout: int, candidate: str, outcome: str
) -> dict[str, Any]:
    expected = {(case, arm, run, 0) for case in preset(scope) for arm in preset_arms(scope) for run in range(runs)}
    result: dict[str, Any] = {
        "scope": scope,
        "status": "incomplete",
        "offered_attempts": len(expected),
        "timeout_scope": _TIMEOUT_SCOPE,
        "timeout_seconds": timeout,
        "observations": [],
        "comparisons": [],
    }
    try:
        directory = private / scope / "aggregate"
        source_manifest = _read(directory / "manifest.json")
        if (
            source_manifest["selected_cases"] != list(preset(scope))
            or source_manifest["runs"] != runs
            or source_manifest["samples_per_run"] != 1
            or source_manifest["measurement"] != measurement
            or source_manifest["timeout_seconds"] != timeout
            or source_manifest["timeout_scope"] != _TIMEOUT_SCOPE
            or source_manifest["offered_attempts"] != len(expected)
            or source_manifest["matrix_digest"] != manifest()["matrix_digest"]
            or source_manifest["source"]["baseline"]["commit"] != BASELINE
            or source_manifest["source"]["candidate"]["commit"] != candidate
        ):
            raise ValueError("manifest_mismatch")
        if not isinstance(source_manifest.get("harness_sha256"), str) or not _HASH.fullmatch(
            source_manifest["harness_sha256"]
        ):
            raise ValueError("manifest_mismatch")
        incomplete = directory / "incomplete.json"
        report = _read(incomplete if incomplete.exists() else directory / "paired.json")
        if report.get("schema") != "hol-guard.package-pairs.v2" or report.get("status") not in {
            "completed",
            "incomplete",
        }:
            raise ValueError("aggregate_invalid")
        observations = report.get("observations")
        if not isinstance(observations, list) or len(observations) > len(expected):
            raise ValueError("aggregate_invalid")
        seen = {}
        for row in observations:
            if not isinstance(row, dict):
                raise ValueError("aggregate_invalid")
            identity = (row.get("case_id"), row.get("arm"), row.get("run"), row.get("sample"))
            if (
                type(identity[2]) is not int
                or type(identity[3]) is not int
                or identity not in expected
                or identity in seen
            ):
                raise ValueError("attempt_identity_invalid")
            arm = str(row["arm"])
            if row.get("source") != source_manifest["source"][arm] or row.get("measurement") != measurement:
                raise ValueError("attempt_identity_invalid")
            if row.get("status") not in {"completed", "failed", "censored"}:
                raise ValueError("attempt_state_invalid")
            if row["status"] == "completed":
                offered = {key: source_manifest[key] for key in ("environment", "harness_sha256", "measurement")}
                offered.update(
                    {key: row[key] for key in ("case_id", "source", "fixture_sha256", "signed_response_sha256")}
                )
                validate_worker_report(
                    {key: value for key, value in row.items() if key not in _CONTROLLER_FIELDS}, offered
                )
                if (
                    type(row.get("returncode")) is not int
                    or row["returncode"] != 0
                    or any(
                        row.get(key) is not False
                        for key in ("timed_out", "containment_failed", "output_limit_exceeded")
                    )
                ):
                    raise ValueError("attempt_state_invalid")
            seen[identity] = row
            projected = {"case_id": identity[0], "arm": arm, "run": identity[2], "sample": 0, "status": row["status"]}
            if row["status"] == "completed":
                projected["bundle_admission_verified_before_route"] = True
            for key in (
                "wall_ms",
                "cpu_ms",
                "packages",
                "evidence_rows",
                "entries",
                "input_bytes",
                "lookups",
                "matched",
            ):
                if row["status"] == "completed" and key in row:
                    projected[key] = row[key]
            for key in (
                "semantic_sha256",
                "evidence_sha256",
                "protect_sha256",
                "entry_sha256",
                "fixture_sha256",
                "signed_response_sha256",
            ):
                value = row.get(key)
                if isinstance(value, str) and _HASH.fullmatch(value):
                    projected[key] = value
            if row["status"] == "completed" and measurement == "attribution":
                projected["phases"] = row["phases"]
                projected["operation_counts"] = row["operation_counts"]
            if row["status"] == "completed" and "registry_transport" in row:
                projected["registry_transport"] = row["registry_transport"]
            if row.get("mismatch") in MISMATCH_FIELDS:
                projected["mismatch"] = row["mismatch"]
            result["observations"].append(projected)
        for case in preset(scope) if len(preset_arms(scope)) == 2 else ():
            for run in range(runs):
                baseline, optimized = seen.get((case, "baseline", run, 0)), seen.get((case, "candidate", run, 0))
                comparison = (
                    compare_pair(baseline, optimized)
                    if baseline is not None and optimized is not None
                    else {"comparable": False, "reason": "missing_attempt"}
                )
                result["comparisons"].append({"case_id": case, "run": run, "sample": 0, **comparison})
        result["summaries"] = descriptive_summary(result["comparisons"])
        result["environment_sha256"] = digest(source_manifest["environment"])
        result["harness_sha256"] = source_manifest["harness_sha256"]
        if (
            not incomplete.exists()
            and report["status"] == "completed"
            and len(seen) == len(expected)
            and all(row["status"] == "completed" for row in seen.values())
            and all(item["comparable"] for item in result["comparisons"])
            and outcome == "success"
        ):
            result["status"] = "completed"
    except (OSError, ValueError, KeyError, TypeError):
        # A corrupt/missing aggregate can never be rescued by a stale success.
        result.update(status="incomplete", reason="missing_or_invalid_scope", observations=[], comparisons=[])
    if outcome != "success":
        result.update(status="incomplete", step_outcome="not_successful")
    return result


def publish(
    private: Path, public: Path, staging: Path, *, candidate: str, plan: str, outcomes: dict[str, str]
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None or set(outcomes) != {item[0] for item in PLANS[plan]}:
        raise ValueError("ci_identity_invalid")
    scopes = [
        _scope(
            private,
            scope=scope,
            runs=runs,
            measurement=measurement,
            timeout=timeout,
            candidate=candidate,
            outcome=outcomes[scope],
        )
        for scope, runs, measurement, timeout in PLANS[plan]
    ]
    required_semantics = {
        (
            scope["scope"],
            f"private_samples/{row['case_id']}.r{row['run']:02d}.s0000.{row['arm']}.semantic.json",
        )
        for scope in scopes
        for row in scope["observations"]
        if row["status"] == "completed" and not row["case_id"].startswith("bundle_kernel.")
    }
    try:
        staged = stage(private, staging, plan=plan, required_semantics=required_semantics)
    except (OSError, ValueError):
        staged = {"status": "incomplete", "reason": "archive_staging_failed"}
    phase_parity = None
    if plan == "phase-attribution":
        validation = {row["case_id"]: row for row in scopes[0]["observations"] if row["status"] == "completed"}
        observed = scopes[1]["observations"]
        compared_fields = ("fixture_sha256", "semantic_sha256", "evidence_sha256", "entry_sha256", "protect_sha256")
        phase_parity = (
            len(validation) == 2
            and len(observed) == 6
            and all(
                row["status"] == "completed"
                and row["case_id"] in validation
                and all(row.get(key) == validation[row["case_id"]].get(key) for key in compared_fields)
                for row in observed
            )
        )
    report = {
        "schema": "hol-guard.package-ci.v2",
        "plan": plan,
        "status": "completed"
        if all(item["status"] == "completed" for item in scopes)
        and staged["status"] == "complete"
        and phase_parity is not False
        else "incomplete",
        "source": {"baseline": BASELINE, "candidate": candidate},
        "scopes": scopes,
        "private_staging": staged,
        "installed_qualified": False,
        "tail_qualified": False,
        "native_activation_authorized": False,
        "native_benefit_proven": False,
    }
    if phase_parity is not None:
        report["instrumented_semantic_parity"] = phase_parity
    public.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_private(public, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--plan", choices=tuple(PLANS), required=True)
    parser.add_argument("--outcome", action="append", default=[])
    args = parser.parse_args()
    report = publish(
        args.private,
        args.public,
        args.staging,
        candidate=args.candidate,
        plan=args.plan,
        outcomes=dict(item.split("=", 1) for item in args.outcome),
    )
    print(json.dumps({"status": report["status"], "native_benefit_proven": False}))
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
