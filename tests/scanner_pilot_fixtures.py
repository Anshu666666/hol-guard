"""Synthetic proof records for evidence-boundary failure tests, never timings."""

from __future__ import annotations

from scripts.native_slo_evidence_format import canonical, digest
from scripts.scanner_pilot_protocol import ARMS, SCHEMA, captured, planned

SOURCE_SHA = "a" * 40


def snapshot(case="working_provider_large", run=0, selection="full"):
    source = {
        key: "b" * 64
        for key in (
            "scanner_sha256",
            "lock_sha256",
            "rust_lock_sha256",
            "harness_sha256",
            "dependency_sha256",
            "python_sha256",
            "binary_sha256",
        )
    }
    source.update(
        source_sha=SOURCE_SHA,
        source_tree="c" * 40,
        python_source_tree="d" * 40,
        pilot_tree="e" * 40,
        python_version=[3, 12, 14],
    )
    source["host"] = {
        "system": "linux",
        "architecture": "x86_64",
        "logical_cpus": 4,
        "image_identity_available": True,
        "runner_image_sha256": "a" * 64,
        "kernel_sha256": "f" * 64,
    }
    fixture = {"definition": {"name": case}, "dimensions": {}, "files": []}
    fixture["sha256"] = digest(canonical(fixture))
    variants = ["complete", "findings", "files", "bytes", "default", "missing"]
    if case != "working_many_unique":
        variants.append("finding-limit")
    result = digest(b"synthetic-complete-result")
    values = {
        "plan.json": {
            "schema": SCHEMA,
            "case": case,
            "run": run,
            "selection": selection,
            "source_sha": SOURCE_SHA,
            "attempts": planned(case, run),
        },
        "source.json": source,
        "fixture.json": fixture,
        "preflight.json": {"passed": True, "complete_result_sha256": result, "variants": variants},
        "worker.json": {"finished": True, "failure": None, "cache_unavailable": [], "identity_verified_after": True},
    }
    for prefix in ["oracle", *("preflight-" + label for label in variants)]:
        for arm in ARMS:
            values[f"{prefix}-{arm}.terminal.json"] = {"status": "completed", "result_sha256": result}
    for attempt in planned(case, run):
        identity = attempt["id"]
        process = {
            "failure": None,
            "returncode": 0 if case == "working_many_unique" else 3,
            "full_cli_wall_ms": 4.0 if attempt["arm"] == "optimized_python" else 2.0,
            "full_cli_process_tree_cpu_ms": 2.0 if attempt["arm"] == "optimized_python" else 1.0,
            "stdout": captured(b"private synthetic stdout"),
            "stderr": captured(b"private diagnostic"),
            "native_pilot_native_files": 4,
            "native_pilot_python_fallback_files": 0,
            "native_pilot_cleanup_failures": 0,
        }
        values[identity + ".offered.json"] = attempt
        values[identity + ".terminal.json"] = {
            "identity": attempt,
            "status": "completed",
            "failure": None,
            "process": process,
            "result_sha256": result,
        }
        values[identity + ".verified.json"] = {"verified": True, "result_sha256": result}
    return values


def encoded(values):
    return tuple((name, canonical(value)) for name, value in sorted(values.items()))
