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
    values["interpreter.json"] = interpreter_record()
    values["worker.json"]["interpreter_setup_sha256"] = digest(canonical(values["interpreter.json"]))
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


def interpreter_record():
    """Synthetic setup commitment for evidence tests, never a hosted result."""
    runtime = {
        "executable": "/private/environment/bin/python",
        "prefix": "/private/environment",
        "base_prefix": "/private/toolchain",
        "version": "3.12.14 fixture",
        "stdlib": "/private/toolchain/lib/python3.12",
        "platstdlib": "/private/environment/lib/python3.12",
        "config_sha256": "c" * 64,
    }
    return {
        "schema": "hol-guard.scanner-private-interpreter.v1",
        "copy": {
            "schema": "hol-guard.qualification-interpreter.v1",
            "platform": "posix",
            "private_copy": True,
            "bytes": 100,
            "source_sha256": "b" * 64,
            "copy_sha256": "b" * 64,
            "source": {"mode": 0o777, "owner": "root", "group_writable": True, "world_writable": True, "regular": True},
            "copy": {
                "mode": 0o700,
                "owner": "current_user",
                "group_writable": False,
                "world_writable": False,
                "regular": True,
            },
        },
        "runtime_before": runtime,
        "runtime_after": dict(runtime),
    }
