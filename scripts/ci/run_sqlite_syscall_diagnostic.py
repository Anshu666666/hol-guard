"""Retain one source-bound Ubuntu disposable tracing outcome, never qualification."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FROZEN_HELPERS = {
    "scripts/probe_sqlite_syscall_observation.py": "c5d2767d9dc9daa24ddb19a41ef50eb4d137ba4161b0bc2fd8786893decb719e",
    "scripts/sqlite_syscall_probe_child.py": "8952e4c1e2930f2ff18e20c921d57ac3ede7fea10115e081e7987605e9c15758",
    "scripts/sqlite_syscall_probe_supervision.py": "640c72b86482f4b7564e9c2d87988f6f08655c274790a6bb05d8b4d17e896f37",
    "scripts/sqlite_syscall_trace_diagnostics.py": "ad6549984257dd637cdfb9219085d72a82508e4ab1482be814a3a7cb5025a042",
    "tests/test_sqlite_syscall_probe_parser.py": "a2c2644af09bd57e41a68c63ed182916ad6c51015a187d8914a4d612ca472447",
}
HOSTED_SOURCES = (
    "scripts/ci/run_sqlite_syscall_diagnostic.py",
    "tests/test_sqlite_syscall_hosted_diagnostic.py",
    "tests/test_sqlite_syscall_trace_diagnostics.py",
    ".github/workflows/sqlite-syscall-feasibility-diagnostic.yml",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(root: Path, expected_commit: str) -> dict[str, object]:
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        raise ValueError("invalid source commit")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, timeout=5).decode().strip()
    if actual != expected_commit:
        raise ValueError("source commit mismatch")
    hashes = {}
    for name in (*FROZEN_HELPERS, *HOSTED_SOURCES):
        digest = _sha(root / name)
        committed = subprocess.check_output(["git", "show", f"{actual}:{name}"], cwd=root, timeout=5)
        if hashlib.sha256(committed).hexdigest() != digest or digest != FROZEN_HELPERS.get(name, digest):
            raise ValueError("source bytes mismatch")
        hashes[name] = digest
    return {
        "commit": actual,
        "sha256": hashes,
        "original_probe_commit": "978f1d7c2a6b6e7d9d61e5db7fdf0d0ba381c016",
        "probe_profile": "additive_bounded_syntax_diagnostics_v2",
        "original_hosted_ambiguous_run": 35380331993,
    }


def python_sqlite_identity() -> dict[str, object]:
    import _sqlite3

    connection = sqlite3.connect(":memory:")
    try:
        source_id = connection.execute("select sqlite_source_id()").fetchone()[0]
        options = sorted(row[0] for row in connection.execute("pragma compile_options"))
    finally:
        connection.close()
    origin = getattr(_sqlite3, "__file__", None)
    images = {}
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and "libsqlite3" in Path(fields[5]).name:
            path = Path(fields[5])
            images[path.name] = _sha(path)
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_sha256": _sha(Path(sys.executable)),
        "sqlite_module_kind": "builtin" if origin is None else "extension",
        "sqlite_module_sha256": None if origin is None else _sha(Path(origin)),
        "sqlite_shared_image_sha256": images,
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_source_id": source_id,
        "compile_options_sha256": hashlib.sha256(json.dumps(options).encode()).hexdigest(),
    }


def strace_identity() -> dict[str, str] | None:
    executable = shutil.which("strace")
    if executable is None:
        return None
    path = Path(executable)
    digest = _sha(path)
    # Only a fixed version flag on the runner's existing binary; no installation.
    version = subprocess.run(
        [executable, "--version"], capture_output=True, timeout=5, check=True, env={**os.environ, "LC_ALL": "C"}
    ).stdout
    if len(version) > 16_384 or not version:
        raise ValueError("strace version unavailable")
    first = version.decode("ascii").splitlines()[0]
    if re.fullmatch(r"strace -- version [0-9][0-9A-Za-z.+_-]*", first) is None or _sha(path) != digest:
        raise ValueError("strace version or binary identity ambiguous")
    return {"version": first, "sha256": digest}


def probe_identity_matches(probe: dict[str, Any], runtime: dict[str, object], tracer: dict[str, str]) -> bool:
    if probe.get("python_sha256") != runtime["python_sha256"] or probe.get("strace_sha256") != tracer["sha256"]:
        return False
    expected = {Path(name).name: digest for name, digest in FROZEN_HELPERS.items() if name.startswith("scripts/")}
    if probe.get("source_sha256") != expected:
        return False
    for arm in ("baseline", "observed"):
        child = probe.get(arm, {}).get("child")
        if not isinstance(child, dict) or not isinstance(child.get("sqlite"), dict):
            return False
        if any(
            child["sqlite"].get(key) != runtime[key]
            for key in ("sqlite_version", "sqlite_source_id", "compile_options_sha256")
        ):
            return False
    return True


def hosted_report(expected_commit: str, controls_status: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "guard.sqlite-syscall-hosted-diagnostic.v1",
        "cohort": "fresh_ubuntu_hosted_disposable",
        "distinct_from_denied_local_v3": True,
        "status": "unavailable",
        "stage": "platform",
        "installed_workload": False,
        "rsp131_qualified": False,
        "physical_device_bytes_measured": False,
        "sqlite_file_lifetime_attribution_complete": False,
        "observer_overhead_quantified": False,
        "raw_trace_exported": False,
        "controls_status": controls_status,
    }
    try:
        if sys.platform != "linux":
            return {**report, "reason": "linux_required"}
        report["stage"] = "source_binding"
        report["source"] = source_identity(ROOT, expected_commit)
        if controls_status != "success":
            return {**report, "reason": "finite_controls_not_passed"}
        report["stage"] = "runtime_identity"
        report["runtime"] = python_sqlite_identity()
        report["stage"] = "strace_identity"
        tracer = strace_identity()
        if tracer is None:
            return {**report, "reason": "strace_unavailable"}
        report["strace"] = tracer
        report["stage"] = "disposable_probe"
        sys.path.insert(0, str(ROOT))
        probe = importlib.import_module("scripts.probe_sqlite_syscall_observation").run_probe()
        report["probe"] = probe
        report["stage"] = "final_identity"
        report["source_unchanged"] = source_identity(ROOT, expected_commit) == report["source"]
        report["runtime_unchanged"] = python_sqlite_identity() == report["runtime"]
        report["strace_unchanged"] = strace_identity() == tracer
        report["observed_identity_matches"] = probe_identity_matches(probe, report["runtime"], tracer)
        # Denial remains denial even when no child executed; never infer counts.
        if probe["status"] == "denied":
            if "descriptor_witness" in probe:
                raise ValueError("denied result contains syscall counts")
            report.update(status="denied", reason="tracing_permission_denied")
        elif all(
            report[key]
            for key in ("source_unchanged", "runtime_unchanged", "strace_unchanged", "observed_identity_matches")
        ):
            report.update(status=probe["status"], reason=probe.get("reason", "finite_disposable_controls_only"))
        else:
            report.update(status="ambiguous", reason="source_or_runtime_identity_unproved")
        report["stage"] = "complete"
    except Exception as error:
        # Exception text can include private paths or trace buffers; retain type only.
        report.update(status="ambiguous", reason="diagnostic_failed", error_type=type(error).__name__)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--controls-status", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = hosted_report(args.commit, args.controls_status)
    descriptor = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({"status": report["status"], "stage": report["stage"], "rsp131_qualified": False}))
    return 0 if report["status"] == "feasible" else 1


if __name__ == "__main__":
    raise SystemExit(main())
