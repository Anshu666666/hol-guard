"""Run one separately admitted owned-child gate; preserve every qualification gap."""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from scripts.ci.rsp131_inode_probe import capture
from scripts.ci.rsp131_inode_probe.evidence import LIMITS, validate
from scripts.ci.rsp131_inode_probe.identity import digest, environment, file_identity, git, source_snapshot

ROOT = Path(__file__).resolve().parents[3]
LEGACY_COMMIT = "67d90ff0211dbc1d878499b90eecb126da98b7fb"
LEGACY_HASHES = {
    ".github/workflows/sqlite-syscall-feasibility-diagnostic.yml": "e7b1ebee2314fb50e77ffdb35086e20132ef18f6fbaa63e490fa42c08dd3401c",
    "scripts/ci/run_sqlite_syscall_diagnostic.py": "0b6c301665e08a44a08a03c563ef182be25130b203814cd9ce7bb2da4f7d0fb9",
    "scripts/probe_sqlite_syscall_observation.py": "c5d2767d9dc9daa24ddb19a41ef50eb4d137ba4161b0bc2fd8786893decb719e",
    "scripts/sqlite_syscall_probe_child.py": "8952e4c1e2930f2ff18e20c921d57ac3ede7fea10115e081e7987605e9c15758",
    "scripts/sqlite_syscall_probe_supervision.py": "3686af06d61fcc4d44f54150f8c4d59840cdcaf273383d0cf94740e9c733a478",
    "scripts/sqlite_syscall_trace_diagnostics.py": "ad6549984257dd637cdfb9219085d72a82508e4ab1482be814a3a7cb5025a042",
    "tests/test_sqlite_syscall_hosted_diagnostic.py": "bc99160b00b58f8ccdc549747dcafd23301c2d67789c1537f38fa67c4cd49e15",
    "tests/test_sqlite_syscall_probe_parser.py": "a2c2644af09bd57e41a68c63ed182916ad6c51015a187d8914a4d612ca472447",
    "tests/test_sqlite_syscall_trace_diagnostics.py": "1d1ed5e67531532cad5752a51911efebabc95370fb36c4cee8c17c3ff7f488cc"
}
SOURCE_PATHS = [
    ".github/workflows/rsp131-owned-inode-feasibility.yml",
    "review-evidence/2026-09-19/rsp131-inode-feasibility/README.md",
    "review-evidence/2026-09-19/rsp131-inode-feasibility/source-preparation-receipt.json",
    "scripts/ci/rsp131_inode_probe/capture.py",
    "scripts/ci/rsp131_inode_probe/child.c",
    "scripts/ci/rsp131_inode_probe/driver.py",
    "scripts/ci/rsp131_inode_probe/evidence.py",
    "scripts/ci/rsp131_inode_probe/identity.py",
    "scripts/ci/rsp131_inode_probe/probe.c",
    "scripts/ci/rsp131_inode_probe/probe.h",
    "scripts/ci/rsp131_inode_probe/trace.c",
    "tests/test_rsp131_inode_feasibility.py",
    "tests/test_rsp131_inode_file_identity.py"
]
C_NAMES = ("probe.c", "trace.c", "child.c")
FLAGS = ("-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-Wformat=2")
EXPECTED_NEW_CASES = {
    "test_complete_finite_transcript_is_narrowly_admitted": 2,
    "test_identity_pairing_errors_never_produce_metrics": 47,
    "test_missing_records_refuse_even_after_resequencing": 6,
    "test_unknown_or_extra_event_never_disappears": 9,
    "test_external_capture_and_process_binding_is_required": 9,
    "test_decoder_refuses_censoring_or_unrecognized_payload": 7,
    "test_permission_and_identity_refusals_have_no_fallback": 4,
    "test_regular_bytes_and_descriptor_retirement": 1,
    "test_nonregular_or_out_of_bound_refused": 4,
    "test_real_mutation_before_final_stat_refuses": 2,
    "test_growth_beyond_original_size_refuses": 1,
}


def junit(path: Path, expected: int, families: dict[str, int] | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > 4 * 1024 * 1024 or b"<!" in data:
        raise ValueError("junit_bound_or_declaration")
    tree = ET.fromstring(data)
    cases = list(tree.iter("testcase"))
    outcomes = collections.Counter()
    actual_families: collections.Counter[str] = collections.Counter()
    identities = []
    for case in cases:
        tags = [child.tag for child in case]
        outcome = "error" if "error" in tags else "failed" if "failure" in tags else "skipped" if "skipped" in tags else "passed"
        outcomes[outcome] += 1
        name = case.attrib.get("name", "")
        actual_families[name.split("[", 1)[0]] += 1
        row: dict[str, Any] = {"class": case.attrib.get("classname", ""), "name": name, "outcome": outcome}
        if outcome != "passed":
            details = []
            for child in case:
                if child.tag not in {"error", "failure", "skipped"}:
                    continue
                text = (child.text or "").replace(str(ROOT), "<candidate>")
                temporary = os.environ.get("RUNNER_TEMP")
                if temporary:
                    text = text.replace(temporary, "<runner-temp>")
                details.append({
                    "kind": child.tag, "type": child.attrib.get("type", "")[:160],
                    "text": text[:8192], "text_truncated": len(text) > 8192,
                })
            if outcomes["error"] + outcomes["failed"] + outcomes["skipped"] <= 32:
                row["failure_details"] = details
        identities.append(row)
    valid = (
        len(cases) == expected and outcomes["passed"] == expected
        and len({(row["class"], row["name"]) for row in identities}) == expected
        and all(int(suite.attrib.get(key, "0")) == 0 for suite in tree.iter("testsuite")
                for key in ("failures", "errors", "skipped"))
    )
    if families is not None:
        valid = valid and actual_families == families
    return {
        "passed": valid, "cases": len(cases), "outcomes": dict(outcomes),
        "families": dict(actual_families), "junit_sha256": digest(data), "case_records": identities,
        "failure_details_truncated": sum(outcomes[key] for key in ("error", "failed", "skipped")) > 32,
    }


def clean(metadata: dict[str, Any]) -> bool:
    return (
        metadata["returncode"] == 0 and metadata["timed_out"] is False
        and metadata["supervisor_failure"] is None
        and all(metadata[key] is True for key in (
            "contained", "leader_reaped", "reader_resources_retired", "streams_complete",
        ))
    )


def command(
    argv: list[str], work: Path, supervisor: Any, report: dict[str, Any], label: str,
) -> tuple[bool, bytes]:
    metadata, output, error = capture.run(argv, work, supervisor)
    metadata.update(
        label=label, stdout_bytes=len(output), stdout_sha256=digest(output),
        stderr_bytes=len(error), stderr_sha256=digest(error),
    )
    diagnostics = []
    for match in re.finditer(
        rb"(probe|trace|child)\.(c|h):(\d+):(\d+): (error|warning): ([^\r\n]+)", error,
    ):
        diagnostics.append({
            "file": (match[1] + b"." + match[2]).decode("ascii"),
            "line": int(match[3]), "column": int(match[4]), "level": match[5].decode("ascii"),
            "message": match[6].decode("utf-8", errors="replace")[:240],
        })
    metadata["source_diagnostics"] = diagnostics[:32]
    report["commands"].append(metadata)
    return clean(metadata), output


def dependency_paths(data: bytes, root: Path) -> list[Path]:
    if not 0 < len(data) <= 256 * 1024:
        raise ValueError("dependency_output_bound")
    text = data.decode("ascii").replace("\\\n", " ")
    if text.count(":") != 1 or any(character in text for character in ("\\", "$", "\0")):
        raise ValueError("dependency_encoding")
    tokens = text.split(":", 1)[1].split()
    if not 1 <= len(tokens) <= 512:
        raise ValueError("dependency_count")
    paths = {(Path(token) if Path(token).is_absolute() else root / token).resolve(strict=True) for token in tokens}
    if any(not path.is_absolute() for path in paths):
        raise ValueError("dependency_path")
    return sorted(paths)


def header_snapshot(paths: list[Path]) -> dict[str, Any]:
    result = {}
    total = 0
    for path in paths:
        row = file_identity(path, maximum=4 * 1024 * 1024)
        total += row["bytes"]
        if total > 32 * 1024 * 1024:
            raise ValueError("header_closure_bound")
        result[str(path)] = row
    return result


def compile_probe(compiler: Path, work: Path, supervisor: Any, report: dict[str, Any]) -> Path:
    source = Path(__file__).resolve().parent
    predicted: dict[str, list[Path]] = {}
    all_headers: set[Path] = set()
    for name in C_NAMES:
        ok, output = command(
            [str(compiler), *FLAGS, "-M", str(source / name)],
            work, supervisor, report, "dependencies_" + name,
        )
        if not ok:
            raise ValueError("dependency_command_failed")
        predicted[name] = dependency_paths(output, work)
        all_headers.update(predicted[name])
    report["compiler_input_headers_before"] = header_snapshot(sorted(all_headers))
    objects = []
    for name in C_NAMES:
        target = work / (name + ".o")
        dependencies = work / (name + ".d")
        ok, _ = command(
            [str(compiler), *FLAGS, "-MD", "-MF", str(dependencies), "-c", str(source / name), "-o", str(target)],
            work, supervisor, report, "compile_" + name,
        )
        if not ok or dependency_paths(dependencies.read_bytes(), work) != predicted[name]:
            raise ValueError("compiled_dependency_binding")
        objects.append(str(target))
    binary = work / "owned-inode-probe"
    ok, _ = command(
        [str(compiler), *FLAGS, *objects, "-o", str(binary)], work, supervisor, report, "link",
    )
    if not ok:
        raise ValueError("link_failed")
    report["compiler_input_headers_after"] = header_snapshot(sorted(all_headers))
    report["compiler_input_headers_unchanged"] = (
        report["compiler_input_headers_before"] == report["compiler_input_headers_after"]
    )
    if not report["compiler_input_headers_unchanged"]:
        raise ValueError("compiler_headers_changed")
    return binary


def _save(path: Path, report: dict[str, Any]) -> None:
    data = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("ascii")
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("report_bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--legacy-status", required=True)
    parser.add_argument("--finite-status", required=True)
    parser.add_argument("--legacy-junit", type=Path, required=True)
    parser.add_argument("--finite-junit", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any] = {
        "schema": "hol-guard.rsp131-owned-inode-driver.v1", **LIMITS,
        "status": "not_run", "feasible": False, "commands": [],
        "workflow_commit": args.expected_commit, "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "legacy_source_commit": LEGACY_COMMIT, "prior_111_controls_changed": False,
        "prior_feasibility_run": 35412005276, "prior_observations_supply_current_credit": False,
        "native_ingestion_qualification": False, "headline_timing_eligible": False,
        "privilege_changes_attempted": False, "raw_buffers_observed_or_exported": False,
        "scope": "one_owned_single_thread_child_descriptor_identity_feasibility",
        "inner_deadline_seconds": 6, "outer_command_deadline_seconds": 8,
        "compile_flags": list(FLAGS), "source_unchanged": False, "legacy_source_unchanged": False,
    }
    legacy = args.legacy_root.resolve(strict=True)
    compiler = None
    try:
        if re.fullmatch(r"[0-9a-f]{40}", args.expected_commit) is None:
            raise ValueError("expected_commit")
        report["source_before"] = source_snapshot(ROOT, args.expected_commit, SOURCE_PATHS)
        report["legacy_source_before"] = source_snapshot(legacy, LEGACY_COMMIT, list(LEGACY_HASHES))
        if {path: row["sha256"] for path, row in report["legacy_source_before"].items()} != LEGACY_HASHES:
            raise ValueError("preserved_legacy_source_hashes")
        report["legacy_controls"] = junit(args.legacy_junit, 111)
        report["new_controls"] = junit(args.finite_junit, 92, EXPECTED_NEW_CASES)
        if (
            args.legacy_status != "success" or args.finite_status != "success"
            or not report["legacy_controls"]["passed"] or not report["new_controls"]["passed"]
        ):
            raise ValueError("finite_controls_not_passed")
        if sys.platform != "linux" or os.getuid() == 0 or os.geteuid() != os.getuid():
            raise ValueError("unprivileged_linux_required")
        found = shutil.which("cc", path="/usr/bin:/bin")
        if found is None:
            raise ValueError("existing_compiler_unavailable")
        compiler = Path(found).resolve(strict=True)
        report["environment_before"] = environment(compiler)
        env = report["environment_before"]
        if env["machine"] != "x86_64" or int(env["status"].get("CapEff", "-1"), 16) != 0:
            raise ValueError("architecture_or_effective_capabilities")
        if any(os.environ.get(name) for name in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")):
            raise ValueError("loader_override_present")
        args.work.mkdir(mode=0o700)
        if args.work.stat().st_uid != os.getuid() or args.work.stat().st_mode & 0o777 != 0o700:
            raise ValueError("owned_work_directory")
        spec = importlib.util.spec_from_file_location(
            "_rsp131_preserved_supervisor", legacy / "scripts/sqlite_syscall_probe_supervision.py",
        )
        if spec is None or spec.loader is None:
            raise ValueError("preserved_supervisor_loader")
        supervisor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(supervisor)
        if supervisor.TIMEOUT_SECONDS != 8.0 or supervisor.MAX_STREAM_BYTES != 256 * 1024:
            raise ValueError("preserved_supervisor_bounds")
        ok, version = command([str(compiler), "--version"], args.work, supervisor, report, "compiler_version")
        if not ok:
            raise ValueError("compiler_identity_command")
        report["compiler_version_sha256"] = digest(version)
        report["status"] = "compiling"
        binary = compile_probe(compiler, args.work, supervisor, report)
        report["binary_before"] = file_identity(binary)
        private = args.work / "control"
        private.mkdir(mode=0o700)
        report["status"] = "observing_owned_child"
        metadata, output, error = capture.run([str(binary), str(private)], args.work, supervisor)
        report["capture"] = metadata | {
            "stdout_bytes": len(output), "stdout_sha256": digest(output),
            "stderr_bytes": len(error), "stderr_sha256": digest(error),
        }
        report["observation"] = validate(
            output, collector_pid=metadata["pid"], returncode=metadata["returncode"],
            capture_complete=(
                metadata["streams_complete"] is True and metadata["reader_resources_retired"] is True
                and metadata["timed_out"] is False and metadata["supervisor_failure"] is None and not error
            ),
            owned_group_retired=metadata["contained"] is True and metadata["leader_reaped"] is True,
        )
        report["binary_after"] = file_identity(binary)
        report["binary_unchanged"] = report["binary_before"] == report["binary_after"]
        report["feasible"] = report["observation"]["feasible"] and report["binary_unchanged"]
        report["status"] = "finite_owned_child_feasible" if report["feasible"] else "owned_child_refused"
    except Exception as error:
        report.update(status="controlled_refusal", error_type=type(error).__name__, feasible=False)
        if isinstance(error, ValueError) and len(str(error)) <= 80:
            report["reason"] = str(error)
        if isinstance(error, OSError):
            report["errno"] = error.errno
    finally:
        try:
            report["source_after"] = source_snapshot(ROOT, args.expected_commit, SOURCE_PATHS)
            report["legacy_source_after"] = source_snapshot(legacy, LEGACY_COMMIT, list(LEGACY_HASHES))
            report["source_unchanged"] = report.get("source_before") == report["source_after"]
            report["legacy_source_unchanged"] = report.get("legacy_source_before") == report["legacy_source_after"]
            report["tracked_checkouts_clean"] = all(
                not git(path, "status", "--porcelain", "--untracked-files=no") for path in (ROOT, legacy)
            )
            if compiler is not None and "environment_before" in report:
                report["environment_after"] = environment(compiler)
                report["environment_unchanged"] = report["environment_before"] == report["environment_after"]
        except Exception as error:
            report["final_binding_error"] = type(error).__name__
            report["feasible"] = False
        if not all(report.get(key) is True for key in (
            "source_unchanged", "legacy_source_unchanged", "tracked_checkouts_clean", "environment_unchanged",
        )):
            report["feasible"] = False
        _save(args.output, report)
    return 0 if report["feasible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
