"""One unchanged installed Windows probe with a bounded checkpoint observer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path

IDENTITY_BLOB = "c3b2bf6adfc3feb95a5cb88d60792f537be71356"
OBSERVER_BLOB = "8f34ab7369c12d309cd3e54bc0315812365a1e21"
DRIVER = "ci/native_runtime/windows_checkpoint_diagnostic.py"
PROCESS_SECONDS = 60.0
OUTPUT_LIMIT = 1024 * 1024


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None or name in sys.modules:
        raise RuntimeError("diagnostic_module_spec_invalid")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_identity_path = Path(__file__).with_name("windows_checkpoint_identity.py")
# Bind the explicit helper before executing it; no namespace-package lookup.
_identity_bytes = _identity_path.read_bytes()
_identity_header = b"blob " + str(len(_identity_bytes)).encode() + b"\0"
if hashlib.sha1(_identity_header + _identity_bytes).hexdigest() != IDENTITY_BLOB:
    raise RuntimeError("diagnostic_identity_helper_changed")
identity = load_module("_checkpoint_identity", _identity_path)
require = identity.require
write_json = identity.write_json


def validate_observation(report: dict[str, object]) -> None:
    require(report["observer_bound"] is True, "checkpoint_observer_not_bound")
    require(report["observer_invalid"] is False, "checkpoint_observer_invalid")
    require(report["exact_seams_restored"] is True, "checkpoint_seams_not_restored")
    require(report["owned_writer_thread_retired"] is True, "checkpoint_writer_not_retired")
    # Lost observations remain explicit; they do not establish absence of errors.


def capture_after(args, report: dict[str, object], installation: dict[str, object]) -> None:
    current = identity.installation_identity(args.source_root, args.original_artifacts)
    write_json(args.output / "child-installation-after.json", current)
    report["imports_after"] = identity.import_identity(args.source_root, args.harness_root)
    require(current == installation, "child_installed_files_changed")
    report["installed_files_unchanged"] = True


def child(args) -> int:
    from codex_plugin_scanner.guard.daemon import (
        runtime_hook_evidence_journal as journal_module,
    )
    from codex_plugin_scanner.guard.daemon import (
        runtime_hook_evidence_writer as writer_module,
    )

    report = {
        "schema": "hol-guard.windows-checkpoint-child.v1",
        "status": "started",
        "original_probe_invocations": 0,
        "historical_cause_identified": False,
    }
    write_json(args.output / "child.json", report)
    installation = identity.installation_identity(args.source_root, args.original_artifacts)
    write_json(args.output / "child-installation-before.json", installation)
    probe = load_module("_checkpoint_original_probe", args.source_root / identity.PROBE)
    observer_path = args.harness_root / "ci/native_runtime/windows_checkpoint_observation.py"
    require(identity.blob_id(observer_path.read_bytes()) == OBSERVER_BLOB, "observer_source_changed")
    observer_module = load_module("_checkpoint_observer", observer_path)
    observation = observer_module.CheckpointObservation(probe, writer_module, journal_module)
    report["imports_before"] = identity.import_identity(args.source_root, args.harness_root)
    write_json(args.output / "child.json", report)
    original_failed = True
    postflight_failed = False
    try:
        with observation:
            report["original_probe_invocations"] = 1
            result = probe.main(json_path=args.output / "native-default-auto.json")
        report["original_probe_returncode"] = result
        original_failed = False
    finally:
        # No observer/postflight failure may replace an original probe exception.
        try:
            observed = observation.report()
            write_json(args.output / "checkpoint-observation.json", observed)
            capture_after(args, report, installation)
            validate_observation(observed)
        except Exception:
            postflight_failed = True
            report["postflight_failed"] = True
        report["status"] = "failed" if original_failed or postflight_failed else "completed"
        try:
            write_json(args.output / "child.json", report)
        except Exception:
            if not original_failed:
                raise
        if not original_failed and postflight_failed:
            raise RuntimeError("checkpoint_child_postflight_failed")
    return int(result)


def clean_environment() -> tuple[dict[str, str], list[str]]:
    environment = dict(os.environ)
    removed = []
    for key in tuple(environment):
        if key.upper().startswith(("PYTHON", "PYTEST", "HOL_GUARD", "GUARD_")) or key == "GITHUB_TOKEN":
            removed.append(key)
            del environment[key]
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment, sorted(removed)


def validate_result(output: Path) -> None:
    report = json.loads((output / "child.json").read_text(encoding="utf-8"))
    require(
        report["status"] == "completed"
        and report["original_probe_invocations"] == 1
        and report["original_probe_returncode"] == 0
        and report["installed_files_unchanged"] is True,
        "original_probe_not_completed",
    )
    observation = json.loads((output / "checkpoint-observation.json").read_text(encoding="utf-8"))
    validate_observation(observation)
    original = json.loads((output / "native-default-auto.json").read_text(encoding="utf-8"))
    require(
        original["corpus_decisions"] == original["resident_decisions"] == 21
        and len(original["route_receipts"]) == 21,
        "original_probe_population_mismatch",
    )
    # The original main owns all route/mode/receipt assertions. A checkpoint
    # error is retained as an observed error, never rewritten into a pass.
    require(
        original["receipt_metrics"]["accepted"] == original["receipt_metrics"]["processed"] == 21,
        "original_receipt_population_mismatch",
    )


def emit_terminal_evidence(output: Path) -> None:
    names = (
        "result.json", "child.json", "checkpoint-observation.json",
        "native-default-auto.json", "native-default-auto-failure.json", "stdout.log", "stderr.log",
    )
    payload = {"schema": "windows-checkpoint-terminal.v1", "original_files": {}, "manifests": {}}
    for name in names:
        file = output / name
        if not file.is_file():
            payload["original_files"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 2_000_000, "terminal_original_bound")
        raw = file.read_bytes()
        payload["original_files"][name] = {
            "bytes": len(raw), "sha256": identity.digest(raw), "content": raw.decode("utf-8"),
        }
    for name in (
        "source-before.json", "source-after.json",
        "installation-before.json", "installation-after.json",
        "child-installation-before.json", "child-installation-after.json",
    ):
        file = output / name
        if not file.is_file():
            payload["manifests"][name] = {"missing": True}
            continue
        require(file.stat().st_size <= 8_000_000, "terminal_manifest_bound")
        raw = file.read_bytes()
        value = json.loads(raw)
        row = {
            "bytes": len(raw), "sha256": identity.digest(raw),
            "full_original_retained_in_artifact": True,
        }
        if name.startswith("source-"):
            row["bindings"] = {
                key: {
                    "head": part["head"], "tree": part["tree"], "parents": part["parents"],
                    "files": len(part["files"]),
                }
                for key, part in value.items()
            }
        else:
            row["bindings"] = {
                key: value[key] for key in (
                    "kind", "source", "source_tree", "literal_build_sha", "archive_bytes",
                    "archive_sha256", "wheel_name", "wheel_bytes", "wheel_sha256", "python",
                    "machine", "executable_sha256", "runtime_sha256", "runtime_bytes",
                )
            }
            row["wheel_file_count"] = len(value["wheel_files"])
            row["installed_record_file_count"] = len(value["installed_record_files"])
        payload["manifests"][name] = row
    encoded = json.dumps(payload, sort_keys=True)
    require(len(encoded.encode()) <= 8_000_000, "terminal_total_bound")
    print("WINDOWS_CHECKPOINT_DIAGNOSTIC_BEGIN")
    print(encoded, flush=True)
    print("WINDOWS_CHECKPOINT_DIAGNOSTIC_END", flush=True)


def parent(args) -> int:
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "hol-guard.windows-checkpoint-diagnostic.v1", "status": "started",
        "source": identity.SOURCE, "source_tree": identity.SOURCE_TREE,
        "literal_build_sha": identity.BUILD_SHA, "harness": args.harness_sha,
        "scope": "one_original_installed_default_auto_main_21_routes",
        "process_seconds": PROCESS_SECONDS, "combined_output_byte_cap": OUTPUT_LIMIT,
        "inner_deadlines_unchanged": True, "native_wheel_full_validation": False,
        "performance_qualification": False, "historical_cause_identified": False,
        "no_observed_exception_means": "historical_cause_unobserved",
    }
    write_json(output / "result.json", result)
    before = installation = None
    failed = True
    try:
        before = identity.bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
        write_json(output / "source-before.json", before)
        installation = identity.installation_identity(args.source_root, args.original_artifacts)
        write_json(output / "installation-before.json", installation)
        result["parent_imports_before"] = identity.import_identity(args.source_root, args.harness_root)
        environment, removed = clean_environment()
        result["removed_environment_key_names"] = removed
        command = [
            sys.executable, "-I", str(args.harness_root / DRIVER), "--child",
            "--source-root", str(args.source_root), "--harness-root", str(args.harness_root),
            "--harness-sha", args.harness_sha, "--original-artifacts", str(args.original_artifacts),
            "--output", str(output),
        ]
        result["command"] = command
        started = time.monotonic()
        result["process_start_monotonic"] = started
        bounded = run_isolated_hook_process(
            command, input_text="", cwd=args.source_root, environment=environment,
            deadline_monotonic=started + PROCESS_SECONDS, output_limit=OUTPUT_LIMIT,
            allow_windows_breakaway=False, windows_kill_on_job_close=True,
        )
        result["process_finish_monotonic"] = time.monotonic()
        (output / "stdout.log").write_text(bounded.stdout, encoding="utf-8")
        (output / "stderr.log").write_text(bounded.stderr, encoding="utf-8")
        outcome = asdict(bounded)
        outcome.pop("stdout")
        outcome.pop("stderr")
        result["process"] = outcome
        require(
            bounded.returncode == 0 and not bounded.timed_out
            and not bounded.output_limit_exceeded and not bounded.containment_failed,
            "bounded_process_not_completed",
        )
        validate_result(output)
        result["status"] = "completed_diagnostic"
        failed = False
    finally:
        postflight_failed = False
        try:
            after = identity.bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
            write_json(output / "source-after.json", after)
            current = identity.installation_identity(args.source_root, args.original_artifacts)
            write_json(output / "installation-after.json", current)
            result["parent_imports_after"] = identity.import_identity(args.source_root, args.harness_root)
            require(before == after, "source_or_harness_changed")
            require(installation == current, "installed_files_changed")
            result["source_and_installation_unchanged"] = True
        except Exception:
            postflight_failed = True
            result["postflight_failed"] = True
        if failed or postflight_failed:
            result["status"] = "failed"
        write_json(output / "result.json", result)
        emit_terminal_evidence(output)
        if not failed and postflight_failed:
            raise RuntimeError("checkpoint_parent_postflight_failed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--harness-sha", required=True)
    parser.add_argument("--original-artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--uv", type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.harness_sha) is not None, "harness_sha_invalid")
    for name in ("source_root", "harness_root", "original_artifacts"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output = args.output.resolve()
    require(
        not args.output.is_relative_to(args.source_root)
        and not args.output.is_relative_to(args.harness_root)
        and args.output != args.original_artifacts,
        "diagnostic_output_scope",
    )
    identity.configure_imports(args.source_root, args.harness_root)
    if args.install:
        require(not args.child and args.uv is not None, "installer_arguments")
        bound = identity.bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
        write_json(args.original_artifacts / "installer-source-before.json", bound)
        result = identity.install_original_wheel(args.source_root, args.original_artifacts, args.uv)
        after = identity.bind_checkouts(args.source_root, args.harness_root, args.harness_sha)
        write_json(args.original_artifacts / "installer-source-after.json", after)
        require(bound == after, "installer_source_changed")
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.child:
        return child(args)
    return parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
