"""Execute one frozen same-host pair and retain every failed or unrun phase."""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

from admission import host_witness, source_witness, start
from archives import (
    retain_command_streams, retain_completed_build_outputs, retain_sources,
    save_archive, temporary_state_witness,
)
from build_variants import assemble_install, build, environment_snapshot, pure_wheel
from common import (
    ARTIFACTS, COMMANDS, CONFIG, REPORT, ROOT, command, content_identity, deadline,
    file_identity, helper_argv, helper_environment, require, successful, write_json,
)
from macho import compare_macho
from probes import run_probes
from setup import prepare, registry_witness
from stop_capture import active_collectors

PHASES = (
    "build", "inventory-and-signature", "selftest-and-capabilities", "native-wheel-install",
    "identity-probe", "default-auto-probe", "pi-probe", "original-smoke",
)


def close_phase_records(variant: str, reason: str) -> None:
    for phase in PHASES:
        path = REPORT / variant / (phase + "-outcome.json")
        if path.exists():
            current = json.loads(path.read_bytes())
            if current["state"] == "started":
                write_json(path, {"variant": variant, "phase": phase, "state": "failed",
                                  "original_started_record": current, "reason": reason,
                                  "qualification_complete": False})
        else:
            write_json(path, {"variant": variant, "phase": phase, "state": "unrun",
                              "prerequisite": reason, "qualification_complete": False})


def postwitness(context: dict, label: str) -> dict:
    require(not (ROOT / "unsafe-continuation.json").exists(), "Cleanup prevents further witness commands")
    result = {"passed": False}
    path = REPORT / (label + "-postwitness.json")
    write_json(path, result)
    try:
        source = source_witness(label, context)
        require(source == context["source_before"], "Frozen source changed")
        registry = registry_witness(label)
        require(registry == context["registry_before"], "Admitted Rust dependency bytes changed")
        host = host_witness(label, context)
        require(host == context["host_before_variants"], "Same-host tool/SDK identity changed")
        require(file_identity(context["pure_wheel"]) == context["pure_original"], "One pure wheel changed")
        result.update(passed=True, source_tree=source["tree"], registry_files=len(registry),
                      same_host_boot_tools_sdk=True, pure_wheel=context["pure_original"])
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        write_json(path, result)
    return result


def one_variant(context: dict, variant: str, strip: str) -> dict:
    result = {"variant": variant, "strip": strip, "attempts": 1, "state": "started",
              "all_original_gates_passed": False, "qualification_complete": False}
    installed = None
    try:
        binary, observation, capabilities = build(context, variant, strip)
        result.update(build_original=observation["original_identity"], build_inventory=observation,
                      capabilities=capabilities)
        installed = assemble_install(context, variant, binary, observation, capabilities)
        result.update(installed_runtime=str(installed["runtime"]), node=installed["node"])
        probes = run_probes(context, variant, installed)
        result["probes"] = probes
        result["all_original_gates_passed"] = (
            probes["all_original_correctness_passed"] and probes["environment_restored"]
            and probes["original_smoke"].get("passed") is True
        )
        result["state"] = "completed"
    except BaseException:
        result["state"] = "failed"
        result["error"] = traceback.format_exc()
    finally:
        close_phase_records(variant, result.get("error", "Earlier admission/correctness prerequisite failed"))
        if not (ROOT / "unsafe-continuation.json").exists():
            result["postwitness"] = postwitness(context, variant + "-after")
            result["all_original_gates_passed"] &= result["postwitness"]["passed"]
        else:
            result["postwitness"] = {"passed": False, "state": "unrun", "reason": "Unproven owned cleanup"}
            result["all_original_gates_passed"] = False
        result["safe_to_continue"] = not (ROOT / "unsafe-continuation.json").exists()
        write_json(REPORT / variant / "variant-outcome.json", result)
    if installed is not None:
        context.setdefault("completed_installs", {})[variant] = installed
    return result


def pair_comparison(results: dict) -> dict:
    output = {"complete_pair_observed": False, "production_candidate_eligible": False,
              "qualification_complete": False, "release_equivalence": False,
              "cross_platform_equivalence": False, "threshold_relaxation": False,
              "cache_added": False, "runtime_security_validation_unchanged": True}
    if all("build_inventory" in results.get(name, {}) for name in ("baseline", "candidate")):
        first, second = (results[name]["build_inventory"] for name in ("baseline", "candidate"))
        output["macho"] = compare_macho(first["inventory"], second["inventory"])
        output["signature_states"] = {name: results[name]["build_inventory"]["signature_state"]
                                      for name in ("baseline", "candidate")}
        output["signature_transition"] = (
            output["signature_states"]["baseline"] + " -> " + output["signature_states"]["candidate"])
        output["signature_preservation_requires_review"] = len(set(output["signature_states"].values())) != 1
        output["entry_mappings"] = {name: results[name]["build_inventory"]["inventory"]["entry_mapping"]
                                   for name in ("baseline", "candidate")}
        output["exclusive_range_bytes"] = {
            name: results[name]["build_inventory"]["inventory"]["exclusive_span_byte_totals"]
            for name in ("baseline", "candidate")}
        output["complete_pair_observed"] = all(results[name]["state"] == "completed"
                                              for name in ("baseline", "candidate"))
    if all("capabilities" in results.get(name, {}) for name in ("baseline", "candidate")):
        originals = {name: results[name]["capabilities"] for name in ("baseline", "candidate")}
        keys = ("protocol_version", "runtime_version", "build_sha", "target", "rule_digest")
        output["capability_originals"] = originals
        output["same_capability_identity"] = all(
            originals["baseline"].get(key) == originals["candidate"].get(key) for key in keys)
        output["all_capability_fields_equal"] = originals["baseline"] == originals["candidate"]
        output["compared_capability_identity_fields"] = list(keys)
    for name in ("baseline", "candidate"):
        output[name + "_original_smoke"] = results.get(name, {}).get("probes", {}).get(
            "original_smoke", {"state": "unrun", "reason": "Earlier variant prerequisite failed"})
    if all("node" in results.get(name, {}) for name in ("baseline", "candidate")):
        first, second = (results[name]["node"] for name in ("baseline", "candidate"))
        output["same_locked_node_bytes"] = content_identity(first) == content_identity(second)
    output["review_required"] = [
        "Every changed loader/load-command byte and signature transition",
        "All original smoke failures, command cleanup and evidence completeness",
        "This single observed pair supplies no production selection or statistical qualification",
    ]
    write_json(REPORT / "pair-comparison.json", output)
    return output


def run_pair() -> int:
    context = None
    results = {}
    terminal = {"source_sha": CONFIG["source_sha"], "started_monotonic_ns": time.monotonic_ns(),
                "variants": results, "passed": False, "comparison_completed": False,
                "qualification_complete": False, "production_candidate_eligible": False,
                "original_smoke_attempt_limit_per_variant": 1, "failures": []}
    try:
        with deadline(CONFIG["bounds"]["environment_setup_seconds"]):
            context = start()
            write_json(REPORT / "terminal.json", terminal)
            # Finite parser controls execute before either real artifact is built.
            parser = command("finite-parser-controls", helper_argv("parser_controls"),
                             environment=helper_environment(context["environment"]), timeout=60)
            require(successful(parser), "Finite parser controls failed")
            retain_sources(context)
            prepare(context)
        pure_wheel(context)
        for variant, strip in (("baseline", "none"), ("candidate", "symbols")):
            if (ROOT / "unsafe-continuation.json").exists():
                results[variant] = {"state": "unrun", "attempts": 0,
                                    "reason": "Previous owned processes were not proved retired"}
                close_phase_records(variant, results[variant]["reason"])
                continue
            results[variant] = one_variant(context, variant, strip)
            write_json(REPORT / "terminal.json", terminal)
            if not results[variant].get("postwitness", {}).get("passed"):
                terminal["failures"].append(variant + " immutable postwitness failed")
                break
        # Check the baseline again after the candidate; allowed probe inode replacement
        # never excuses changed installed file bytes, modes, RECORD or providers.
        if not (ROOT / "unsafe-continuation.json").exists():
            for variant, installed in context.get("completed_installs", {}).items():
                environment_snapshot(context, variant, "final", installed["environment"],
                                     prior=installed["before_environment"])
            backend = command("backend-environment-after", helper_argv(
                "environment", "--prefix", context["backend"], "--kind", "backend",
                "--output", REPORT / "backend-environment-after.json",
                "--prior", REPORT / "backend-environment-before.json", python=context["backend_python"]),
                environment=helper_environment(context["environment"]), timeout=120)
            require(successful(backend), "Backend closure changed")
        comparison = pair_comparison(results)
        terminal["comparison_completed"] = comparison["complete_pair_observed"]
        terminal["comparison"] = comparison
        terminal["passed"] = (
            all(results.get(name, {}).get("all_original_gates_passed") for name in ("baseline", "candidate"))
            and comparison.get("same_locked_node_bytes") is True
            and comparison.get("same_capability_identity") is True
            and comparison.get("all_capability_fields_equal") is True
            and comparison.get("macho", {}).get("actual_reduction_observed") is True
            and not terminal["failures"]
        )
    except BaseException:
        terminal["failures"].append(traceback.format_exc())
    finally:
        for variant in ("baseline", "candidate"):
            if variant not in results:
                results[variant] = {"state": "unrun", "attempts": 0,
                                    "reason": "Earlier immutable input/finite control prerequisite failed"}
                if REPORT.exists():
                    close_phase_records(variant, results[variant]["reason"])
        if REPORT.exists():
            # Fixed bounded retention remains available after any expired work deadline.
            try:
                terminal["original_commands"] = retain_command_streams()
                terminal["completed_outputs"] = retain_completed_build_outputs()
                if (ROOT / "backend-wheels").exists():
                    wheels = [(path.name, path, file_identity(path, honor_deadline=False))
                              for path in sorted((ROOT / "backend-wheels").iterdir())]
                    if wheels:
                        terminal["backend_wheels"] = save_archive(
                            ARTIFACTS / "complete-original-backend-wheels.tar.gz", wheels)
                terminal["temporary_state"] = temporary_state_witness()
            except BaseException:
                terminal["failures"].append("Final original retention failed: " + traceback.format_exc())
            terminal["passed"] = bool(terminal["passed"] and not terminal["failures"]
                                      and not (ROOT / "unsafe-continuation.json").exists())
            terminal["ended_monotonic_ns"] = time.monotonic_ns()
            terminal["command_count"] = len(COMMANDS)
            live_readers = active_collectors()
            if live_readers:
                terminal["passed"] = False
                terminal["unretired_owned_fifo_readers"] = live_readers
                terminal["forced_failed_harness_exit"] = True
            terminal["safe_to_continue"] = (
                not live_readers and not (ROOT / "unsafe-continuation.json").exists())
            write_json(REPORT / "terminal.json", terminal)
        else:
            print(json.dumps(terminal, ensure_ascii=True, sort_keys=True), flush=True)
    return 0 if terminal["passed"] else 1


def main() -> int:
    try:
        return run_pair()
    finally:
        live_readers = active_collectors()
        if live_readers:
            # This outer finalizer also covers failure of the large terminal write.
            # Terminate only the harness/owned reader after a bounded failure record.
            failure = {"passed": False, "safe_to_continue": False,
                       "forced_failed_harness_exit": True, "owned_readers": live_readers,
                       "terminal": str(REPORT / "terminal.json"),
                       "terminal_fsync_success_not_assumed": True,
                       "pending_exception": traceback.format_exc() if sys.exc_info()[0] else None}
            try:
                write_json(REPORT / "failed-owned-reader-shutdown.json", failure)
            except BaseException:
                failure["minimal_retention_error"] = traceback.format_exc()
            try:
                print(json.dumps(failure, ensure_ascii=True, sort_keys=True), flush=True)
                sys.stdout.flush()
                sys.stderr.flush()
            finally:
                os._exit(1)


if __name__ == "__main__":
    raise SystemExit(main())
