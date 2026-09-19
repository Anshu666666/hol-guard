"""Run each unchanged installed correctness probe and at most one original smoke."""

from __future__ import annotations

import json
from pathlib import Path
import traceback

from build_variants import environment_snapshot
from common import CONFIG, REPORT, ROOT, SOURCE, command, file_identity, phase_record, require, successful, write_json
from stop_capture import StopCapture


def observed_report(path: Path) -> dict:
    if not path.is_file():
        return {"present": False, "reason": "The original program did not write its report"}
    raw = path.read_bytes()
    result = {"present": True, "identity": file_identity(path)}
    try:
        result["original"] = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        result["parse_error"] = traceback.format_exc()
    return result


def run_probes(context: dict, variant: str, installed: dict) -> dict:
    python = installed["prefix"] / "bin/python"
    environment = installed["environment"]
    before = installed["before_environment"]
    rows = []
    restored = True
    correctness = True
    probes = [
        ("identity", "identity-probe", "ci/native_runtime/probe_installed_runtime_identity.py",
         "installed-runtime-identity.json", ["-I", "-B"], CONFIG["bounds"]["identity_probe_seconds"]),
        ("default-auto", "default-auto-probe", "ci/native_runtime/probe_native_default_auto.py",
         "native-default-auto.json", ["-B"], CONFIG["bounds"]["default_auto_probe_seconds"]),
        ("pi", "pi-probe", "ci/native_runtime/probe_installed_pi_output.py",
         "installed-pi-output.json", ["-B"], CONFIG["bounds"]["pi_probe_seconds"]),
    ]
    for name, phase, program, output_name, flags, bound in probes:
        destination = REPORT / variant / output_name
        if not restored or (ROOT / "unsafe-continuation.json").exists():
            phase_record(variant, phase, "unrun", prerequisite="Earlier environment restoration/cleanup failed")
            correctness = False
            continue
        phase_record(variant, phase, "started", attempts=1)
        row = command(variant + "-probe-" + name,
                      [str(python), *flags, str(SOURCE / program), "--json", str(destination)],
                      environment=environment, timeout=bound)
        original = observed_report(destination)
        passed = successful(row) and original["present"] and "parse_error" not in original
        if passed and name == "default-auto":
            payload = original["original"]
            passed = (
                payload.get("corpus_decisions") == 21
                and payload.get("resident_decisions") == 21
                and payload.get("oneshot_decisions") == 0
                and len(payload.get("route_receipts", [])) == 21
            )
        correctness = correctness and passed
        rows.append({"probe": name, "passed": passed, "command": row, "report": original})
        phase_record(variant, phase, "passed" if passed else "failed", command=row, report=original)
        try:
            environment_snapshot(context, variant, "after-" + name, environment, prior=before)
        except BaseException:
            restored = False
            phase_record(variant, "environment-after-" + name, "failed", error=traceback.format_exc())
    smoke = {"state": "unrun", "prerequisite": "Every original correctness probe and full restoration must pass"}
    if correctness and restored and not (ROOT / "unsafe-continuation.json").exists():
        capture = StopCapture(variant)
        command_row = None
        command_attempted = False
        phase_record(variant, "original-smoke", "started", maximum_original_attempts=1)
        try:
            sink = capture.start()
            smoke_environment = environment | {
                "MACOSX_DEPLOYMENT_TARGET": "13.0", "PLATFORM_TAG": CONFIG["installed_platform_tag"],
                "NATIVE_STOP_DIAGNOSTIC_PATH": str(sink),
            }
            destination = REPORT / variant / "native-installed-slo.json"
            command_attempted = True
            command_row = command(variant + "-original-smoke", [
                str(python), "-B", str(SOURCE / "scripts/bench_guard_native_installed_slo.py"),
                "--runtime", str(installed["runtime"]), "--warm-iterations", "2",
                "--cold-iterations", "2", "--recovery-iterations", "2", "--readiness-samples", "2",
                "--launcher-iterations", "2", "--json", str(destination), "--enforce",
            ], environment=smoke_environment, timeout=CONFIG["bounds"]["original_smoke_seconds"])
            original = observed_report(destination)
            smoke = {"state": "completed", "command": command_row, "report": original,
                     "passed": successful(command_row) and original.get("original", {}).get("passed") is True,
                     "attempts": 1, "schedule_unchanged": True}
        except BaseException:
            smoke = {"state": "failed", "error": traceback.format_exc(), "command": command_row,
                     "passed": False, "attempts": int(command_attempted)}
        finally:
            capture_result = capture.finish(producers_retired=(
                command_row is not None and command_row["cleanup"]["safe_to_continue"]))
            smoke["stop_diagnostics"] = capture_result
            if not capture_result["native_stop_succeeded"]:
                smoke["passed"] = False
                smoke["retention_complete"] = capture_result["complete"]
            else:
                smoke["retention_complete"] = True
        phase_record(variant, "original-smoke", smoke["state"], outcome=smoke)
        if not (ROOT / "unsafe-continuation.json").exists():
            try:
                environment_snapshot(context, variant, "after-smoke", environment, prior=before)
            except BaseException:
                restored = False
                phase_record(variant, "environment-after-smoke", "failed", error=traceback.format_exc())
    else:
        phase_record(variant, "original-smoke", "unrun", prerequisite=smoke["prerequisite"])
    result = {"correctness": rows, "all_original_correctness_passed": correctness,
              "environment_restored": restored, "original_smoke": smoke,
              "qualification_complete": False}
    write_json(REPORT / variant / "probe-outcomes.json", result)
    return result
