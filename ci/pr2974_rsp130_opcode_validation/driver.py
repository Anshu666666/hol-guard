"""Run fresh trace calibrations and six opcode cells; preserve original45 without replay."""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json
from environment_setup import prepare_environment, finish_environment
from prior_admission import admit_previous, bind_previous_dependencies


def main() -> int:
    run = Run("rsp130-trace-calibration-and-six-operation-cells-only")
    errors, results = [], {}
    env, primary = None, None
    try:
        run.before = source_witness("before")
        results["prior_functional"] = admit_previous(run)
        for relative in CONFIG["candidate_files"]:
            destination = REPORT / "source-payload/current" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((SOURCE / relative).read_bytes())
        (REPORT / "retained-original-terminal.json").write_bytes((HERE / "original-terminal.json").read_bytes())
        (REPORT / "retained-opcode-source-proof.json").write_bytes((HERE / "opcode-source-proof.json").read_bytes())
        run.require(run.command("source-admission-before-environment", [
            sys.executable, "-I", "-B", str(HERE / "source_contract.py"), str(REPORT / "source-contract.json"),
        ], cwd=SCRATCH, env=None, timeout=60), "Source admission failed before project import")
        assert json.loads((REPORT / "source-contract.json").read_bytes())["passed"] is True
        for name, key in (("operation_probe.py", "corrected_probe"),
                          ("original_operation_probe.py", "original_probe"),
                          ("opcode_calibration.py", "calibration")):
            raw = (HERE / name).read_bytes()
            assert len(raw) == CONFIG[key]["bytes"] and sha256(raw) == CONFIG[key]["sha256"], name
        env, primary, _create = prepare_environment(run)
        results["prior_fixture_currentness"] = bind_previous_dependencies(run)
        results["calibrations"] = []
        for case in ("unprimed-negative", "first-load", "nested-comparison", "exception-cleanup"):
            output = REPORT / ("calibration-" + case + ".json")
            probe = "original_operation_probe.py" if case == "unprimed-negative" else "operation_probe.py"
            passed = run.command("calibration-" + case, [
                str(primary), "-I", "-B", str(HERE / "opcode_calibration.py"),
                "--case", case, "--probe", str(HERE / probe), "--output", str(output),
            ], env=env, timeout=60)
            try:
                result = json.loads(output.read_bytes())
                results["calibrations"].append(result)
                assert passed and result["passed"] and result["sources_unchanged"]
                assert result["case"] == case and result["product_callbacks_executed"] == 0
                assert result["discarded_product_warmup_calls"] == 0
                assert result["trace_after_is_none"] and result["profile_after_is_none"]
                assert result["python"]["executable"]["sha256"] == sha256(primary.read_bytes())
            except BaseException as error:
                errors.append("calibration-" + case + ": " + repr(error))
        if not errors:
            output = REPORT / "operation-counts.json"
            passed = run.command("six-separate-operation-cells", [
                str(primary), "-I", "-B", str(HERE / "operation_probe.py"),
                "--baseline-file", str(BASELINE / "src/codex_plugin_scanner/guard/aibom_cli.py"),
                "--candidate-root", str(SOURCE), "--output", str(output),
                "--manifest", str(HERE / "probe-manifest.json"),
            ], env=env, timeout=120)
            result = json.loads(output.read_bytes())
            results["operation_cells"] = result
            assert passed and result["passed"] and result["sources_unchanged"] and len(result["cells"]) == 6
            for row, expected in zip(result["cells"], CONFIG["operation_cells"], strict=True):
                assert [row["snapshots"], row["sources"]] == expected
                count, supplied = expected
                assert row["original"] == {
                    "snapshot_id_load_attr": 2 * count * supplied + count,
                    "explicit_equal_comparisons": count * supplied,
                }
                assert row["candidate"] == {
                    "snapshot_id_load_attr": count + supplied, "explicit_equal_comparisons": 0,
                }
                assert row["exact_key_and_source_object_order_equal"] is True
            for origin in result["product_origins"].values():
                relative = Path(origin["path"]).relative_to(SOURCE).as_posix()
                pin = run.before["files"][relative]
                assert origin["bytes"] == pin["bytes"] and origin["sha256"] == pin["sha256"]
    except BaseException as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append("Environment finalizer: " + repr(error))
        write_json(REPORT / "operations-results.json", {
            "results": results, "errors": errors,
            "historical_functional_cases": 45, "historical_functional_overall_run": "failure",
            "fresh_calibration_cases": 4, "expected_fresh_operation_cells": 6,
            "fresh_functional_test_bodies": 0, "discarded_product_warmup_calls": 0,
            "timing_measurement": False, "optimization_selected": False,
            "qualification_complete": False,
        })
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
