"""Run five independent join pairs only after exact functional and operation admission."""

from __future__ import annotations

import ast
import json
import math
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, source_witness, write_json
from environment_setup import prepare_environment, finish_environment
from measurement_support import admitted, hashed


def current_inputs(run: Run) -> None:
    for side, root, pins in (
        ("candidate", SOURCE, CONFIG["candidate_files"]),
        ("baseline", BASELINE, CONFIG["baseline_input_files"]),
    ):
        for relative, pin in pins.items():
            assert hashed(root / relative) == {"bytes": pin["bytes"], "sha256": pin["sha256"]}, (side, relative)


def bind_origins(run: Run, report: dict, arm: str) -> None:
    assert report["product_origins_before"] == report["product_origins_after"]
    key = "baseline_files" if arm == "baseline" else "files"
    for origin in report["product_origins_after"].values():
        relative = "src/" + origin["path"]
        pin = run.before[key][relative]
        assert {"sha256": origin["sha256"], "bytes": origin["bytes"]} == {
            "sha256": pin["sha256"], "bytes": pin["bytes"]}, relative


def arm_summary(report: dict) -> list[dict]:
    expected = [(cell, mode, sample) for cell in range(18)
                for mode in ("cold_alias", "cold_independent", "warm_independent") for sample in range(20)]
    rows = report["samples"]
    assert [(row["cell_index"], row["mode"], row["sample"]) for row in rows] == expected
    assert all(row["result_verified_after_stop"] for row in rows)
    result = []
    for cell in range(18):
        for mode in ("cold_alias", "cold_independent", "warm_independent"):
            selected = [row for row in rows if row["cell_index"] == cell and row["mode"] == mode]
            assert len(selected) == 20
            metrics = {}
            for name in ("wall_ns", "process_cpu_ns"):
                values = [row[name] for row in selected]
                assert all(type(value) is int and value >= 0 for value in values)
                metrics[name] = {"median": statistics.median(values),
                                 "p95_nearest_rank": sorted(values)[math.ceil(0.95 * len(values)) - 1],
                                 "minimum": min(values), "maximum": max(values)}
            result.append({"cell_index": cell, "mode": mode, "samples": 20, "metrics": metrics})
    return result


def paired_summaries(arms: dict) -> list[dict]:
    pairs = []
    for pair in range(1, 6):
        baseline = arms.get((pair, "baseline"))
        candidate = arms.get((pair, "candidate"))
        if baseline is None or candidate is None:
            pairs.append({"pair": pair, "complete": False})
            continue
        rows = []
        for left, right in zip(baseline, candidate, strict=True):
            assert (left["cell_index"], left["mode"]) == (right["cell_index"], right["mode"])
            ratios = {}
            for metric in ("wall_ns", "process_cpu_ns"):
                ratios[metric] = {}
                for estimator in ("median", "p95_nearest_rank"):
                    denominator = left["metrics"][metric][estimator]
                    numerator = right["metrics"][metric][estimator]
                    ratios[metric][estimator] = numerator / denominator if denominator else None
            rows.append({"cell_index": left["cell_index"], "mode": left["mode"],
                         "baseline": left["metrics"], "candidate": right["metrics"],
                         "candidate_over_baseline": ratios})
        pairs.append({"pair": pair, "complete": True, "rows": rows})
    return pairs


def main() -> int:
    run = Run("rsp130-five-pair-join-diagnosis-not-selection")
    errors, outputs, summaries, diagnostics, runtime_pairs = [], [], {}, [], {}
    env, primary = None, None
    try:
        run.before = source_witness("before")
        syntax = []
        for path in sorted(HERE.glob("*.py")):
            raw = path.read_bytes()
            parsed = ast.parse(raw, filename=str(path), type_comments=True)
            compile(parsed, str(path), "exec", dont_inherit=True)
            syntax.append({"name": path.name, **hashed(path)})
        write_json(REPORT / "harness-syntax.json", {"passed": True, "files": syntax,
                   "python": sys.version, "project_imports": []})
        admission = HERE / "operation-admission.json"
        evidence = admitted(admission, CONFIG)
        write_json(REPORT / "admitted-evidence.json", {
            "functional": CONFIG["functional_admission"], "operations": CONFIG["operation_admission"],
            "historical_functional_cases": 45, "historical_functional_overall_run": "failure",
            "actual_operation_cells": 6, "operations_overall_passed": True,
            "original_failure_preserved": evidence["functional"]["original_outcome"]["passed"] is False,
        })
        for name in ("original-functional-terminal.json", "operation-admission.json",
                     "measurement-proposal.json", "interpreter-source.json"):
            (REPORT / name).write_bytes((HERE / name).read_bytes())
        run.require(run.command("source-admission-before-environment", [
            sys.executable, "-I", "-B", str(HERE / "source_contract.py"), str(REPORT / "source-contract.json"),
        ], cwd=SCRATCH, env=None, timeout=60), "Source admission failed")
        assert json.loads((REPORT / "source-contract.json").read_bytes())["passed"] is True
        env, primary, _create = prepare_environment(run)
        assert CONFIG["pair_order"] == [["baseline", "candidate"], ["candidate", "baseline"],
                                       ["baseline", "candidate"], ["candidate", "baseline"],
                                       ["baseline", "candidate"]]
        assert len(CONFIG["pair_hash_seeds"]) == 5 and len(set(CONFIG["pair_hash_seeds"])) == 5
        halted = False
        for pair, order in enumerate(CONFIG["pair_order"], 1):
            for arm in order:
                current_inputs(run)
                name = f"pair-{pair:02d}-{arm}"
                output = REPORT / (name + ".json")
                arm_env = {key: value for key, value in env.items() if not key.startswith("PYTHON")}
                arm_env["PYTHONHASHSEED"] = str(CONFIG["pair_hash_seeds"][pair - 1])
                passed = run.command(name, [
                    str(primary), "-P", "-s", "-B", str(HERE / "join_measurement_arm.py"),
                    "--arm", arm, "--pair", str(pair), "--baseline-root", str(BASELINE),
                    "--candidate-root", str(SOURCE), "--manifest", str(HERE / "manifest.json"),
                    "--finite-admission", str(admission), "--output", str(output),
                ], env=arm_env, timeout=CONFIG["arm_timeout_seconds"])
                try:
                    observed = json.loads(output.read_bytes())
                    outputs.append({"pair": pair, "arm": arm, "path": output.name, **hashed(output),
                                    "actual_passed": observed["passed"]})
                    assert passed and observed["passed"] and observed["sources_unchanged"]
                    assert observed["pair"] == pair and observed["arm"] == arm
                    assert observed["hash_seed"] == str(CONFIG["pair_hash_seeds"][pair - 1])
                    assert observed["python"]["executable_digest"] == hashed(primary)
                    bind_origins(run, observed, arm)
                    settings = observed["runtime_settings"]
                    assert settings["python_environment"] == {"PYTHONHASHSEED": str(CONFIG["pair_hash_seeds"][pair - 1])}
                    runtime_pairs[(pair, arm)] = settings
                    other = "candidate" if arm == "baseline" else "baseline"
                    if (pair, other) in runtime_pairs:
                        assert settings["hash_sentinels"] == runtime_pairs[(pair, other)]["hash_sentinels"]
                        assert settings["python_flags"] == runtime_pairs[(pair, other)]["python_flags"]
                    summaries[(pair, arm)] = arm_summary(observed)
                except BaseException as error:
                    errors.append(name + ": " + repr(error))
                current_inputs(run)
                if (SCRATCH / "unsafe-process-cleanup.json").exists():
                    errors.append("Stopped further arms after incomplete owned-group retirement")
                    halted = True
                    break
            if halted:
                break
        # This separate process campaign never instruments a timed child.
        if not halted:
            for arm in ("baseline", "candidate"):
                name = "container-diagnostic-" + arm
                output = REPORT / (name + ".json")
                diagnostic_env = {key: value for key, value in env.items() if not key.startswith("PYTHON")}
                diagnostic_env["PYTHONHASHSEED"] = str(CONFIG["diagnostic_hash_seed"])
                current_inputs(run)
                passed = run.command(name, [
                    str(primary), "-P", "-s", "-B", str(HERE / "join_group_diagnostic.py"),
                    "--arm", arm, "--baseline-root", str(BASELINE), "--candidate-root", str(SOURCE),
                    "--manifest", str(HERE / "manifest.json"), "--finite-admission", str(admission),
                    "--output", str(output),
                ], env=diagnostic_env, timeout=CONFIG["diagnostic_timeout_seconds"])
                try:
                    observed = json.loads(output.read_bytes())
                    diagnostics.append({"arm": arm, "path": output.name, **hashed(output),
                                        "actual_passed": observed["passed"]})
                    assert passed and observed["passed"] and observed["sources_unchanged"]
                    assert observed["arm"] == arm and observed["timing_samples"] == 0
                    assert [(row["cell_index"], row["mode"]) for row in observed["observations"]] == [
                        (cell, mode) for cell in range(18)
                        for mode in ("cold_alias", "cold_independent", "warm_independent")]
                    bind_origins(run, observed, arm)
                except BaseException as error:
                    errors.append(name + ": " + repr(error))
                current_inputs(run)
        assert len(summaries) == 10 and len(diagnostics) == 2
    except BaseException as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append("Environment finalizer: " + repr(error))
        try:
            pairs = paired_summaries(summaries)
        except BaseException as error:
            errors.append("Pair summary: " + repr(error))
            pairs = []
        write_json(REPORT / "measurement-results.json", {
            "schema": "pr2974-rsp130-five-pair-join-diagnosis.v1",
            "errors": errors, "arm_reports": outputs, "diagnostic_reports": diagnostics,
            "pairs": pairs,
            "expected_independent_pairs": 5, "expected_timed_arms": 10,
            "expected_samples_per_arm": 1080, "expected_total_timed_joins": 10800,
            "timing_scope": "Exact isolated join only; process CPU excludes scanner/cloud/process tree",
            "estimator": "Per independent arm median and nearest-rank p95 of 20 raw samples",
            "no_ratios_pooled_across_cells_or_pairs": True,
            "optimization_selected": False,
            "production_threshold_selected": None, "whole_workload_requirement_satisfied": False,
            "qualification_complete": False,
        })
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
