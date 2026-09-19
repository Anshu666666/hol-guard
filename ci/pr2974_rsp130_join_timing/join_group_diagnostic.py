"""Observe return-frame container counts separately from every timed process."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from join_measurement_arm import population, verify_output
from measurement_support import admitted, hashed, load_join, origins, runtime_settings


def containers(result: dict) -> dict:
    assert type(result) is dict and all(type(value) is tuple for value in result.values())
    unique_tuples = {id(value): value for value in result.values()}
    return {
        "result_keys": len(result),
        "returned_tuple_occurrences": sum(len(value) for value in result.values()),
        "unique_result_tuple_objects": len(unique_tuples),
        "result_dict_shallow_bytes": sys.getsizeof(result),
        "unique_result_tuples_shallow_bytes": sum(sys.getsizeof(value) for value in unique_tuples.values()),
    }


def observe(callback, target, snapshots, sources, arm: str) -> tuple[dict, dict]:
    assert sys.gettrace() is None and sys.getprofile() is None and not tracemalloc.is_tracing()
    rows = []
    calls = 0

    def traced(frame, event, argument):
        nonlocal calls
        if frame.f_code is not target:
            return None
        if event == "call":
            calls += 1
        elif event == "return":
            assert type(argument) is dict, "The expected stock-key path did not return its dictionary"
            row = containers(argument)
            if arm == "candidate":
                local = frame.f_locals
                snapshot_ids, source_ids = local["snapshot_ids"], local["source_ids"]
                grouped = local["grouped"]
                assert type(snapshot_ids) is list and type(source_ids) is list and type(grouped) is dict
                assert local["result"] is argument
                assert all(type(value) is list for value in grouped.values())
                row.update(
                    snapshot_id_entries=len(snapshot_ids), source_id_entries=len(source_ids),
                    grouped_keys=len(grouped), grouped_source_occurrences=sum(map(len, grouped.values())),
                    snapshot_id_list_shallow_bytes=sys.getsizeof(snapshot_ids),
                    source_id_list_shallow_bytes=sys.getsizeof(source_ids),
                    grouped_dict_shallow_bytes=sys.getsizeof(grouped),
                    grouped_lists_shallow_bytes=sum(sys.getsizeof(value) for value in grouped.values()),
                    candidate_temporary_groups_observed=True,
                )
            else:
                assert frame.f_locals["content_sources_by_snapshot"] is argument
                row["candidate_temporary_groups_observed"] = False
            rows.append(row)
        return traced

    try:
        sys.settrace(traced)
        result = callback(snapshots, sources)
    finally:
        sys.settrace(None)
    assert sys.gettrace() is None and sys.getprofile() is None
    assert calls == len(rows) == 1, (calls, len(rows))
    return result, {"target_calls": calls, "target_returns": len(rows), **rows[0]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--finite-admission", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "pr2974-rsp130-join-container-diagnostic.v1", "arm": args.arm,
              "passed": False, "observations": [], "timing_samples": 0,
              "scope": "Live-at-return shallow CPython containers only; no keys or record payloads",
              "peak_memory_bytes": None, "process_rss_bytes": None, "physical_bytes": None,
              "optimization_selected": False, "qualification_complete": False}
    baseline, candidate = args.baseline_root.resolve(strict=True), args.candidate_root.resolve(strict=True)
    root = baseline if args.arm == "baseline" else candidate
    before, watched = {}, []
    try:
        assert sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 12, 13)
        assert not args.output.resolve().is_relative_to(baseline) and not args.output.resolve().is_relative_to(candidate)
        assert sys.gettrace() is None and sys.getprofile() is None and not tracemalloc.is_tracing()
        manifest = json.loads(args.manifest.read_bytes())
        admitted(args.finite_admission, manifest)
        assert os.environ.get("PYTHONHASHSEED") == str(manifest["diagnostic_hash_seed"])
        report["runtime_settings"] = runtime_settings(manifest["diagnostic_hash_seed"])
        baseline_file = baseline / "src/codex_plugin_scanner/guard/aibom_cli.py"
        candidate_file = candidate / "src/codex_plugin_scanner/guard/aibom_cli.py"
        watched = [Path(__file__).resolve(), Path(__file__).with_name("measurement_support.py").resolve(),
                   Path(__file__).with_name("join_measurement_arm.py").resolve(),
                   args.manifest.resolve(), args.finite_admission.resolve(), baseline_file, candidate_file,
                   root / "src/codex_plugin_scanner/guard/aibom_content_upload.py"]
        before = {str(path): hashed(path) for path in watched}
        callback, _module, upload, snapshot_type, source_type = load_join(
            root, baseline_file, candidate_file, args.arm, manifest)
        target = callback.__code__ if args.arm == "baseline" else upload._indexed_primary_content_sources.__code__
        report["target"] = {"file": target.co_filename, "name": target.co_name,
                            "source": hashed(Path(target.co_filename))}
        report["product_origins_before"] = origins(root)
        for index, cell in enumerate(manifest["cells"]):
            for mode in ("cold_alias", "cold_independent", "warm_independent"):
                values = population(cell, mode, snapshot_type, source_type)
                if mode == "warm_independent":
                    prime = callback(values[0], values[1])
                    verify_output(prime, *values)
                    del prime
                result, observed = observe(callback, target, values[0], values[1], args.arm)
                identity = verify_output(result, *values)
                assert observed["result_keys"] == identity["result_keys"]
                assert observed["returned_tuple_occurrences"] == identity["returned_source_occurrences"]
                if args.arm == "candidate":
                    assert observed["snapshot_id_entries"] == cell["S"]
                    assert observed["source_id_entries"] == observed["grouped_source_occurrences"] == cell["P"]
                report["observations"].append({
                    "cell_index": index, "mode": mode, "actual": observed, "result_identity": identity})
                del result, values
        assert len(report["observations"]) == 54
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["before"] = before
        report["trace_after_is_none"] = sys.gettrace() is None
        report["profile_after_is_none"] = sys.getprofile() is None
        try:
            report["after"] = {str(path): hashed(path) for path in watched}
            report["sources_unchanged"] = bool(before) and before == report["after"]
            report["product_origins_after"] = origins(root)
            report["product_origins_unchanged"] = report.get("product_origins_before") == report["product_origins_after"]
        except BaseException as error:
            report["final_observation_error"] = {"type": type(error).__name__, "message": str(error)}
            report["sources_unchanged"] = False
        report["passed"] = bool(report["passed"] and report.get("sources_unchanged")
                                and report.get("product_origins_unchanged") and report["trace_after_is_none"]
                                and report["profile_after_is_none"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
