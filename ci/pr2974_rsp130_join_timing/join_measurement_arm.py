"""One isolated uninstrumented join arm; exploratory evidence, never selection."""

from __future__ import annotations

import argparse
import gc
import json
import os
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measurement_support import admitted, hashed, load_join, origins, runtime_settings


def fresh_key(ordinal: int) -> str:
    value = ("rsp130-public-key:" + ("x" * 31) + ":" + str(ordinal)).encode("ascii").decode("ascii")
    assert type(value) is str and len(value) > 32
    return value


def population(cell: dict, mode: str, snapshot_type, source_type):
    count, supplied = cell["S"], cell["P"]
    shape = cell["shape"]
    distinct = max(1, count // 2) if shape == "duplicate_snapshot_ids" else count
    key_ids = [index % distinct for index in range(count)]
    keys = [fresh_key(index) for index in range(distinct)]
    snapshots = tuple(snapshot_type(
        snapshot_id=keys[key_ids[index]], agent_id="codex:local", agent_type="codex",
        generated_at="2026-09-19T00:00:00Z") for index in range(count))
    repeat = shape == "repeated_source_references"
    source_total = max(1, supplied // 4) if repeat and supplied else supplied
    keys_unmatched = count == 0 or shape == "unmatched_source_keys"
    source_key_ids = [(distinct + 10000 + index) if keys_unmatched else index % distinct
                      for index in range(source_total)]
    objects = []
    for index, ordinal in enumerate(source_key_ids):
        key = (keys[ordinal] if mode == "cold_alias" and not keys_unmatched else fresh_key(ordinal))
        if not keys_unmatched and mode != "cold_alias":
            assert key is not keys[ordinal] and key == keys[ordinal]
        objects.append(source_type(
            agent_id="codex:local", allowed_root=Path("/tmp/rsp130-public-fixture"),
            content_hash="sha256:" + "0" * 64, harness_id="codex", item_id=f"item-{index}",
            item_kind="skill", mime_type="text/markdown",
            path=Path("/tmp/rsp130-public-fixture") / f"item-{index}.md",
            snapshot_id=key, version_id=f"version-{index}"))
    indices = [index % source_total for index in range(supplied)] if repeat else list(range(supplied))
    sources = [objects[index] for index in indices]
    source_ordinals = [source_key_ids[index] for index in indices]
    # No string-keyed dictionary/set/hash operation has touched the cold key population.
    return snapshots, sources, key_ids, source_ordinals


def verify_output(result, snapshots, sources, snapshot_ordinals, source_ordinals):
    assert type(result) is dict
    ordered = []
    for ordinal in snapshot_ordinals:
        if ordinal not in ordered:
            ordered.append(ordinal)
    by_ordinal = {}
    for source, ordinal in zip(sources, source_ordinals, strict=True):
        by_ordinal.setdefault(ordinal, []).append(source)
    actual_keys = list(result)
    assert len(actual_keys) == len(ordered)
    for key, ordinal in zip(actual_keys, ordered, strict=True):
        original_index = snapshot_ordinals.index(ordinal)
        assert key == snapshots[original_index].snapshot_id and key is snapshots[original_index].snapshot_id
        expected = by_ordinal.get(ordinal, [])
        actual = result[key]
        assert type(actual) is tuple and len(actual) == len(expected)
        assert all(left is right for left, right in zip(actual, expected, strict=True))
    return {"result_keys": len(ordered),
            "returned_source_occurrences": sum(len(value) for value in result.values()),
            "snapshot_visit_match_occurrences": sum(len(by_ordinal.get(ordinal, []))
                                                    for ordinal in snapshot_ordinals)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--pair", type=int, required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--finite-admission", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    report = {"schema": "pr2974-rsp130-join-micro-arm.v1", "arm": args.arm, "pair": args.pair,
              "samples": [], "passed": False, "optimization_selected": False,
              "qualification_complete": False, "timing_scope": "isolated join wall/process CPU only"}
    watched = [Path(__file__).resolve(), Path(__file__).with_name("measurement_support.py").resolve(),
               args.manifest.resolve(), args.finite_admission.resolve()]
    baseline = args.baseline_root.resolve(strict=True)
    candidate = args.candidate_root.resolve(strict=True)
    root = baseline if args.arm == "baseline" else candidate
    before = {}
    try:
        assert sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 12, 13)
        assert 1 <= args.pair <= 5 and not output.is_relative_to(baseline) and not output.is_relative_to(candidate)
        assert sys.gettrace() is None and sys.getprofile() is None and not tracemalloc.is_tracing()
        manifest = json.loads(args.manifest.read_bytes())
        assert manifest["measurement_status"] == "final_evidence_bound", "Measurement draft is not executable"
        assert os.environ.get("PYTHONHASHSEED") == str(manifest["pair_hash_seeds"][args.pair - 1])
        report["hash_seed"] = os.environ["PYTHONHASHSEED"]
        report["runtime_settings"] = runtime_settings(manifest["pair_hash_seeds"][args.pair - 1])
        admitted(args.finite_admission, manifest)
        watched += [baseline / "src/codex_plugin_scanner/guard/aibom_cli.py",
                    candidate / "src/codex_plugin_scanner/guard/aibom_cli.py",
                    root / "src/codex_plugin_scanner/guard/aibom_content_upload.py"]
        before = {str(path): hashed(path) for path in watched}
        callback, _module, _upload, snapshot_type, source_type = load_join(
            root, watched[-3], watched[-2], args.arm, manifest)
        report["product_origins_before"] = origins(root)
        report["python"] = {"version": sys.version, "executable": str(Path(sys.executable).resolve()),
                            "executable_digest": hashed(Path(sys.executable).resolve())}
        report["literal_join_source_scope"] = {"baseline": hashed(watched[-3]), "candidate": hashed(watched[-2])}
        assert len(manifest["cells"]) == 18 and manifest["samples_per_cell"] == 20
        report["clock_info"] = {name: vars(time.get_clock_info(name)) for name in ("perf_counter", "process_time")}
        report["gc_enabled"] = gc.isenabled()
        report["cpu_affinity"] = sorted(os.sched_getaffinity(0))
        report["logical_cpus"] = os.cpu_count()
        wall, cpu = time.perf_counter_ns, time.process_time_ns
        for index, cell in enumerate(manifest["cells"]):
            assert type(cell["S"]) is int and 0 <= cell["S"] <= 486
            assert type(cell["P"]) is int and 0 <= cell["P"] <= 4096
            for mode in ("cold_alias", "cold_independent", "warm_independent"):
                shared = population(cell, mode, snapshot_type, source_type) if mode == "warm_independent" else None
                if shared is not None:
                    prime = callback(shared[0], shared[1])
                    verify_output(prime, *shared)
                    del prime
                for sample in range(20):
                    values = shared if shared is not None else population(cell, mode, snapshot_type, source_type)
                    snapshots, sources = values[:2]
                    assert sys.gettrace() is None and sys.getprofile() is None and not tracemalloc.is_tracing()
                    started_wall = wall()
                    started_cpu = cpu()
                    result = callback(snapshots, sources)
                    ended_cpu = cpu()
                    ended_wall = wall()
                    wall_ns, cpu_ns = ended_wall - started_wall, ended_cpu - started_cpu
                    row = {"cell_index": index, "mode": mode, "sample": sample,
                           "wall_ns": wall_ns, "process_cpu_ns": cpu_ns}
                    report["samples"].append(row)
                    assert wall_ns >= 0 and cpu_ns >= 0
                    row["result_identity"] = verify_output(result, *values)
                    row["result_verified_after_stop"] = True
                    del result
                    if shared is None:
                        del values, snapshots, sources
                if shared is not None:
                    del shared, values, snapshots, sources
        assert len(report["samples"]) == 18 * 3 * 20
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["trace_after_is_none"] = sys.gettrace() is None
        report["profile_after_is_none"] = sys.getprofile() is None
        report["allocation_trace_after_is_none"] = not tracemalloc.is_tracing()
        report["before"] = before
        try:
            report["after"] = {str(path): hashed(path) for path in watched}
            report["sources_unchanged"] = bool(before) and before == report["after"]
            report["product_origins_after"] = origins(root)
            report["product_origins_unchanged"] = report.get("product_origins_before") == report["product_origins_after"]
        except BaseException as error:
            report["final_observation_error"] = {"type": type(error).__name__, "message": str(error)}
            report["sources_unchanged"] = False
        report["passed"] = bool(report["passed"] and report.get("sources_unchanged")
                                and report.get("product_origins_unchanged")
                                and report["trace_after_is_none"] and report["profile_after_is_none"]
                                and report["allocation_trace_after_is_none"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
