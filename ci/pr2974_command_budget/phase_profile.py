"""Separately traced phase attribution; never counted as original budget evidence."""

from __future__ import annotations

import cProfile
import hashlib
import importlib
import json
import os
from pathlib import Path
import pstats
import signal
import sys
import time

SOURCE = Path(os.environ["BUDGET_SOURCE"]).resolve()
OUTPUT = Path(os.environ["BUDGET_PROFILE"]).resolve()
PHASES: list[dict[str, object]] = []
OUTPUT.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def stop(signum: int, frame: object) -> None:
    del frame
    raise TimeoutError("Paired diagnostic process group terminated: signal " + str(signum))


def origins() -> list[dict[str, object]]:
    result = []
    for name, module in sorted(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if not isinstance(path, str):
            continue
        path = Path(path).resolve()
        if path.is_relative_to(SOURCE) and path.is_file():
            data = path.read_bytes()
            result.append({"module": name, "path": str(path.relative_to(SOURCE)),
                           "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    return result


def retain(profile: cProfile.Profile, label: str, extra: dict[str, object]) -> None:
    profile.disable()
    stats = pstats.Stats(profile).stats
    rows = [{"file": key[0], "line": key[1], "function": key[2],
             "primitive_calls": value[0], "total_calls": value[1],
             "self_seconds": value[2], "cumulative_seconds": value[3]}
            for key, value in stats.items()]
    rows.sort(key=lambda row: (-row["cumulative_seconds"], row["file"], row["line"], row["function"]))
    profile.dump_stats(str(OUTPUT / (label + ".pstats")))
    write_json(OUTPUT / (label + "-full.json"), rows)
    write_json(OUTPUT / (label + "-summary.json"), {
        **extra, "label": label, "pid": os.getpid(), "profiled": True,
        "tracing_overhead": "cProfile active; elapsed and RSS are not original budget evidence",
        "qualified": False, "functions": len(rows), "top_cumulative": rows[:60],
        "top_self": sorted(rows, key=lambda row: -row["self_seconds"])[:60],
        "actual_source_origins": origins(),
    })


def profile_worker(index: int):
    signal.signal(signal.SIGTERM, stop)
    profile = cProfile.Profile()
    start = time.perf_counter()
    extra = {"worker_index": index, "status": "started",
             "startup_trace_active": sys.gettrace() is not None,
             "startup_profile_active": sys.getprofile() is not None}
    profile.enable()
    try:
        imported = time.perf_counter()
        runner = importlib.import_module("tests.guard_command_decision_diff_runner")
        extra["worker_evaluator_import_seconds"] = time.perf_counter() - imported
        evaluated = time.perf_counter()
        result = runner._evaluate_shard(index)
        extra.update(status="completed", evaluation_seconds=time.perf_counter() - evaluated,
                     cases=result.total, rss_mib=result.rss_mib)
        return result
    except BaseException as error:
        extra.update(status="interrupted_or_failed", error_type=type(error).__name__)
        raise
    finally:
        extra["wall_seconds"] = time.perf_counter() - start
        retain(profile, "worker-" + str(index), extra)


def timed(label: str, function):
    def invoke(*args, **kwargs):
        start = time.perf_counter()
        row = {"phase": label, "status": "started"}
        PHASES.append(row)
        try:
            result = function(*args, **kwargs)
            row["status"] = "completed"
            return result
        except BaseException as error:
            row.update(status="interrupted_or_failed", error_type=type(error).__name__)
            raise
        finally:
            row["wall_seconds"] = time.perf_counter() - start
            write_json(OUTPUT / "phases.json", PHASES)
    return invoke


def main() -> int:
    signal.signal(signal.SIGTERM, stop)
    sys.path.insert(0, str(SOURCE))
    sys.path.insert(0, str(SOURCE / "src"))
    profile = cProfile.Profile()
    start = time.perf_counter()
    extra = {"status": "started", "source_sha": os.environ["BUDGET_SOURCE_SHA"],
             "startup_trace_active": sys.gettrace() is not None,
             "startup_profile_active": sys.getprofile() is not None,
             "hash_seed": os.environ.get("PYTHONHASHSEED"), "timezone": os.environ.get("TZ"),
             "locale": os.environ.get("LC_ALL"), "outer_timeout_seconds": 75,
             "worker_count": 4}
    code = 1
    profile.enable()
    try:
        imported = time.perf_counter()
        module = importlib.import_module("tests.guard_command_decision_diff")
        extra["parent_evaluator_import_seconds"] = time.perf_counter() - imported
        runner_globals = module.evaluate_decision_diff_shards.__globals__
        assert runner_globals["EVALUATION_SHARD_COUNT"] == runner_globals["MAX_CONCURRENT_WORKERS"] == 4
        runner_globals["_evaluate_shard"] = profile_worker
        for name in ("evaluate_decision_diff_shards", "corpus_digest", "_oracle_digest",
                     "_source_bindings", "_group_summaries", "_validate_manifest_digests"):
            setattr(module, name, timed(name, getattr(module, name)))
        generated = time.perf_counter()
        report, rss = module._generate_decision_diff_report()
        extra.update(status="completed", generation_seconds=time.perf_counter() - generated,
                     rss_mib=rss, report_framed_sha256=module.report_framed_sha256(report))
        fixture = json.loads(module.REPORT_PATH.read_text())
        assert extra["report_framed_sha256"] == module.report_framed_sha256(fixture)
        assert len(list(OUTPUT.glob("worker-*-summary.json"))) == 4
        code = 0
    except BaseException as error:
        extra.update(status="interrupted_or_failed", error_type=type(error).__name__, error=str(error)[:1000])
    finally:
        extra["wall_seconds"] = time.perf_counter() - start
        extra["phases"] = PHASES
        retain(profile, "parent", extra)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
