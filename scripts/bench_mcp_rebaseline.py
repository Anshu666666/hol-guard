#!/usr/bin/env python3
"""Five alternating independent MCP source runs with private bounded evidence."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.mcp_rebaseline_report import aggregate, raw_reference, write_private
from scripts.mcp_rebaseline_trace import CHILD, TRACES, trace_identity
from scripts.native_slo_resources import ResourceSampler

WORKER = Path(__file__).with_name("mcp_rebaseline_worker.py")
MAX_CAPTURE = 65536


def source_identity(path: Path) -> dict[str, object]:
    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

    if git("status", "--porcelain", "--", "src"):
        raise ValueError("production source must be frozen before sampling")
    return {
        "commit": git("rev-parse", "HEAD"),
        "production_tree": git("rev-parse", "HEAD:src"),
        "uv_lock_sha256": hashlib.sha256((path / "uv.lock").read_bytes()).hexdigest(),
    }


def _worker(source: Path, output: Path, *, calls: int, diagnostic: bool, resources: bool = False) -> dict[str, Any]:
    command = [sys.executable, str(WORKER), "--source", str(source), "--output", str(output), "--calls", str(calls)]
    if diagnostic:
        command.append("--diagnostic")
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("HOL_GUARD_", "GUARD_")) or key in {"PYTHONPATH", "PYTEST_CURRENT_TEST"}:
            env.pop(key)
    env["PYTHONHASHSEED"] = "0"
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    started = time.perf_counter_ns()
    process = subprocess.Popen(
        command,
        cwd=source,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None

    def drain(stream: Any, name: str) -> None:
        while chunk := stream.read(4096):
            totals[name] += len(chunk)
            captured[name].extend(chunk[: max(0, MAX_CAPTURE - len(captured[name]))])

    readers = [
        threading.Thread(target=drain, args=(stream, name), daemon=True)
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr"))
    ]
    for thread in readers:
        thread.start()
    sampler = None
    sampling = False
    failure = None
    try:
        if resources:
            sampler = ResourceSampler(interval_seconds=0.01, pid=process.pid)
            sampler.__enter__()
            sampling = True
        process.wait(timeout=180)
    except subprocess.TimeoutExpired:
        failure = "worker_deadline"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except Exception as error:
        failure = f"worker_observer_failure:{type(error).__name__}"
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    finally:
        if sampling and sampler is not None:
            try:
                sampler.__exit__(None, None, None)
            except Exception:
                failure = "resource_observer_cleanup_incomplete"
        for thread in readers:
            thread.join(timeout=2)
            if thread.is_alive():
                failure = "capture_cleanup_incomplete"
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                thread.join(timeout=2)
        for stream, thread in zip((process.stdout, process.stderr), readers, strict=True):
            # Buffered close can wait on a blocked reader's lock. A failed
            # cleanup stays failed; do not turn it into an unbounded close.
            if not thread.is_alive():
                stream.close()
    elapsed = time.perf_counter_ns() - started
    for name in captured:
        if totals[name] > MAX_CAPTURE:
            failure = "capture_byte_bound"
        write_private(
            output.with_suffix(f".{name}.json"),
            {
                "total_bytes": totals[name],
                "retained_bytes": len(captured[name]),
                "text": captured[name].decode("utf-8", errors="replace"),
            },
            limit=512 * 1024,
        )
    if not output.is_file() or output.stat().st_size > 16 * 1024 * 1024:
        payload = {"status": "failed", "failure_type": "missing_or_oversized_worker_evidence"}
    else:
        try:
            payload = json.loads(output.read_text())
            if not isinstance(payload, dict):
                raise ValueError("worker result must be an object")
        except (OSError, ValueError) as error:
            payload = {"status": "failed", "failure_type": f"worker_evidence_invalid:{type(error).__name__}"}
    result: dict[str, Any] = {
        "returncode": process.returncode,
        "capture_failure": failure,
        "worker_lifecycle_wall_ns": elapsed,
        "result": payload,
    }
    if sampling and sampler is not None:
        result["resources"] = sampler.report(attempted=calls * len(TRACES))
        result["resources"]["scope"] = "mcp_proxy_worker_and_descendants"
    return result


def run(
    baseline: Path,
    candidate: Path,
    output: Path,
    *,
    runs: int,
    calls: int,
    lock: Path,
    expected_candidate: str | None = None,
) -> dict[str, Any]:
    if not 1 <= runs <= 5 or not 2 <= calls <= 100:
        raise ValueError("runs/calls outside evidence bounds")
    sources = {"baseline": source_identity(baseline), "candidate": source_identity(candidate)}
    if sources["baseline"]["commit"] != "2e672d2d950c6ec471005ddba46e49bba16dc23b":
        raise ValueError("baseline is not frozen reviewed source")
    if expected_candidate is not None and sources["candidate"]["commit"] != expected_candidate:
        raise ValueError("candidate differs from pinned source revision")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    script_files = [
        Path(__file__),
        WORKER,
        *Path(__file__).parent.glob("mcp_rebaseline_*.py"),
        Path(__file__).with_name("native_slo_resources.py"),
    ]
    manifest: dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "platform": platform.platform(),
        "python": sys.version,
        "executable_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        "dependencies": sorted({f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()}),
        "harness": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in script_files},
        "child_sha256": hashlib.sha256(CHILD.encode()).hexdigest(),
        "traces": [trace_identity(t, calls) for t in TRACES],
        "order": [
            {"block": block, "role": role, "mode": mode}
            for block in range(runs)
            for role in (("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"))
            for mode in ("plain", "resources", "diagnostic")
        ],
        "note": "Both source revisions use this identical locked dependency environment.",
    }
    write_private(output / "manifest.json", manifest)
    records = []
    with lock.open("a+") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for block in range(runs):
            for role in ("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"):
                for mode in ("plain", "resources", "diagnostic"):
                    identity = {"block": block, "role": role, "mode": mode}
                    name = f"{block}-{role}-{mode}"
                    write_private(output / f"{name}.begin.json", identity)
                    observation: dict[str, Any]
                    exception_class = None
                    try:
                        observation = _worker(
                            baseline if role == "baseline" else candidate,
                            output / f"{name}.raw.json",
                            calls=calls,
                            diagnostic=mode == "diagnostic",
                            resources=mode == "resources",
                        )
                    except Exception as error:
                        name_of_exception = type(error).__name__
                        exception_class = (
                            name_of_exception
                            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name_of_exception)
                            else "NonStandardException"
                        )
                        observation = {
                            "returncode": None,
                            "capture_failure": "controller_worker_failure",
                            "result": {"status": "failed", "failure_type": type(error).__name__},
                        }
                    record = {**identity, **observation}
                    records.append(record)
                    private_observation = {k: v for k, v in record.items() if k != "result"}
                    if exception_class is not None:
                        private_observation["controller_exception_class"] = exception_class
                    write_private(output / f"{name}.observation.json", private_observation)
                    print(json.dumps({**identity, "status": observation["result"].get("status")}), flush=True)
        fcntl.flock(lease, fcntl.LOCK_UN)
    report = aggregate(records, runs=runs, calls=calls)
    report["source_and_environment"] = manifest
    report["run_observations"] = [
        {k: v for k, v in record.items() if k != "result"}
        | {
            "import": record["result"].get("import"),
            "phase_counts": record["result"].get("phase_counts"),
            "self_cpu_seconds": record["result"].get("self_cpu_seconds"),
            "waited_child_cpu_seconds": record["result"].get("waited_child_cpu_seconds"),
            "self_peak_rss_bytes": record["result"].get("self_peak_rss_bytes"),
            "largest_waited_child_peak_rss_bytes": record["result"].get("largest_waited_child_peak_rss_bytes"),
        }
        for record in records
    ]
    report["raw_evidence"] = [raw_reference(path) for path in sorted(output.iterdir())]
    write_private(output / "aggregate.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--expected-candidate")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--calls", type=int, default=13)
    args = parser.parse_args()
    report = run(
        args.baseline.resolve(),
        args.candidate.resolve(),
        args.output.resolve(),
        runs=args.runs,
        calls=args.calls,
        lock=args.lock.resolve(),
        expected_candidate=args.expected_candidate,
    )
    print(json.dumps({"status": report["status"], "failures": report["failures"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
