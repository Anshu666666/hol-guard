#!/usr/bin/env python3
"""Compare scanner algorithms on synthetic repositories, without exporting inputs.

Run with the same interpreter and a pinned --baseline-root. Output separates
instrumented in-process scanning from fresh full CLI processes. This is a local
algorithm diagnostic, not a release hardware or native-boundary qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=30)
    return result.stdout.decode().strip()


def _source_identity(root: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    files = sorted((root / "src/codex_plugin_scanner/guard/secrets").glob("*.py"))
    files.append(root / "src/codex_plugin_scanner/checks/security.py")
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return {"commit": _git(root, "rev-parse", "HEAD"), "scanner_source_sha256": digest.hexdigest()}


def _cpu_children() -> float | None:
    try:
        import resource
    except ImportError:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _worker(args: argparse.Namespace) -> dict[str, object]:
    sys.path.insert(0, str(args.source_root / "src"))
    from codex_plugin_scanner.checks import security
    from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository
    from codex_plugin_scanner.guard.secrets import secret_staged_scanner as staged

    subprocess_count = 0
    object_process_count = 0
    detector_calls = 0
    detector_cpu = 0.0
    object_io_wall = 0.0
    original_popen = subprocess.Popen

    def launch(command: list[str], *positional: object, **kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal subprocess_count, object_process_count
        subprocess_count += 1
        object_process_count += int("cat-file" in command)
        return original_popen(command, *positional, **kwargs)

    def instrument_detector(function: object) -> object:
        def measure(*positional: object, **kwargs: object) -> object:
            nonlocal detector_calls, detector_cpu
            detector_calls += 1
            start = time.process_time()
            result = function(*positional, **kwargs)
            detector_cpu += time.process_time() - start
            return result

        return measure

    def instrument_io(function: object) -> object:
        def measure(*positional: object, **kwargs: object) -> object:
            nonlocal object_io_wall
            start = time.perf_counter()
            result = function(*positional, **kwargs)
            object_io_wall += time.perf_counter() - start
            return result

        return measure

    subprocess.Popen = launch
    repository.scan_secret_text = instrument_detector(repository.scan_secret_text)
    security._first_hardcoded_secret_line = instrument_detector(security._first_hardcoded_secret_line)
    try:
        from codex_plugin_scanner.guard.secrets.git_object_reader import _BatchProcess
    except ImportError:
        repository._git_blob = instrument_io(repository._git_blob)
        staged._git_staged_blob = instrument_io(staged._git_staged_blob)
    else:
        _BatchProcess.request = instrument_io(_BatchProcess.request)
    cpu_before = time.process_time()
    children_before = _cpu_children()
    start = time.perf_counter()
    if args.workflow == "plugin":
        results = security.run_security_checks(args.target)
        public = [asdict(result) for result in results]
        counts = {"files_scanned": args.file_count, "bytes_scanned": args.input_bytes, "finding_count": 0}
    else:
        result = (
            staged.scan_staged_secrets(args.target, max_findings=10_000)
            if args.workflow == "staged"
            else repository.scan_repository_secrets(
                args.target, include_history=args.workflow == "history", max_findings=10_000
            )
        )
        public = result.to_public_dict()
        if result.truncated or result.errors:
            raise RuntimeError("synthetic benchmark scan was incomplete")
        counts = {
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "finding_count": len(result.findings),
        }
    wall = time.perf_counter() - start
    cpu = time.process_time() - cpu_before
    children_after = _cpu_children()
    git_cpu = None if children_before is None or children_after is None else children_after - children_before
    return {
        **counts,
        "scan_wall_ms": wall * 1000,
        "python_cpu_ms": cpu * 1000,
        "child_cpu_ms": None if git_cpu is None else git_cpu * 1000,
        "detector_cpu_ms": detector_cpu * 1000,
        "object_io_wall_ms": object_io_wall * 1000,
        "subprocess_count": subprocess_count,
        "object_process_count": object_process_count,
        "detector_calls": detector_calls,
        "result_sha256": hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest(),
    }


def _fixture(root: Path, *, workflow: str, files: int, size: int, repeated: bool) -> int:
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "Guard Benchmark")
    _git(root, "config", "user.email", "guard-benchmark@example.invalid")
    total = 0
    for generation in range(6 if workflow == "history" else 1):
        total = 0
        for index in range(files):
            # Public synthetic inputs only. No real paths, credentials or source
            # contents are copied into the repository or exported report.
            number = generation % 2 if repeated else generation * files + index
            line = f"VALUE_{number:08d}=ordinary\n"
            data = (line * (size // len(line) + 1)).encode()[:size]
            (root / f"config-{index:05d}.json").write_bytes(data)
            total += len(data)
        _git(root, "add", ".")
        if workflow == "history":
            _git(root, "commit", "-m", f"generation {generation}")
    return total


def _full_cli(source_root: Path, target: Path, workflow: str) -> tuple[float, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(source_root / "src")
    code = "import sys; sys.argv[0]='hol-guard'; from codex_plugin_scanner.cli import main; raise SystemExit(main())"
    command = [sys.executable, "-c", code, "secrets", "scan", str(target), "--json", "--max-findings", "10000"]
    if workflow != "working":
        command.append("--" + workflow)
    start = time.perf_counter()
    process = subprocess.run(command, env=env, capture_output=True, timeout=120, check=True)
    elapsed = (time.perf_counter() - start) * 1000
    public = json.loads(process.stdout)
    return elapsed, hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--target", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--workflow", help=argparse.SUPPRESS)
    parser.add_argument("--file-count", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--input-bytes", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(_worker(args), sort_keys=True))
        return 0
    if args.baseline_root is None or args.output is None or not 1 <= args.repeats <= 100:
        parser.error("provide --baseline-root and --output, with 1..100 repeats")
    roots = {"current_python": args.baseline_root.resolve(), "optimized_python": args.source_root.resolve()}
    source_identities = {name: _source_identity(root) for name, root in roots.items()}
    rows = []
    cases = [
        ("staged_small_unique", "staged", 10, 256, False),
        ("staged_many_unique", "staged", 1000, 256, False),
        ("staged_many_repeated", "staged", 1000, 256, True),
        ("staged_large_repeated", "staged", 8, 256 * 1024, True),
        ("history_repeated", "history", 80, 256, True),
        ("working_many_unique", "working", 1000, 256, False),
        ("plugin_many_unique", "plugin", 1000, 256, False),
    ]
    with tempfile.TemporaryDirectory(prefix="guard-secret-benchmark-") as directory:
        for label, workflow, files, size, repeated in cases:
            target = Path(directory) / label
            input_bytes = _fixture(target, workflow=workflow, files=files, size=size, repeated=repeated)
            samples: dict[str, list[dict[str, object]]] = {name: [] for name in roots}
            for repeat in range(args.repeats):
                for name in list(roots) if repeat % 2 == 0 else list(reversed(roots)):
                    command = [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--worker",
                        "--source-root",
                        str(roots[name]),
                        "--target",
                        str(target),
                        "--workflow",
                        workflow,
                        "--file-count",
                        str(files),
                        "--input-bytes",
                        str(input_bytes),
                    ]
                    worker = subprocess.run(command, capture_output=True, timeout=180, check=True)
                    sample = json.loads(worker.stdout)
                    if workflow != "plugin":
                        cli_wall, digest = _full_cli(roots[name], target, workflow)
                        if digest != sample["result_sha256"]:
                            raise RuntimeError("full CLI output differs from instrumented scanner")
                        sample["full_cli_wall_ms"] = cli_wall
                    samples[name].append(sample)
            if len({sample["result_sha256"] for group in samples.values() for sample in group}) != 1:
                raise RuntimeError("current and optimized Python produced different scan results")
            summary = {}
            for name, group in samples.items():
                summary[name] = {
                    key: statistics.median(sample[key] for sample in group)
                    for key in group[0]
                    if key != "result_sha256" and all(sample[key] is not None for sample in group)
                }
            rows.append({"case": label, "workflow": workflow, "samples": samples, "median": summary})
            print(label + ": equivalent", flush=True)
    if source_identities != {name: _source_identity(root) for name, root in roots.items()}:
        raise RuntimeError("scanner sources changed during benchmark; rerun against frozen sources")
    report = {
        "schema": "guard-secret-algorithm-benchmark.v1",
        "sources": source_identities,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
            "git": _git(args.source_root, "--version"),
        },
        "method": {
            "repeats": args.repeats,
            "order": "alternating",
            "cache": "uncontrolled OS cache",
            "full_cli": "fresh interpreter running codex_plugin_scanner.cli.main",
            "qualification": "local synthetic algorithm diagnostic; no native implementation compared",
            "fixtures": "many small/unique/repeated, few large, staged/history/working/plugin; safe synthetic text",
            "privacy": "aggregate counts, timing and result digests only",
        },
        "cases": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
