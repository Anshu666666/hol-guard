"""Bounded test-only process topology; no job CPU query occurs in this worker."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil


def chain_until(pid: int, boundary: int, *, include_boundary: bool) -> list[dict[str, int | float]]:
    rows: list[dict[str, int | float]] = []
    current = psutil.Process(pid)
    # CPython executes directly or through one Windows venv redirector. Extra
    # ancestors are not silently counted as part of the intended fixture.
    for _ in range(3):
        if current.pid == boundary and not include_boundary:
            return rows
        rows.append({"pid": current.pid, "parent": current.ppid(), "created": current.create_time()})
        if current.pid == boundary:
            return rows
        current = psutil.Process(current.ppid())
    raise AssertionError("unexpected witness ancestry")


def main() -> None:
    if sys.argv[1] == "child":
        chain = chain_until(os.getpid(), int(sys.argv[2]), include_boundary=False)
        assert 1 <= len(chain) <= 2
        sum(number * number for number in range(1_000_000))
        print(json.dumps({"chain": chain, "ticks": time.process_time_ns() // 100}), flush=True)
        return

    sys.path.insert(0, sys.argv[1])
    from codex_plugin_scanner.guard.codex_hook_windows_job import spawn_windows_hook_process

    root_launcher_pid = int(sys.stdin.buffer.readline(16))
    root_chain = chain_until(os.getpid(), root_launcher_pid, include_boundary=True)
    assert 1 <= len(root_chain) <= 2
    command = [sys.executable, str(Path(__file__).resolve()), "child", str(os.getpid())]
    nested_job = None
    if sys.argv[2] == "nested":
        child, nested_job = spawn_windows_hook_process(command, cwd=Path.cwd(), environment=dict(os.environ))
    else:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = child.communicate(timeout=15)
        assert child.returncode == 0 and not error and len(output) <= 4096
        completed = json.loads(output)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        if nested_job is not None:
            nested_job.close()
    print(
        json.dumps(
            {
                "root_chain": root_chain,
                "child_chain": completed["chain"],
                "child_launcher_pid": child.pid,
                "child_ticks": completed["ticks"],
                "root_ticks": time.process_time_ns() // 100,
            }
        ),
        flush=True,
    )
    sys.stdin.buffer.read(1)


if __name__ == "__main__":
    main()
