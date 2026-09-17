"""Actual macOS correctness witnesses; these are not SLO/performance samples."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from scripts import native_slo_darwin_resources as darwin
from scripts.native_slo_resources import sample_process_tree
from tests.fixtures.native_slo_darwin_cpu_witness import classify_ignored_rollup

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="actual Darwin libproc accounting")
FIXTURE = Path(__file__).parent / "fixtures/native_slo_darwin_cpu_witness.py"


def _line(process: subprocess.Popen[bytes]) -> bytes:
    results: queue.Queue[bytes] = queue.Queue(maxsize=1)
    assert process.stdout is not None
    threading.Thread(target=lambda: results.put(process.stdout.readline(4096)), daemon=True).start()
    result = results.get(timeout=10)
    assert result.endswith(b"\n") and len(result) < 4096
    return result


@pytest.fixture
def owned_root():
    process = subprocess.Popen(
        [sys.executable, "-I", str(FIXTURE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert _line(process) == b"ready\n"
        yield process
    finally:
        try:
            _, stderr = process.communicate(b"stop\n", timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr.decode("utf-8", errors="replace")


def test_actual_darwin_cpu_units_match_process_clock():
    numer, denom = darwin.timebase()
    before = time.process_time_ns()
    value = darwin.process_cpu(os.getpid())
    after = time.process_time_ns()
    converted = (value.user + value.system) * numer // denom
    # getrusage-based process_time and libproc take different kernel snapshots.
    # A 2ms accounting tolerance is tiny relative to the ARM 125/3 units error.
    assert before - 2_000_000 <= converted <= after + 2_000_000


@pytest.mark.parametrize("command", ["nested", "ignored"])
def test_actual_unobserved_child_rollup_is_diagnostic_not_qualified_cpu(owned_root, command):
    process = owned_root
    before = sample_process_tree(process.pid)
    before_raw = darwin.process_cpu(process.pid)
    assert before is not None and before.darwin_cpu is not None and before.processes == 1
    assert process.stdin is not None
    process.stdin.write((command + "\n").encode("ascii"))
    process.stdin.flush()
    witness = json.loads(_line(process))
    after_raw = darwin.process_cpu(process.pid)
    after = sample_process_tree(process.pid)
    assert after is not None and after.darwin_cpu is not None and after.processes == 1
    for snapshot in (before, after):
        assert snapshot.cpu_seconds is None and snapshot.cpu_includes_reaped is False
        assert snapshot.unavailable["cpu_seconds"] == darwin.REAPED_CPU_UNAVAILABLE
    assert after.darwin_cpu.root == before.darwin_cpu.root
    numer, denom = darwin.timebase()
    child_ns = (
        ((after_raw.child_user + after_raw.child_system) - (before_raw.child_user + before_raw.child_system))
        * numer
        / denom
    )
    if command == "nested":
        expected = witness["waited_cpu_ns"]
        assert 0 < witness["grandchild_cpu_ns"] < expected
        assert abs(child_ns - expected) <= 2_000_000 + expected * 0.02
        classification = "waited_once"
    else:
        # Child reports process_time immediately before its short write/exit.
        expected = witness["child_cpu_ns"]
        classification = classify_ignored_rollup(expected, child_ns)
    # Retain finite correctness evidence via pytest -rP, without process data.
    print(json.dumps({"case": command, "expected_ns": expected, "raw_child_ns": child_ns, "rollup": classification}))
    # Only the raw delta is conserved here. Ignored children can be rolled up
    # twice; neither this delta nor its classification qualifies tree CPU.
    assert after.darwin_cpu.seconds_since(before.darwin_cpu) * 1e9 >= child_ns - 2_000_000
