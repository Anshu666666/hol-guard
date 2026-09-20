from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import native_slo_launcher_resources as observed
from scripts.native_slo_lifetime_cpu import CpuSnapshot


class _Sampler:
    def __init__(self, *, fail: str | None = None) -> None:
        self.fail = fail
        self.events: list[str] = []

    def __enter__(self) -> _Sampler:
        self.events.append("enter")
        if self.fail == "enter":
            raise RuntimeError("private recorder start")
        return self

    def __exit__(self, *_args: object) -> None:
        self.events.append("exit")
        if self.fail == "exit":
            raise RuntimeError("private recorder stop")

    def report(self, *, attempted: int) -> dict[str, object]:
        self.events.append("report")
        assert attempted == 0
        if self.fail == "report":
            raise RuntimeError("private recorder report")
        return {"cpu_seconds": 0.2, "short_exited_descendants_cpu_complete": False}


@pytest.mark.parametrize("failure", [None, "enter", "exit", "report"])
@pytest.mark.parametrize("raises", [False, True])
def test_recorder_failures_preserve_the_single_original_object(
    monkeypatch: pytest.MonkeyPatch, failure: str | None, raises: bool
) -> None:
    sampler = _Sampler(fail=failure)
    monkeypatch.setattr(observed, "ResourceSampler", lambda **_kwargs: sampler)
    collector = observed.LauncherResourceObservation()
    result = object()
    error = RuntimeError("original private error")
    calls = []

    def original() -> object:
        calls.append(None)
        assert sampler.events == ["enter"]
        if raises:
            raise error
        return result

    if raises:
        with pytest.raises(RuntimeError) as caught:
            collector.run(original)
        assert caught.value is error
    else:
        assert collector.run(original) is result
    assert calls == [None]
    assert sampler.events == ["enter", "exit", "report"]
    assert collector.report["original_calls"] == 1
    assert collector.report["original_returned"] is not raises
    assert collector.report["observation_complete"] is (not raises and failure is None)
    assert collector.report["lifetime_cpu_complete"] is False
    assert "private" not in repr(collector.report)
    with pytest.raises(ValueError, match="single use"):
        collector.run(original)
    assert calls == [None]


def test_unexpected_finish_failure_cannot_replace_original_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    sampler = _Sampler()
    monkeypatch.setattr(observed, "ResourceSampler", lambda **_kwargs: sampler)
    collector = observed.LauncherResourceObservation()
    original = LookupError("original")

    def finish(*_args: object) -> None:
        raise ValueError("recorder failure")

    def operation() -> None:
        raise original

    monkeypatch.setattr(collector, "_finish", finish)
    with pytest.raises(LookupError) as caught:
        collector.run(operation)
    assert caught.value is original
    assert collector.report["finish_failed"] is True


class _Lifetime:
    identity_sha256 = "a" * 64

    def __init__(self, *, lost: bool = False) -> None:
        self.calls = 0
        self.lost = lost

    def snapshot(self) -> CpuSnapshot:
        self.calls += 1
        if self.calls == 2 and self.lost:
            raise RuntimeError("private group moved")
        return CpuSnapshot(self.calls * 100_000, self.calls * 60_000, self.calls * 40_000)


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("failure_tail", [False, True])
def test_kernel_counter_and_workload_tail_are_separate(
    monkeypatch: pytest.MonkeyPatch, lost: bool, failure_tail: bool
) -> None:
    monkeypatch.setattr(observed, "ResourceSampler", lambda **_kwargs: _Sampler())
    lifetime: Any = _Lifetime(lost=lost)
    collector = observed.LauncherResourceObservation(lifetime_cpu=lifetime)

    def original() -> None:
        if failure_tail:
            raise ValueError("original")

    if failure_tail:
        with pytest.raises(ValueError, match="original"):
            collector.run(original)
    else:
        collector.run(original)
    assert lifetime.calls == 2
    assert collector.report["lifetime_cpu_complete"] is (not lost and not failure_tail)
    assert collector.report["full_resource_qualification"] is False
    assert collector.report["final_tail_complete"] is not failure_tail
    assert collector.report["sampled_resources"]["short_exited_descendants_cpu_complete"] is False
    if not lost:
        assert collector.report["lifetime_cpu"]["usage_seconds"] == 0.1


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux waited-child CPU subset")
def test_real_reaped_child_and_grandchild_cpu_between_polls_remains_a_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_sampler = observed.ResourceSampler
    monkeypatch.setattr(observed, "ResourceSampler", lambda **kwargs: original_sampler(interval_seconds=1.0, **kwargs))
    leaf = "import time; end=time.process_time()+0.04\nwhile time.process_time()<end: pass"
    program = (
        "import subprocess, sys\n"
        f"subprocess.run([sys.executable, '-c', {leaf!r}], check=True, timeout=5)\n"
        "print('original-result', flush=True)\n"
    )
    collector = observed.LauncherResourceObservation()
    result = collector.run(
        lambda: subprocess.run([sys.executable, "-c", program], capture_output=True, timeout=8, check=True)
    )
    assert result.stdout == b"original-result\n"
    resources = collector.report["sampled_resources"]
    assert resources["cpu_seconds"] >= 0.03
    assert resources["cpu_includes_reaped_descendants"] is True
    assert resources["short_exited_descendants_cpu_complete"] is False
    assert collector.report["lifetime_cpu_complete"] is False
    assert collector.report["includes_load_generator_and_collector"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX independently session-owned partial child")
def test_real_new_session_child_survives_failed_operation_until_original_owner_cleans_it() -> None:
    child: subprocess.Popen[bytes] | None = None
    collector = observed.LauncherResourceObservation()
    original = RuntimeError("original operation failed")

    def operation() -> None:
        nonlocal child
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; print('ready',flush=True); sys.stdin.read(1)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            start_new_session=True,
        )
        assert child.stdout is not None and child.stdout.readline() == b"ready\n"
        raise original

    try:
        with pytest.raises(RuntimeError) as caught:
            collector.run(operation)
        assert caught.value is original
        assert child is not None and child.poll() is None
        assert os.getsid(child.pid) == child.pid
        assert collector.report["observation_complete"] is False
        assert collector.report["final_tail_complete"] is False
        assert collector.report["lifetime_cpu_complete"] is False
    finally:
        if child is not None:
            child.communicate(b"x", timeout=5)
            assert child.returncode == 0


def test_run_block_default_and_opt_in_calls_preserve_original_producer_source() -> None:
    import ast

    path = Path(__file__).resolve().parents[1] / "scripts/native_slo_qualification_run.py"
    tree = ast.parse(path.read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "measure_priority_launchers"
    ]
    assert len(calls) == 2
    assert ast.dump(calls[0]) == ast.dump(calls[1])
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_block"]
    assert len(functions) == 1
    assert ast.literal_eval(functions[0].args.kw_defaults[-1]) is None
