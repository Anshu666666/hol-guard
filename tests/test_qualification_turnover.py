from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import qualification_turnover_contract as contract
from scripts.ci import qualification_turnover_worker as worker
from scripts.native_slo_lifetime_cpu import CpuSnapshot


def facts() -> dict[str, Any]:
    return {
        "planned_children": 256,
        "planned_waves": 16,
        "concurrency": 16,
        "sampler_interval_seconds": 0.1,
        "offered": 256,
        "returned": 256,
        "exit_codes": [0] * 256,
        "waves_completed": 16,
        "locally_reaped": 256,
        "local_cleanup_complete": True,
        "only_worker_live_after": True,
        "failure_stage": None,
        "lifetime_cpu": {"usage_seconds": 1.0, "user_seconds": 0.6, "system_seconds": 0.4},
        "sampled_resources": {
            "live_inventory_scope": "protected_kernel_group",
            "live_inventory_identity": "pid_and_creation_time_before_and_after_each_sample",
            "instantaneous_peak_proven": False,
            "samples": 33,
            "unavailable_samples": 0,
            "metric_samples": {k: 33 for k in contract.METRICS},
            "metric_minimum_met": {k: True for k in contract.METRICS},
            "unavailable_metrics": {"handles": {"platform_unsupported": 33}},
            "unavailable_sample_reasons": {},
            "unavailable_sample_operations": {},
            "peak": {k: 123 for k in contract.METRICS},
            "baseline": {k: 100 for k in contract.METRICS},
        },
    }


def report(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "hol-guard.finite-turnover-resource-control.v1",
        "admitted": True,
        "admission_refusal": None,
        "passed": contract.measurement_complete(value),
        "original_workload_executed": False,
        "facts": value,
    }


def test_complete_finite_shape_admits_without_promoting_original_workload() -> None:
    original = report(facts())
    assert contract.read_worker_report(json.dumps(original).encode()) == original
    assert original["passed"] is True and original["original_workload_executed"] is False


@pytest.mark.parametrize("bucket", ["baseline", "peak"])
@pytest.mark.parametrize("metric", contract.METRICS)
def test_each_required_actual_metric_is_required(bucket: str, metric: str) -> None:
    value = facts()
    del value["sampled_resources"][bucket][metric]
    original = report(value)
    assert original["passed"] is False
    assert contract.read_worker_report(json.dumps(original).encode()) == original
    original["passed"] = True
    with pytest.raises(ValueError, match="result_join"):
        contract.read_worker_report(json.dumps(original).encode())


@pytest.mark.parametrize("bucket", ["baseline", "peak"])
@pytest.mark.parametrize("invalid", [None, True, -1])
def test_required_actual_metric_refusal_is_not_hidden_by_flags(bucket: str, invalid: Any) -> None:
    value = facts()
    value["sampled_resources"][bucket]["private_bytes"] = invalid
    original = report(value)
    assert original["passed"] is False
    assert contract.read_worker_report(json.dumps(original).encode()) == original


@pytest.mark.parametrize("kind", ["baseline", "peak", "over_count", "boolean_count", "peak_below_baseline"])
def test_actual_metric_buckets_and_sample_count_join_are_required(kind: str) -> None:
    value = facts()
    sampled = value["sampled_resources"]
    if kind in {"baseline", "peak"}:
        del sampled[kind]
    elif kind == "peak_below_baseline":
        sampled["peak"]["rss_bytes"] = 99
    else:
        sampled["metric_samples"]["rss_bytes"] = True if kind == "boolean_count" else 34
    original = report(value)
    assert original["passed"] is False
    assert contract.read_worker_report(json.dumps(original).encode()) == original


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "denied",
        "samples",
        "metric_count",
        "flag",
        "partial",
        "exit",
        "cleanup",
        "retirement",
        "cpu",
        "stage",
    ],
)
def test_measurement_or_ownership_failure_remains_retained_and_false(kind: str) -> None:
    value = facts()
    sampled = value["sampled_resources"]
    if kind == "missing":
        sampled["unavailable_samples"] = 1
        sampled["unavailable_sample_reasons"] = {"inventory_changed": 1}
        sampled["unavailable_sample_operations"] = {"inventory_after:unknown": 1}
    elif kind == "denied":
        sampled["unavailable_metrics"]["private_bytes"] = {"permission_denied": 1}
    elif kind == "samples":
        sampled["samples"] = 29
    elif kind == "metric_count":
        sampled["metric_samples"]["private_bytes"] = 29
    elif kind == "flag":
        sampled["metric_minimum_met"]["private_bytes"] = False
    elif kind == "partial":
        value["returned"] = 255
        value["exit_codes"].pop()
    elif kind == "exit":
        value["exit_codes"][0] = -9
    elif kind == "cleanup":
        value["local_cleanup_complete"] = False
    elif kind == "retirement":
        value["only_worker_live_after"] = False
    elif kind == "cpu":
        value["lifetime_cpu"] = None
    else:
        value["failure_stage"] = "sampler_stop"
    original = report(value)
    assert original["passed"] is False
    assert contract.read_worker_report(json.dumps(original).encode()) == original
    original["passed"] = True
    with pytest.raises(ValueError, match="result_join"):
        contract.read_worker_report(json.dumps(original).encode())


@pytest.mark.parametrize(
    "kind", ["unknown_key", "private_value", "nonfinite", "planned", "bool_count", "extra_exit", "unknown_stage"]
)
def test_closed_original_shape_rejects_ambiguity_and_private_export(kind: str) -> None:
    value = facts()
    if kind == "unknown_key":
        value["sampled_resources"]["raw_command"] = "private"
    elif kind == "private_value":
        value["sampled_resources"]["scope"] = "/private/workspace"
    elif kind == "nonfinite":
        value["sampled_resources"]["samples"] = float("nan")
    elif kind == "planned":
        value["planned_children"] = 257
    elif kind == "bool_count":
        value["offered"] = True
    elif kind == "extra_exit":
        value["exit_codes"].append(0)
    else:
        value["failure_stage"] = "private command"
    with pytest.raises(ValueError):
        contract.admit_facts(value)


def test_duplicate_or_oversized_original_json_refuses() -> None:
    for body in [b'{"schema":1,"schema":2}', b" " * (128 * 1024 + 1)]:
        with pytest.raises(ValueError):
            contract.read_worker_report(body)


def empty_facts() -> dict[str, Any]:
    return {
        "offered": 0,
        "returned": 0,
        "exit_codes": [],
        "waves_completed": 0,
        "locally_reaped": 0,
        "local_cleanup_complete": False,
    }


def test_fixed_population_argument_and_normal_independent_ownership(monkeypatch) -> None:
    calls = []

    class Process:
        def wait(self, *, timeout: float) -> int:
            assert 0 <= timeout <= worker.WORK_SECONDS
            return 0

        def kill(self) -> None:
            raise AssertionError("already reaped must not be killed")

    def spawn(command, **kwargs):
        calls.append(command)
        assert command == [sys.executable, "-I", "-c", worker.PROGRAM]
        assert kwargs == {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        return Process()

    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    value = empty_facts()
    worker.run_children(value)
    assert len(calls) == worker.CHILDREN == 256
    assert value == {
        "offered": 256,
        "returned": 256,
        "exit_codes": [0] * 256,
        "waves_completed": 16,
        "locally_reaped": 256,
        "local_cleanup_complete": True,
    }


@pytest.mark.parametrize("failure", ["spawn", "first_wait", "kill_and_wait"])
def test_every_successfully_spawned_child_is_cleaned_even_after_another_failure(monkeypatch, failure: str) -> None:
    monkeypatch.setattr(worker, "WAVES", 1)
    monkeypatch.setattr(worker, "WIDTH", 3)
    original = OSError("first owned failure")
    calls: list[tuple[str, int]] = []
    spawned = []

    class Process:
        def __init__(self, index: int) -> None:
            self.index = index
            self.waits = 0

        def wait(self, *, timeout: float) -> int:
            self.waits += 1
            calls.append(("wait", self.index))
            if self.index == 0 and self.waits == 1 and failure != "spawn":
                raise original
            if self.index == 0 and failure == "kill_and_wait":
                raise subprocess.TimeoutExpired("owned", timeout)
            return 0

        def kill(self) -> None:
            calls.append(("kill", self.index))
            if self.index == 0 and failure == "kill_and_wait":
                raise PermissionError("secondary cleanup failure")

    def spawn(*_args, **_kwargs):
        if len(spawned) == 2 and failure == "spawn":
            raise original
        child = Process(len(spawned))
        spawned.append(child)
        return child

    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    value = empty_facts()
    with pytest.raises(OSError) as caught:
        worker.run_children(value)
    assert caught.value is original
    assert value["offered"] == len(spawned)
    assert all(("kill", i) in calls and ("wait", i) in calls for i in range(len(spawned)))
    assert value["local_cleanup_complete"] is (failure != "kill_and_wait")


def test_real_fixed_leaf_is_finite_and_stdout_free() -> None:
    # One test-owned leaf validates the exact program, not the hosted c16 offer.
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", worker.PROGRAM], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        stdout, stderr = child.communicate(timeout=3)
        assert child.returncode == 0 and stdout == stderr == b""
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def test_admission_precedes_every_child_and_sample(monkeypatch) -> None:
    def refused(_path):
        raise ValueError("private admission detail")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("called before admission")

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", refused)
    monkeypatch.setattr(worker, "ResourceSampler", forbidden)
    monkeypatch.setattr(worker, "run_children", forbidden)
    original = worker.run(Path("/owned-group"))
    assert original["admitted"] is False and original["facts"]["offered"] == 0
    assert contract.read_worker_report(json.dumps(original).encode()) == original
    assert "private admission detail" not in json.dumps(original)


def test_source_sampler_report_vocabulary_and_default_interval(monkeypatch) -> None:
    from scripts import native_slo_resources as source

    def modeled(*_args, **_kwargs):
        return source.TreeResources(
            rss_bytes=200,
            private_bytes=100,
            cpu_seconds=1.0,
            processes=2,
            threads=2,
            descriptors=8,
            unavailable={"handles": "platform_unsupported"},
            process_cpu={(1, 1.0): 1.0},
            cpu_includes_reaped=True,
        )

    monkeypatch.setattr(source, "sample_process_tree", modeled)
    sampler = source.ResourceSampler(protected_members=lambda: (1, 2))
    assert sampler.interval == 0.1
    for _ in range(31):
        sampler._sample()
    value = facts()
    value["sampled_resources"] = sampler.report(attempted=256)
    assert contract.measurement_complete(value)
    assert contract.read_worker_report(json.dumps(report(value)).encode())["passed"] is True


@pytest.mark.parametrize("failure", [None, "missing", "owned_children", "sampler_stop", "boundary_close"])
def test_whole_finite_worker_preserves_samples_and_admission_cleanup_order(monkeypatch, failure: str | None) -> None:
    events = []
    template = facts()
    if failure == "missing":
        template["sampled_resources"]["unavailable_samples"] = 1
        template["sampled_resources"]["unavailable_sample_reasons"] = {"inventory_changed": 1}

    class Boundary:
        def __init__(self, _path: Path) -> None:
            events.append("admission")
            self.snapshots = 0

        def snapshot(self) -> CpuSnapshot:
            events.append("snapshot")
            self.snapshots += 1
            return CpuSnapshot(self.snapshots * 1000, self.snapshots * 600, self.snapshots * 400)

        def member_pids(self) -> tuple[int, ...]:
            return (1,)

        def close(self) -> None:
            events.append("close")
            if failure == "boundary_close":
                raise OSError("private close")

    class Sampler:
        def __init__(self, *, protected_members) -> None:
            assert callable(protected_members)
            events.append("sampler_created_at_default_interval")

        def __enter__(self):
            events.append("sampler_start")
            return self

        def __exit__(self, *_args) -> None:
            events.append("sampler_stop")
            if failure == "sampler_stop":
                raise OSError("private sampler stop")

        def report(self, *, attempted: int) -> dict[str, Any]:
            assert attempted == 256
            events.append("report")
            return copy.deepcopy(template["sampled_resources"])

    def children(value: dict[str, Any]) -> None:
        events.append("children")
        value.update({k: template[k] for k in empty_facts()})
        if failure == "owned_children":
            raise OSError("private child")

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", Boundary)
    monkeypatch.setattr(worker, "ResourceSampler", Sampler)
    monkeypatch.setattr(worker, "run_children", children)
    monkeypatch.setattr(worker, "_singleton", lambda _reader: True)
    original = worker.run(Path("/owned-group"))
    assert original["passed"] is (failure is None)
    assert contract.read_worker_report(json.dumps(original).encode()) == original
    assert events.index("admission") < events.index("sampler_start") < events.index("children")
    assert events.count("sampler_stop") == 1
    assert events[-2:] == ["report", "close"]
    assert original["facts"]["sampled_resources"] == template["sampled_resources"]
    assert "private child" not in json.dumps(original)


@pytest.mark.parametrize(
    "kind,selected,schema",
    [
        ("cpu", None, "hol-guard.kernel-cpu-host-controller.v1"),
        ("resources", "qualification_resource_contract.py", "hol-guard.kernel-resource-host-controller.v1"),
        ("turnover", "qualification_turnover_contract.py", "hol-guard.kernel-turnover-host-controller.v1"),
    ],
)
def test_actual_controller_selects_only_fixed_reader_before_group_creation(monkeypatch, kind, selected, schema) -> None:
    from types import SimpleNamespace

    from scripts.ci import qualification_cpu_controller as controller

    observed = []

    class StopBeforeGroup:
        def __truediv__(self, _name: str):
            observed.append("before_group")
            raise OSError("intentional source-control boundary")

    def load(path: str) -> dict[str, Any]:
        observed.append(Path(path).name)
        return {"read_worker_report": contract.read_worker_report}

    monkeypatch.setattr(controller, "ROOT", StopBeforeGroup())
    monkeypatch.setattr(
        controller, "sys", SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1, no_site=1))
    )
    monkeypatch.setattr(controller.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(controller.os, "listdir", lambda _path: ["single"])
    monkeypatch.setattr(controller.runpy, "run_path", load)
    original = controller.run(Path(sys.executable), 1001, 1001, control_kind=kind)
    assert original["schema"] == schema
    assert original["worker_launched"] is False and original["cleanup_complete"] is True
    assert observed == ([selected, "before_group"] if selected else ["before_group"])
