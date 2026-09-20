from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci import qualification_cpu_controller as controller
from scripts.ci import qualification_resource_contract as contract
from scripts.ci import qualification_resource_worker as worker


def report() -> dict[str, Any]:
    rows = []
    for name in contract.NAMES:
        denied = name == "denied_private_memory"
        facts = {
            "member_count": 3 if name == "child_and_grandchild" else 2,
            "non_ancestry_members": 1 if name == "reparented_member" else 0,
            "samples": 34,
            "private_bytes": None if denied else 20 * 1024 * 1024,
            "rss_bytes": 40 * 1024 * 1024,
            "metric_minimum_met": {
                key: not denied or key not in {"private_bytes", "descriptors"} for key in contract.METRICS
            },
            "only_worker_live_after": True,
            "orphan_reaped_by_worker": False,
            "denied_private_observed": denied,
            "sampled_peak_only": True,
        }
        rows.append({"name": name, "passed": True, "error": None, "facts": facts})
    return {
        "schema": "hol-guard.live-member-resource-controls.v1",
        "admitted": True,
        "admission_refusal": None,
        "controls": rows,
        "passed": True,
    }


def test_closed_reader_preserves_sampled_values_and_denied_metrics() -> None:
    original = report()
    result = contract.read_worker_report(json.dumps(original).encode())
    assert result == original
    assert result["controls"][2]["facts"]["private_bytes"] is None
    assert result["controls"][2]["facts"]["metric_minimum_met"]["descriptors"] is False


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "order",
        "name",
        "duplicate",
        "false_success",
        "active",
        "reaping",
        "ancestry",
        "private_zero",
        "rss_proxy",
        "bool_samples",
        "few_samples",
        "instant_peak",
        "denial_zero",
        "denial_flag",
        "unknown_field",
    ],
)
def test_strict_finite_reader_refuses_missing_or_invented_proof(change: str) -> None:
    value = report()
    row = value["controls"][1]
    facts = row["facts"]
    if change == "missing":
        value["controls"].pop()
    elif change == "order":
        value["controls"].reverse()
    elif change == "name":
        row["name"] = "arbitrary"
    elif change == "duplicate":
        value["controls"][1] = copy.deepcopy(value["controls"][0])
    elif change == "false_success":
        row["passed"] = False
    elif change == "active":
        facts["only_worker_live_after"] = False
    elif change == "reaping":
        facts["orphan_reaped_by_worker"] = True
    elif change == "ancestry":
        facts["non_ancestry_members"] = 0
    elif change == "private_zero":
        facts["private_bytes"] = 0
    elif change == "rss_proxy":
        facts["private_bytes"] = None
    elif change == "bool_samples":
        facts["samples"] = True
    elif change == "few_samples":
        facts["samples"] = 29
    elif change == "instant_peak":
        facts["sampled_peak_only"] = False
    elif change == "denial_zero":
        value["controls"][2]["facts"]["private_bytes"] = 0
    elif change == "denial_flag":
        value["controls"][2]["facts"]["metric_minimum_met"]["private_bytes"] = True
    elif change == "unknown_field":
        facts["private_path"] = "do-not-export"
    with pytest.raises(ValueError):
        contract.read_worker_report(json.dumps(value).encode())


@pytest.mark.parametrize("body", [b'{"a":1,"a":2}', b" " * (128 * 1024 + 1)], ids=["duplicate", "size"])
def test_reader_bounds_input(body: bytes) -> None:
    with pytest.raises(ValueError):
        contract.read_worker_report(body)


def test_admission_refusal_starts_no_finite_child(monkeypatch: pytest.MonkeyPatch) -> None:
    offered = []

    def refuse(_path):
        raise worker.LifetimeCpuUnavailableError("private exception content")

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", refuse)
    monkeypatch.setattr(worker, "control", lambda *_args: offered.append(True))
    value = worker.run(Path("/private"))
    assert offered == [] and value["admitted"] is False and value["controls"] == []
    assert value["admission_refusal"] == "accounting"
    assert contract.read_worker_report(json.dumps(value).encode()) == value
    assert "private" not in json.dumps(value)


@pytest.mark.parametrize("name", contract.NAMES)
def test_original_control_failure_closes_created_pipes_and_preserves_exception(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    descriptors = []
    pipe = os.pipe

    def create_pipe():
        pair = pipe()
        descriptors.extend(pair)
        return pair

    original = AssertionError("fixed readiness failure")

    def refuse(*_args):
        raise original

    monkeypatch.setattr(worker.os, "pipe", create_pipe)
    programs = []

    def capture_program(command, **_kwargs):
        assert command[:3] == [sys.executable, "-I", "-c"]
        programs.append(command[3])
        compile(command[3], "finite-control-program", "exec")
        compile(worker._LEAF, "finite-control-leaf", "exec")
        return SimpleNamespace(wait=lambda **_kwargs: 0)

    monkeypatch.setattr(worker.subprocess, "Popen", capture_program)
    monkeypatch.setattr(worker, "_ready", refuse)
    retired = []
    monkeypatch.setattr(worker, "_retired", lambda reader: retired.append(reader))
    reader: Any = object()
    with pytest.raises(AssertionError) as raised:
        worker.control(reader, name)
    assert raised.value is original and retired == [reader]
    assert len(programs) == 1
    assert len(descriptors) == 4
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_controller_resource_selection_loads_only_fixed_stdlib_contract_before_group_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(controller.sys, "platform", "linux")
    monkeypatch.setattr(controller.sys, "flags", SimpleNamespace(isolated=1, no_site=1))
    monkeypatch.setattr(controller.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(controller.os, "listdir", lambda _path: ["one"])
    seen = []

    def fixed_contract(path: str):
        seen.append(Path(path).name)
        raise ValueError("stop before any group")

    monkeypatch.setattr(controller.runpy, "run_path", fixed_contract)
    value = controller.run(Path(sys.executable), 1001, 1001, control_kind="resources")
    assert seen == ["qualification_resource_contract.py"]
    assert value["worker_launched"] is False and value["cleanup_complete"] is True


def test_arbitrary_controller_kind_is_refused_before_any_setup() -> None:
    value = controller.run(Path("/not-read"), 1001, 1001, control_kind="arbitrary_module")
    assert value["worker_launched"] is False and value["cleanup_complete"] is True
