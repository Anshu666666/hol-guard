from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_qualification_run as module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_numeric_journal import recover_numeric_journal

PLAN = {
    "priority_per_run": 2,
    "other_per_run": 1,
    "cold_per_run": 2,
    "recovery_per_run": 2,
    "resource_samples_per_run": 1,
}


@pytest.fixture
def collection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    class Fixture:
        entered = 0

        def __init__(self, *_args, **_kwargs):
            self.pid = 123
            self.observed = 0
            self.readiness_ms = 0.0
            self.startup_ms = 0.0

        def __enter__(self):
            type(self).entered += 1
            self.readiness_ms = float(type(self).entered)
            self.startup_ms = self.readiness_ms * 10
            return self

        def __exit__(self, *_args):
            pass

        def cpu_accounting_reader(self):
            return None

        def observe(self, harness, event, _size):
            self.observed += 1
            return Observation(harness, event, "1k", float(self.observed), "native_resident", True)

        def control(self, operation, *, count):
            assert operation == "native_samples"
            return {"benign_and_block_validated": True, "values": [10.0 + i for i in range(count)]}

    class Resources:
        samples = 100

        def __init__(self, *, pid, cpu_reader):
            assert pid == 123
            assert cpu_reader is None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def report(self, **_kwargs):
            return {}

    def launchers(_session, _plan, *, journal):
        raw = {"INSTALLED_LAUNCHER.claude-code.PreToolUse": [7.0, 8.0]}
        for name, values in raw.items():
            journal.record(name, values)
        return {}, raw

    def cold(_runtime, _session, count, *, journal):
        values = [20.0 + i for i in range(count)]
        journal.record("NATIVE_CLIENT.cold_oneshot", values)
        return values

    def recovery(_session, count, *, journal):
        values = [30.0] * count
        journal.record("DAEMON_INGRESS.recovery", values)
        return values

    monkeypatch.setattr(module, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(
        module, "native_runtime_status", lambda: SimpleNamespace(identity=SimpleNamespace(path=tmp_path))
    )
    monkeypatch.setattr(module, "_runtime_summary", lambda _: {"build_sha": "a" * 40})
    monkeypatch.setattr(module, "route_matrix", lambda: (("claude-code", "PreToolUse"), ("pi", "PostToolUse")))
    monkeypatch.setattr(
        module,
        "run_contract_corpus",
        lambda *_args, **_kw: {
            "manifest_digest": "b" * 64,
            "oracle_digest": "c" * 64,
            "validated_digest": "d" * 64,
        },
    )
    monkeypatch.setattr(module, "run_registered_contract_corpus", lambda *_args, **_kw: {"validated_digest": "e" * 64})
    monkeypatch.setattr(module, "workload_matrix", lambda *_args: {"missing_reference_scopes": []})
    monkeypatch.setattr(module, "run_additional_scenarios", lambda *_args, **_kw: {"python_phases": {}})
    monkeypatch.setattr(module, "hardware_summary", lambda: {"platform": "linux-x64"})
    monkeypatch.setattr(module, "DaemonFixture", Fixture)
    monkeypatch.setattr(module, "ResourceSampler", Resources)
    monkeypatch.setattr(module, "measure_priority_launchers", launchers)
    monkeypatch.setattr(module, "measure_load_profiles", lambda *_args: ({}, {}, {}))
    monkeypatch.setattr(module, "_run_cold", cold)
    monkeypatch.setattr(module, "_run_recovery", recovery)
    return tmp_path / "block.json"


def test_block_aggregate_is_exactly_conserved_by_private_journal(collection: Path) -> None:
    report = module.run_block(plan=PLAN, raw_file=collection)
    raw = json.loads(collection.read_bytes())
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert recovered["series"] == raw
    assert list(recovered["series"]) == list(raw)
    assert raw["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0, 4.0]
    assert raw["DAEMON_PROCESS.startup"] == [10.0, 20.0, 30.0, 40.0]
    assert raw["NATIVE_CLIENT.policy_readiness"] == [1.0, 2.0, 3.0, 4.0]
    assert raw["DAEMON_INGRESS.recovery"] == [30.0, 30.0]
    assert recovered["collection_complete"] is True
    assert report["qualification_complete"] is recovered["qualification_complete"] is False
    assert "series" not in report and "numeric_journal" not in report
    measurements = cast(dict[str, dict[str, object]], report["measurements"])
    assert {name: value["count"] for name, value in measurements.items()} == {
        name: len(values) for name, values in raw.items()
    }


@pytest.mark.parametrize("phase", ["launcher", "cold", "recovery"])
def test_later_interruption_preserves_earlier_numeric_series(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    names = {
        "launcher": ("measure_priority_launchers", "INSTALLED_LAUNCHER.claude-code.PreToolUse"),
        "cold": ("_run_cold", "NATIVE_CLIENT.cold_oneshot"),
        "recovery": ("_run_recovery", "DAEMON_INGRESS.recovery"),
    }
    function, series = names[phase]

    def interrupted(*_args, journal, **_kwargs):
        with journal.batch(series, 2) as batch:
            batch.record([99.0])
            raise TimeoutError("PRIVATE stopped worker stderr /home/customer")

    monkeypatch.setattr(module, function, interrupted)
    with pytest.raises(TimeoutError):
        module.run_block(plan=PLAN, raw_file=collection)
    assert not collection.exists()
    path = collection.with_name("block-numeric.jsonl")
    recovered = recover_numeric_journal(path)
    assert recovered["series"]["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0, 4.0]
    assert recovered["series"]["NATIVE_CLIENT.claude-code.PostToolUse"] == [10.0, 11.0]
    assert recovered["series"][series] == [99.0]
    assert recovered["batches"][-1]["status"] == "failed"
    assert recovered["collection_complete"] is False
    assert b"PRIVATE" not in path.read_bytes() and b"customer" not in path.read_bytes()


def test_native_batch_interruption_keeps_the_previous_hundred_observations(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = module.DaemonFixture
    original = fixture.control
    calls = 0

    def control(self, operation, *, count):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError("child stopped")
        assert count == 100
        return original(self, operation, count=count)

    monkeypatch.setattr(fixture, "control", control)
    with pytest.raises(TimeoutError):
        module.run_block(plan={**PLAN, "priority_per_run": 101}, raw_file=collection)
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert len(recovered["series"]["NATIVE_CLIENT.claude-code.PostToolUse"]) == 100
    assert recovered["batches"][-1] == {
        "series": "NATIVE_CLIENT.claude-code.PostToolUse",
        "offered": 1,
        "observed": 0,
        "status": "failed",
    }
    assert recovered["collection_complete"] is False


def test_rejected_warm_observation_is_retained_without_qualification(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = module.DaemonFixture
    original = fixture.observe

    def observe(self, harness, event, size):
        value = original(self, harness, event, size)
        if self.observed == 3:
            return Observation(harness, event, size, value.latency_ms, "native_fail_safe", False)
        return value

    monkeypatch.setattr(fixture, "observe", observe)
    with pytest.raises(RuntimeError, match="warm sample changed semantic route"):
        module.run_block(plan=PLAN, raw_file=collection)
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert recovered["series"]["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0]
    assert recovered["batches"][-1]["status"] == "failed"
    assert recovered["collection_complete"] is recovered["qualification_complete"] is False
    assert not collection.exists()
