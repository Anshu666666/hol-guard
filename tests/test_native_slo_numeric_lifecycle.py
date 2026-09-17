from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from scripts import bench_guard_native_installed_slo as module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_numeric_journal import NumericBatch, NumericJournal, recover_numeric_journal


@dataclass
class Session:
    workspace: Path
    guard_home: Path

    def stop_resident(self) -> bool:
        return True

    def observe(self, harness: str, event: str, size_class: str) -> Observation:
        return Observation(harness, event, size_class, 1.0, "native_resident", True)


@pytest.mark.parametrize("phase", ["cold", "recovery"])
def test_lifecycle_checkpoint_cost_is_after_the_measured_stop(
    phase: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = 0.0
    ticks = 0
    records = 0
    original_record = NumericBatch.record

    def now() -> float:
        nonlocal clock, ticks
        ticks += 1
        clock += 0.25
        return clock

    def record(self, values):
        nonlocal clock, records
        records += 1
        assert ticks == records * 2  # Both start and stop already captured.
        clock += 1000.0  # Simulated storage cost must not enter any sample.
        original_record(self, values)

    session = Session(tmp_path, tmp_path)
    monkeypatch.setattr(module.time, "perf_counter", now)
    monkeypatch.setattr(NumericBatch, "record", record)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            stdout=b'{"decision":"allow"}',
            stderr=b"",
        ),
    )
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        values = (
            module._run_cold(tmp_path / "runtime", session, 2, journal=journal)
            if phase == "cold"
            else (module._run_recovery(session, 2, journal=journal))
        )
        assert values == [250.0, 250.0]
    recovered = recover_numeric_journal(path)
    assert list(recovered["series"].values()) == [[250.0, 250.0]]


def test_failed_cold_result_keeps_stopped_latency_before_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Session(tmp_path, tmp_path)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            1,
            stdout=b"PRIVATE raw output",
            stderr=b"PRIVATE child error",
        ),
    )
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal, pytest.raises(RuntimeError, match="one-shot failed"):
        module._run_cold(tmp_path / "runtime", session, 2, journal=journal)
    recovered = recover_numeric_journal(path)
    assert len(recovered["series"]["NATIVE_CLIENT.cold_oneshot"]) == 1
    assert recovered["batches"][-1]["status"] == "failed"
    assert recovered["collection_complete"] is False
    assert b"PRIVATE" not in path.read_bytes()
