from __future__ import annotations

import threading
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from scripts.native_slo_launcher_offers import LauncherOffers


def fixture_module(original: Any) -> Any:
    module: Any = ModuleType("owned")
    module.observe_priority_launcher = original
    return module


def test_forwarding_retains_arguments_return_and_original_exception() -> None:
    launcher = SimpleNamespace(harness="codex", event="PreToolUse")
    session, response, failure, stop = object(), SimpleNamespace(latency_ms=2.5), RuntimeError("original"), object()
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        if kwargs["sample"] == 1:
            raise failure
        return response

    module = fixture_module(original)
    ledger = LauncherOffers({"priority_per_run": 2, "cold_per_run": 2})

    def operation():
        assert module.observe_priority_launcher(session, launcher, sample=0, stop_event=stop) is response
        module.observe_priority_launcher(session, launcher, sample=1)

    with pytest.raises(RuntimeError) as raised:
        ledger.run(module, original, operation)
    assert raised.value is failure and module.observe_priority_launcher is original
    assert calls == [((session, launcher), {"sample": 0, "stop_event": stop}), ((session, launcher), {"sample": 1})]
    assert [row["outcome"] for row in ledger.report["rows"]] == ["returned", "raised"]
    assert ledger.report["producer_returned"] is False and ledger.report["complete"] is False


def test_failure_tail_snapshot_stays_frozen_without_waiting() -> None:
    entered, release = threading.Event(), threading.Event()
    response = SimpleNamespace(latency_ms=1.0)

    def original(*_args, **_kwargs):
        entered.set()
        assert release.wait(5)
        return response

    module = fixture_module(original)
    ledger = LauncherOffers({"priority_per_run": 2, "cold_per_run": 2})
    worker = None
    failure = RuntimeError("producer")

    def operation():
        nonlocal worker
        worker = threading.Thread(
            target=module.observe_priority_launcher,
            args=(object(), SimpleNamespace(harness="codex", event="PreToolUse")),
            kwargs={"sample": 0},
        )
        worker.start()
        assert entered.wait(5)
        raise failure

    try:
        with pytest.raises(RuntimeError) as raised:
            ledger.run(module, original, operation)
        assert raised.value is failure and ledger.report["active_at_freeze"] == 1
        frozen = repr(ledger.report)
    finally:
        release.set()
        if worker is not None:
            worker.join(timeout=5)
    assert repr(ledger.report) == frozen and ledger.report["rows"][0]["outcome"] == "inflight"


@pytest.mark.parametrize("stage", ["_entry", "_exit", "_freeze"])
def test_recorder_fault_never_replaces_original_return(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    response = SimpleNamespace(latency_ms=1.0)

    def original(*_args, **_kwargs):
        return response

    module = fixture_module(original)
    ledger = LauncherOffers({"priority_per_run": 2, "cold_per_run": 2})

    def fail(*_args, **_kwargs):
        raise RuntimeError("recorder")

    monkeypatch.setattr(ledger, stage, fail)
    assert (
        ledger.run(
            module,
            original,
            lambda: module.observe_priority_launcher(
                None, SimpleNamespace(harness="codex", event="PreToolUse"), sample=0
            ),
        )
        is response
    )
    assert ledger.report["complete"] is False and ledger.report["faults"]


def test_original_producer_coordinates_and_population_are_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import native_slo_priority_launchers as producer

    launches = [
        SimpleNamespace(harness=harness, event=event, config_path="owned", registration_sha256="a" * 64)
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
    ]
    monkeypatch.setattr(producer, "install_priority_launchers", lambda _session: launches)
    monkeypatch.setattr(
        producer,
        "registered_launcher",
        lambda _path, harness, event: next(row for row in launches if row.harness == harness and row.event == event),
    )
    monkeypatch.setattr(producer, "_route_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(producer, "_require_native_count", lambda *_args: None)
    monkeypatch.setattr(
        producer, "validate_batch_routes", lambda observations, *_args: (observations, {"native_resident": 16})
    )
    calls = []

    def original(session, launcher, **kwargs):
        calls.append((session, launcher, kwargs))
        return SimpleNamespace(latency_ms=1.25)

    monkeypatch.setattr(producer, "observe_priority_launcher", original)
    session: Any = object()
    ledger = LauncherOffers({"priority_per_run": 2, "cold_per_run": 2})
    result = ledger.run(
        producer,
        original,
        lambda: producer.measure_priority_launchers(session, {"priority_per_run": 2, "cold_per_run": 2}),
    )
    assert len(calls) == 88 and len(ledger.report["rows"]) == 88
    assert all(call[0] is session for call in calls)
    assert result[0]["contracts_passed"] is True and ledger.report["complete"] is True
    assert sum(len(values) for values in result[1].values()) == 80
    assert producer.observe_priority_launcher is original
