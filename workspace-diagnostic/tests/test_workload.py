"""Actual workload invocation accounting under preparation and call failures."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import run_workload as workload


@pytest.fixture
def isolated_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    source, output = tmp_path / "source", tmp_path / "output"
    script = source / "scripts/native_slo_workspace_lifecycle_runner.py"
    script.parent.mkdir(parents=True)
    script.write_text("# synthetic invocation-accounting control\n", encoding="utf-8")
    output.mkdir()
    runtime = tmp_path / "synthetic-runtime"
    state = SimpleNamespace(
        setup_error=None,
        call_error=None,
        calls=[],
        entries=0,
        exits=0,
        runtime=runtime,
        output=output,
    )

    class Forwarding:
        def __enter__(self) -> Forwarding:
            state.entries += 1
            if state.setup_error is not None:
                raise state.setup_error
            return self

        def __exit__(self, *_arguments: Any) -> bool:
            state.exits += 1
            return False

        def report(self) -> dict[str, Any]:
            return {
                "patches_restored": state.exits == 1,
                "declared_fixture_roster_complete": state.entries == 1 and state.exits == 1,
            }

    def original(current: Path, **arguments: Any) -> dict[str, Any]:
        state.calls.append((current, arguments))
        if state.call_error is not None:
            raise state.call_error
        return {
            "counts": [100],
            "scenarios": list(workload.SCENARIOS),
            "complete_lifecycle_matrix_visited": False,
            "implemented_checks_passed": False,
            "headline_timing_eligible": False,
            "full_rsp_128_129_qualification": False,
            "runtime": {"build_sha": workload.SOURCE_SHA, "runtime_sha256": "a" * 64},
            "cells": [
                {"scenario": scenario, "registered_workspaces": 100, "passed": False} for scenario in workload.SCENARIOS
            ],
        }

    package: Any = ModuleType("scripts")
    runner: Any = ModuleType("scripts.native_slo_workspace_lifecycle_runner")
    runner.__file__ = str(script)
    runner.run_lifecycle_sweep = original
    package.native_slo_workspace_lifecycle_runner = runner
    monkeypatch.setitem(sys.modules, "scripts", package)
    monkeypatch.setitem(sys.modules, runner.__name__, runner)
    monkeypatch.setattr(
        workload,
        "sys",
        SimpleNamespace(
            flags=SimpleNamespace(isolated=True),
            platform="linux",
            path=list(sys.path),
        ),
    )
    monkeypatch.setattr(
        workload,
        "os",
        SimpleNamespace(
            name="posix",
            environ={},
            open=os.open,
            fdopen=os.fdopen,
            fsync=os.fsync,
            O_WRONLY=os.O_WRONLY,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
        ),
    )
    monkeypatch.setattr(
        workload.argparse.ArgumentParser,
        "parse_args",
        lambda _self: SimpleNamespace(source=source, output=output),
    )
    monkeypatch.setattr(
        workload,
        "_installed_runtime",
        lambda _source: (
            runtime,
            {"runtime_sha256": "a" * 64},
        ),
    )
    monkeypatch.setattr(workload, "FixtureForwarding", lambda *_arguments: Forwarding())
    monkeypatch.setattr(
        workload,
        "read_cell",
        lambda *_arguments: {
            "original_result_flags": {"passed": False},
        },
    )
    monkeypatch.setattr(workload, "summarize", lambda report: report)
    return state


def test_setup_failure_records_zero_original_calls_and_preserves_error(isolated_call: Any) -> None:
    failure = RuntimeError("synthetic forwarding setup failure")
    isolated_call.setup_error = failure
    with pytest.raises(RuntimeError) as raised:
        workload.main()
    assert raised.value is failure
    report = json.loads((isolated_call.output / "diagnostic-result.json").read_text(encoding="utf-8"))
    assert report["original_function_calls"] == 0
    assert report["diagnostic_admitted"] is False
    assert isolated_call.calls == [] and isolated_call.exits == 0


def test_original_exception_records_one_call_without_retry(isolated_call: Any) -> None:
    failure = RuntimeError("synthetic original sweep failure")
    isolated_call.call_error = failure
    with pytest.raises(RuntimeError) as raised:
        workload.main()
    assert raised.value is failure
    report = json.loads((isolated_call.output / "diagnostic-result.json").read_text(encoding="utf-8"))
    assert report["original_function_calls"] == 1
    assert report["diagnostic_admitted"] is False
    assert len(isolated_call.calls) == isolated_call.exits == 1
    assert isolated_call.calls[0] == (
        isolated_call.runtime,
        {
            "ledger_path": isolated_call.output / "workspace-lifecycle.jsonl",
            "counts": (100,),
            "scenarios": workload.SCENARIOS,
        },
    )


def test_normal_return_records_one_call_and_keeps_failed_original_cells(isolated_call: Any) -> None:
    assert workload.main() == 1
    report = json.loads((isolated_call.output / "diagnostic-result.json").read_text(encoding="utf-8"))
    assert report["original_function_calls"] == 1
    assert report["diagnostic_admitted"] is True
    assert report["original_selected_cells_passed"] is False
    assert report["original_full_matrix_passed"] is False
    assert len(isolated_call.calls) == isolated_call.exits == 1
    assert len(report["summaries"]) == 3
