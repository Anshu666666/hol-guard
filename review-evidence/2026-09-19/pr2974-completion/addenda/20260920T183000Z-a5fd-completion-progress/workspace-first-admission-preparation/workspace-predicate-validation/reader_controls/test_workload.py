"""No workload execution: original CLI forwarding and failure accounting controls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from scripts import native_slo_workspace_lifecycle_runner as original

import workload


@pytest.mark.parametrize("mode", ["return", "exception", "setup", "export"])
def test_exact_original_invocation_and_failure_preservation(tmp_path: Path, monkeypatch: Any, mode: str) -> None:
    source = Path(__file__).resolve().parents[2]
    calls = []
    error = RuntimeError("PRIVATE_ORIGINAL")
    before_argv = sys.argv

    class Forwarding:
        def __init__(self, *args: Any) -> None:
            assert args == (source, tmp_path / "predicates")

        def __enter__(self) -> Any:
            if mode == "setup":
                raise error
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def report(self) -> dict[str, Any]:
            return {"fixture_factories": 0}

    def main() -> int:
        calls.append(sys.argv.copy())
        if mode == "exception":
            raise error
        return 1

    monkeypatch.setattr(workload, "FixtureForwarding", Forwarding)
    monkeypatch.setattr(original, "main", main)
    if mode == "export":

        def bad_write(*_args: Any) -> None:
            raise ValueError("export")

        monkeypatch.setattr(workload, "write", bad_write)
    if mode in {"exception", "setup"}:
        with pytest.raises(RuntimeError) as caught:
            workload.invoke(source, Path("/owned/runtime"), tmp_path)
        assert caught.value is error
    else:
        assert workload.invoke(source, Path("/owned/runtime"), tmp_path) == 1
    assert sys.argv is before_argv
    assert len(calls) == (0 if mode == "setup" else 1)
    if calls:
        assert calls[0] == [
            str(source / "scripts/native_slo_workspace_lifecycle_runner.py"),
            "--runtime",
            "/owned/runtime",
            "--ledger",
            str(tmp_path / "workspace-lifecycle.jsonl"),
            "--output",
            str(tmp_path / "workspace-lifecycle.json"),
            "--counts",
            "100",
            "--scenarios",
            "first_admission_fault",
        ]
    if mode != "export":
        record = json.loads((tmp_path / "original-invocation.json").read_text())
        assert record["original_main_calls"] == len(calls)
        assert record["original_main_raised"] is (mode in {"exception", "setup"})
    else:
        assert not (tmp_path / "original-invocation.json").exists()
