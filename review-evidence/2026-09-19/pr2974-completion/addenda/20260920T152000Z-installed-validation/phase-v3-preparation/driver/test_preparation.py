"""Untimed forwarding controls; never launch an interpreter or product process."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location("phase_owned_preparation", Path(__file__).with_name("verify_inputs.py"))
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProvisionError(RuntimeError):
    def __init__(self, evidence: dict[str, object]) -> None:
        super().__init__("synthetic unchanged primary")
        self.evidence = evidence


@pytest.fixture
def boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[argparse.Namespace, dict[str, Any], list[Path]]:
    python = tmp_path / ".venv/bin/python"
    calls: list[Path] = []
    proof = {
        "passed": True,
        "identical_bytes": True,
        "original_target_preserved": True,
        "managed_integrity_validated": True,
        "owned": {"mode": 0o755, "owner_current": True},
    }

    def original(path: Path) -> dict[str, Any]:
        calls.append(path)
        return proof

    module = SimpleNamespace(
        __file__=str(tmp_path / "scripts/native_qualification_interpreter.py"),
        provision_venv_interpreter=original,
        InterpreterProvisioningError=ProvisionError,
    )
    monkeypatch.setattr(MODULE, "importlib", SimpleNamespace(import_module=lambda _name: module))
    monkeypatch.setattr(
        MODULE, "sys", SimpleNamespace(executable=str(python), prefix=str(python.parent.parent), path=[])
    )
    monkeypatch.setattr(MODULE, "_interpreter_metadata", lambda path: {"invocation_path": str(path), "synthetic": True})
    return argparse.Namespace(source=tmp_path), {"proof": proof, "module": module}, calls


def test_calls_existing_helper_once_with_unchanged_invocation(
    boundary: tuple[argparse.Namespace, dict[str, Any], list[Path]],
) -> None:
    args, state, calls = boundary
    report: dict[str, object] = {}
    MODULE._provision(args, report)
    assert calls == [args.source / ".venv/bin/python"]
    assert report["preparation"] is state["proof"]
    assert report["interpreter_before"] == report["interpreter_after"]


@pytest.mark.parametrize("field", ["identical_bytes", "original_target_preserved", "managed_integrity_validated"])
def test_incomplete_preparation_is_rejected(
    boundary: tuple[argparse.Namespace, dict[str, Any], list[Path]], field: str
) -> None:
    args, state, calls = boundary
    state["proof"][field] = False
    with pytest.raises(ValueError, match="phase_input_preparation_"):
        MODULE._provision(args, {})
    assert len(calls) == 1


def test_wrong_invocation_refuses_before_helper(
    boundary: tuple[argparse.Namespace, dict[str, Any], list[Path]],
) -> None:
    args, _state, calls = boundary
    MODULE.sys.executable = str(args.source / "other-python")
    with pytest.raises(ValueError, match="preparation_invocation"):
        MODULE._provision(args, {})
    assert calls == []


def test_original_helper_error_survives_after_metadata_failure(
    boundary: tuple[argparse.Namespace, dict[str, Any], list[Path]], monkeypatch: pytest.MonkeyPatch
) -> None:
    args, state, calls = boundary
    evidence = {"passed": False, "retained": True}
    original = ProvisionError(evidence)

    def fail(path: Path) -> None:
        calls.append(path)
        raise original

    count = 0

    def metadata(_path: Path) -> dict[str, object]:
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("synthetic cleanup observation fault")
        return {"before": True}

    state["module"].provision_venv_interpreter = fail
    monkeypatch.setattr(MODULE, "_interpreter_metadata", metadata)
    report: dict[str, object] = {}
    with pytest.raises(ProvisionError) as caught:
        MODULE._provision(args, report)
    assert caught.value is original and report["preparation"] is evidence
    assert report["interpreter_after_failure"] == {"kind": "OSError"}
    assert len(calls) == 1
