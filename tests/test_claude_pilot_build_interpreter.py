from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from scripts.ci import build_claude_pilot_wheel as builder

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX executable alias and mode contract")


def _environment(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = (tmp_path / "external-environment").resolve()
    (root / "bin").mkdir(parents=True, mode=0o700)
    (root / "pyvenv.cfg").write_text("home = fixture\n")
    source = tmp_path / "shared-python"
    source.write_bytes(b"exact selected interpreter fixture bytes\n")
    source.chmod(0o755)
    python = root / "bin/python"
    python.symlink_to(source)
    return root, python, source


@pytest.mark.parametrize("alias", ["python", "python3", "python3.12"])
def test_selected_venv_alias_uses_exact_private_executable(tmp_path: Path, monkeypatch, alias: str) -> None:
    root, python, source = _environment(tmp_path)
    selected = python.with_name(alias)
    if selected != python:
        selected.symlink_to("python")
    original = source.stat()
    original_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with monkeypatch.context() as context:
        context.setattr(builder.sys, "prefix", str(root))
        context.setattr(builder.sys, "executable", str(selected))
        prepared = builder._prepare_build_interpreter()
    assert prepared == python and not python.is_symlink()
    assert selected.resolve() == python
    assert hashlib.sha256(python.read_bytes()).hexdigest() == original_digest
    assert stat.S_IMODE(python.stat().st_mode) == 0o700
    assert source.stat() == original


def test_interpreter_outside_selected_environment_is_rejected_before_copy(tmp_path: Path, monkeypatch) -> None:
    root, python, source = _environment(tmp_path)
    with monkeypatch.context() as context:
        context.setattr(builder.sys, "prefix", str(root))
        context.setattr(builder.sys, "executable", str(source))
        with pytest.raises(ValueError, match="interpreter_mismatch"):
            builder._prepare_build_interpreter()
    assert python.is_symlink()


def test_alias_for_different_bytes_is_rejected_before_copy(tmp_path: Path, monkeypatch) -> None:
    root, python, _ = _environment(tmp_path)
    selected = python.with_name("python3")
    selected.write_bytes(b"different interpreter")
    selected.chmod(0o700)
    with monkeypatch.context() as context:
        context.setattr(builder.sys, "prefix", str(root))
        context.setattr(builder.sys, "executable", str(selected))
        with pytest.raises(ValueError, match="interpreter_mismatch"):
            builder._prepare_build_interpreter()
    assert python.is_symlink()


def test_detached_alias_cannot_continue_using_shared_interpreter(tmp_path: Path, monkeypatch) -> None:
    root, python, source = _environment(tmp_path)
    selected = python.with_name("python3")
    selected.symlink_to(source)
    with monkeypatch.context() as context:
        context.setattr(builder.sys, "prefix", str(root))
        context.setattr(builder.sys, "executable", str(selected))
        with pytest.raises(ValueError, match="interpreter_alias_detached"):
            builder._prepare_build_interpreter()
    assert selected.resolve() == source and python.resolve() == python
