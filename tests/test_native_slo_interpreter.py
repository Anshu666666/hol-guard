"""The qualification fixture fixes its own executable, never shared trust rules."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import (
    CodexHookIntegrityError,
    validate_regular_file,
)
from scripts import native_slo_interpreter as module

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX mode-specific qualification fixture")


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = (tmp_path / "environment").resolve()
    binary = root / "bin"
    binary.mkdir(parents=True, mode=0o700)
    (root / "pyvenv.cfg").write_text("home = fixture\n")
    source = tmp_path / "shared interpreter"
    source.write_bytes(b"qualification exact interpreter bytes\n")
    source.chmod(0o777)
    python = binary / "python"
    python.symlink_to(source)
    return root, python, source


def test_private_copy_repairs_exact_rejected_permissions_without_changing_source(tmp_path: Path) -> None:
    root, python, source = _fixture(tmp_path)
    original = source.stat()
    with pytest.raises(CodexHookIntegrityError) as failure:
        validate_regular_file(source, role="interpreter", executable_required=True)
    assert failure.value.reason == "codex_hook_interpreter_permissions_unsafe"
    assert hashlib.sha256(str(failure.value).encode()).hexdigest() == (
        "3a7dada600dc5f78680385a54e01c8ce4ac4c14b77c2cca25d22f2ada6fc1222"
    )
    proof = module.prepare_private_interpreter(python, environment_root=root)
    validate_regular_file(python, role="interpreter", executable_required=True)
    assert not python.is_symlink()
    assert python.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(python.stat().st_mode) == 0o700
    assert source.stat() == original
    assert proof["source_sha256"] == proof["copy_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert proof["source"] == {
        "mode": 0o777,
        "owner": "current_user",
        "group_writable": True,
        "world_writable": True,
        "regular": True,
    }
    assert str(tmp_path) not in json.dumps(proof)
    assert str(source) not in json.dumps(proof)


@pytest.mark.parametrize("symlink", [False, True])
def test_real_venv_copy_preserves_executable_and_environment_identity(tmp_path: Path, symlink: bool) -> None:
    root = (tmp_path / "actual-venv").resolve()
    venv.EnvBuilder(with_pip=False, symlinks=False).create(root)
    python = root / "bin/python"
    if symlink:
        # Own the test executable even when the sandbox base Python has a
        # different uid. Reproduce the runner mode without touching its source.
        shared = tmp_path / "owned-shared" / "bin" / "python"
        shared.parent.mkdir(parents=True)
        (shared.parent.parent / "lib").symlink_to(Path(sys.base_prefix) / "lib", target_is_directory=True)
        config = (root / "pyvenv.cfg").read_text().splitlines()
        _ = (root / "pyvenv.cfg").write_text(
            "\n".join(f"home = {shared.parent}" if line.startswith("home = ") else line for line in config) + "\n"
        )
        _ = shutil.copyfile(python.resolve(), shared)
        shared.chmod(0o777)
        python.unlink()
        python.symlink_to(shared)
    query = "import json,sys; print(json.dumps([sys.executable,sys.prefix,sys.base_prefix,sys.version]))"
    before = subprocess.check_output([str(python), "-I", "-c", query], text=True)
    proof = module.prepare_private_interpreter(python, environment_root=root)
    after = subprocess.check_output([str(python), "-I", "-c", query], text=True)
    assert json.loads(before) == json.loads(after)
    assert json.loads(after)[1] == str(root)
    assert proof["source_sha256"] == proof["copy_sha256"]
    assert python.resolve() == python


def test_changed_source_aborts_before_replacing_invocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, python, source = _fixture(tmp_path)
    real_fsync = os.fsync

    def change_source(descriptor: int) -> None:
        real_fsync(descriptor)
        source.write_bytes(b"changed source content after copy\n")

    monkeypatch.setattr(module.os, "fsync", change_source)
    with pytest.raises(ValueError, match="qualification_interpreter_source_changed"):
        module.prepare_private_interpreter(python, environment_root=root)
    assert python.is_symlink()
    assert not tuple(python.parent.glob(".qualification-python-*"))


def test_copy_io_failure_preserves_shared_source_and_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, python, source = _fixture(tmp_path)
    original = source.stat()

    def failed_fsync(_descriptor: int) -> None:
        raise OSError("injected copy failure")

    monkeypatch.setattr(module.os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="injected copy failure"):
        module.prepare_private_interpreter(python, environment_root=root)
    assert python.is_symlink()
    assert source.stat() == original
    assert not tuple(python.parent.glob(".qualification-python-*"))


@pytest.mark.parametrize("fault", ["missing-venv", "outside-venv", "writable-parent", "oversized"])
def test_copy_refuses_unbounded_or_unowned_destination(
    tmp_path: Path, fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, python, source = _fixture(tmp_path)
    if fault == "missing-venv":
        (root / "pyvenv.cfg").unlink()
    elif fault == "outside-venv":
        python = source
    elif fault == "writable-parent":
        python.parent.chmod(0o777)
    else:
        monkeypatch.setattr(module, "_MAX_INTERPRETER_BYTES", 1)
    with pytest.raises(ValueError, match="qualification_interpreter_"):
        module.prepare_private_interpreter(python, environment_root=root)
    assert stat.S_IMODE(source.stat().st_mode) == 0o777
