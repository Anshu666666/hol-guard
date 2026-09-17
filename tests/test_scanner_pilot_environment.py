"""Setup correctness only: no timed scanner work or hosted-toolchain mutation."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
import sys
import tempfile
import venv
from pathlib import Path

import pytest

from scripts import scanner_pilot_environment as module
from scripts.native_slo_evidence_format import canonical, digest
from scripts.scanner_pilot_identity import ExecutableIdentityError, executable_digest
from scripts.scanner_pilot_public import projection
from tests.scanner_pilot_fixtures import SOURCE_SHA, interpreter_record, snapshot


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only scanner experiment setup")
def test_actual_private_copy_preserves_runtime_stdlib_config_and_shared_source(tmp_path):
    # Own both copies and clean them immediately; never chmod the host binary.
    with tempfile.TemporaryDirectory(dir=tmp_path) as temporary:
        base = Path(temporary)
        root = (base / "environment").resolve()
        venv.EnvBuilder(with_pip=False, symlinks=True).create(root)
        python = root / "bin/python"
        source = base / "owned-shared" / "bin/python"
        source.parent.mkdir(parents=True)
        (source.parent.parent / "lib").symlink_to(Path(sys.base_prefix) / "lib", target_is_directory=True)
        config = (root / "pyvenv.cfg").read_text().splitlines()
        (root / "pyvenv.cfg").write_text(
            "\n".join(f"home = {source.parent}" if line.startswith("home = ") else line for line in config) + "\n"
        )
        shutil.copyfile(python.resolve(), source)
        source.chmod(0o777)
        python.unlink()
        python.symlink_to(source)
        metadata = source.stat()
        with pytest.raises(ExecutableIdentityError) as rejected:
            executable_digest(source)
        assert rejected.value.reason == "metadata_writable"
        private = base / "private"
        private.mkdir(mode=0o700)
        config = (root / "pyvenv.cfg").read_bytes()
        retained = (
            root / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages/retained.txt"
        )
        retained.write_bytes(b"locked environment content is unchanged")
        record = module.prepare(root, private)
        assert not python.is_symlink() and stat.S_IMODE(python.stat().st_mode) == 0o700
        assert record["copy"]["source_sha256"] == record["copy"]["copy_sha256"] == executable_digest(python)
        assert record["copy"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        current = source.stat()
        assert (current.st_ino, current.st_mode, current.st_size, current.st_mtime_ns, current.st_ctime_ns) == (
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        assert record["runtime_before"] == record["runtime_after"]
        assert record["runtime_after"]["prefix"] == str(root)
        assert (root / "pyvenv.cfg").read_bytes() == config
        assert retained.read_bytes() == b"locked environment content is unchanged"
        assert json.loads((private / "interpreter.json").read_text()) == record


@pytest.mark.parametrize("change", ["digest", "copy_digest", "private_copy", "mode", "bytes", "stdlib", "config"])
def test_copy_record_cannot_claim_changed_interpreter_runtime_or_admission(change):
    record = copy.deepcopy(interpreter_record())
    expected = "b" * 64
    if change == "digest":
        expected = "a" * 64
    elif change == "copy_digest":
        record["copy"]["copy_sha256"] = "a" * 64
    elif change == "private_copy":
        record["copy"]["private_copy"] = False
    elif change == "mode":
        record["copy"]["copy"]["mode"] = 0o777
    elif change == "bytes":
        record["copy"]["bytes"] = True
    else:
        record["runtime_after"]["stdlib" if change == "stdlib" else "config_sha256"] = "changed"
    with pytest.raises(ValueError):
        module.verify_record(record, expected)


def _public(values):
    return projection(
        tuple((name, canonical(value)) for name, value in values.items()),
        source_sha=SOURCE_SHA,
        case="working_provider_large",
        run=0,
        selection="smoke",
    )


def test_public_setup_commitment_binds_encrypted_record_without_projecting_private_paths():
    values = snapshot(selection="smoke")
    record = interpreter_record()
    values["interpreter.json"] = record
    values["worker.json"]["interpreter_setup_sha256"] = digest(canonical(record))
    public = _public(values)
    assert public["collection_complete"] and not public["installed_qualified"]
    assert public["interpreter_setup_sha256"] == digest(canonical(record))
    assert "/private" not in json.dumps(public) and "runtime_before" not in json.dumps(public)


@pytest.mark.parametrize("change", ["delete", "replace", "source", "wrong_commitment", "delete_both"])
def test_missing_or_changed_required_setup_proof_cannot_be_projected_as_complete(change):
    values = snapshot(selection="smoke")
    values["interpreter.json"] = interpreter_record()
    values["worker.json"]["interpreter_setup_sha256"] = digest(canonical(values["interpreter.json"]))
    if change in {"delete", "delete_both"}:
        del values["interpreter.json"]
        if change == "delete_both":
            del values["worker.json"]["interpreter_setup_sha256"]
    elif change == "replace":
        values["interpreter.json"]["copy"]["bytes"] = 101
    elif change == "source":
        values["source.json"]["python_sha256"] = "a" * 64
    else:
        values["worker.json"]["interpreter_setup_sha256"] = "d" * 64
    with pytest.raises(ValueError):
        _public(values)


def test_copy_provenance_can_be_retained_after_later_preoffer_failure():
    values = snapshot(selection="smoke")
    private = {
        "plan.json": values["plan.json"],
        "interpreter.json": interpreter_record(),
        "worker.json": {"failure": "native_executable_identity_failed", "identity_verified_after": False},
    }
    result = _public(private)
    assert result["source"] is None and result["planned"] == 24
    assert all(row["status"] == "unoffered" for row in result["observations"])
    assert not result["collection_complete"] and not result["installed_qualified"]


@pytest.mark.parametrize("absent", [False, True])
def test_complete_public_identity_requires_its_setup_commitment(absent):
    from scripts.scanner_pilot_public import validate_report

    result = _public(snapshot(selection="smoke"))
    if absent:
        del result["interpreter_setup_sha256"]
    else:
        result["interpreter_setup_sha256"] = None
    with pytest.raises(ValueError):
        validate_report(result)
