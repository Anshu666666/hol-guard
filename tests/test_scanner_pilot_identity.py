from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import scanner_pilot_identity as identity
from scripts import scanner_pilot_protocol as protocol


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source experiment")
def test_cargo_style_hardlinked_executable_has_exact_digest_without_relaxing_archive_reader(tmp_path):
    from scripts.native_slo_evidence_files import read_file

    first, second = tmp_path / "deps-executable", tmp_path / "release-executable"
    data = b"synthetic executable bytes"
    first.write_bytes(data)
    first.chmod(0o755)
    os.link(first, second)
    assert first.stat().st_nlink == 2
    with pytest.raises(ValueError, match="archive_file_invalid"):
        read_file(second, 1024)
    assert identity.executable_digest(second) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("owner", [0, 1001])
def test_root_owned_hosted_python_and_runner_owned_pilot_are_admitted(monkeypatch, owner):
    monkeypatch.setattr(identity.os, "geteuid", lambda: 1001, raising=False)
    identity._admit(SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=owner, st_nlink=2, st_size=100))


@pytest.mark.parametrize(
    "changes",
    [
        {"st_uid": 1002},
        {"st_mode": stat.S_IFREG | 0o775},
        {"st_mode": stat.S_IFREG | 0o644},
        {"st_mode": stat.S_IFIFO | 0o755},
        {"st_nlink": 0},
        {"st_size": 0},
        {"st_size": identity.MAX_EXECUTABLE_BYTES + 1},
    ],
)
def test_invalid_toolchain_metadata_is_rejected(monkeypatch, changes):
    monkeypatch.setattr(identity.os, "geteuid", lambda: 1001, raising=False)
    metadata = {"st_mode": stat.S_IFREG | 0o755, "st_uid": 0, "st_nlink": 1, "st_size": 100}
    with pytest.raises(ValueError, match="toolchain_executable_invalid"):
        identity._admit(SimpleNamespace(**(metadata | changes)))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only descriptor identity")
def test_path_replacement_during_read_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "executable"
    replacement = tmp_path / "replacement"
    for item in (path, replacement):
        item.write_bytes(b"same bytes do not establish same executable inode")
        item.chmod(0o755)
    original = identity.os.read
    changed = False

    def replacing_read(descriptor, count):
        nonlocal changed
        data = original(descriptor, count)
        if not changed:
            changed = True
            replacement.replace(path)
        return data

    monkeypatch.setattr(identity.os, "read", replacing_read)
    with pytest.raises(ValueError, match="toolchain_executable_changed"):
        identity.executable_digest(path)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only descriptor identity")
def test_unresolved_executable_symlink_is_rejected(tmp_path):
    target, alias = tmp_path / "target", tmp_path / "alias"
    target.write_bytes(b"executable")
    target.chmod(0o755)
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="toolchain_executable_unresolved"):
        identity.executable_digest(alias)


@pytest.mark.parametrize(
    "stage", ["dependency_identity_failed", "python_executable_identity_failed", "native_executable_identity_failed"]
)
def test_identity_stage_hides_unbounded_original_error(stage):
    original = OSError("private toolchain path must not become a public diagnostic")

    def fail():
        raise original

    with pytest.raises(identity.IdentityError) as failure:
        protocol._identity_stage(fail, stage)
    assert str(failure.value) == stage and failure.value.__cause__ is original


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only collector")
@pytest.mark.parametrize(
    "stage",
    [
        "source_identity_failed",
        "dependency_identity_failed",
        "python_executable_identity_failed",
        "native_executable_identity_failed",
    ],
)
def test_identity_failure_retains_exact_unoffered_denominator(tmp_path, monkeypatch, stage):
    from scripts import scanner_pilot_ci as ci
    from scripts import scanner_pilot_public as public
    from scripts import scanner_pilot_worker as worker
    from scripts import secret_scan_benchmark_fixtures as fixtures
    from tests.scanner_pilot_fixtures import SOURCE_SHA

    monkeypatch.setitem(sys.modules, "secret_scan_benchmark_fixtures", fixtures)

    def fail(*_args):
        raise identity.IdentityError(stage)

    monkeypatch.setattr(worker, "identities", fail)
    output = tmp_path / "evidence"
    ci.initialize(output, source_sha=SOURCE_SHA, case="working_provider_large", run=0, selection="smoke")
    private = output / "private_samples"
    assert not worker.collect(
        Path(__file__).resolve().parents[1],
        tmp_path / "unused",
        private,
        expected_source=SOURCE_SHA,
        lock=tmp_path / "test.lock",
    )
    assert json.loads((private / "worker.json").read_text())["failure"] == stage
    files = [(path.name, path.read_bytes()) for path in private.iterdir()]
    result = public.projection(
        tuple(files), source_sha=SOURCE_SHA, case="working_provider_large", run=0, selection="smoke"
    )
    assert result["worker_failure"] == stage and result["planned"] == 24
    assert not result["collection_complete"] and not result["installed_qualified"]
    assert all(row["status"] == "unoffered" and row["cpu_ms"] is None for row in result["observations"])
