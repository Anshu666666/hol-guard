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


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"st_mode": stat.S_IFIFO | 0o755}, "metadata_not_regular"),
        ({"st_mode": stat.S_IFREG | 0o644}, "metadata_not_executable"),
        ({"st_mode": stat.S_IFREG | 0o775}, "metadata_writable"),
        ({"st_uid": 1002}, "metadata_owner"),
        ({"st_nlink": 0}, "metadata_link_count"),
        ({"st_size": 0}, "metadata_size"),
        ({"st_size": identity.MAX_EXECUTABLE_BYTES + 1}, "metadata_size"),
    ],
)
def test_metadata_rejection_has_exact_original_subreason(monkeypatch, changes, reason):
    monkeypatch.setattr(identity.os, "geteuid", lambda: 1001, raising=False)
    metadata = {"st_mode": stat.S_IFREG | 0o755, "st_uid": 0, "st_nlink": 1, "st_size": 100}
    with pytest.raises(identity.ExecutableIdentityError) as failure:
        identity._admit(SimpleNamespace(**(metadata | changes)))
    assert failure.value.reason == reason
    assert str(failure.value) == "toolchain_executable_invalid"


@pytest.fixture
def executable(tmp_path):
    if sys.platform != "linux":
        pytest.skip("Linux-only executable identity collector")
    path = tmp_path / "private-executable-sentinel"
    path.write_bytes(b"the exact executable bytes")
    path.chmod(0o755)
    return path


def test_metadata_diagnostic_uses_original_lstat_without_open_or_second_observation(executable, monkeypatch):
    executable.chmod(0o775)
    original = Path.lstat
    observations = []

    def observe(path):
        value = original(path)
        observations.append(value)
        return value

    def forbidden_open(*_args, **_kwargs):
        pytest.fail("rejected metadata must not open or retry")

    monkeypatch.setattr(Path, "lstat", observe)
    monkeypatch.setattr(identity.os, "open", forbidden_open)
    with pytest.raises(identity.IdentityError) as failure:
        protocol._identity_stage(lambda: identity.executable_digest(executable), "python_executable_identity_failed")
    diagnostic = failure.value.diagnostic
    assert diagnostic is not None and len(observations) == 1
    assert diagnostic == {
        "reason": "metadata_writable",
        "phase": "path_before",
        "errno": None,
        "bytes_read": 0,
        "metadata": {"before": identity._metadata(observations[0])},
        "cleanup_failed": False,
    }
    assert str(executable) not in json.dumps(diagnostic)


@pytest.mark.parametrize("phase", ["open", "descriptor_before", "read", "descriptor_after", "path_after"])
def test_original_io_failure_records_finite_phase_errno_without_retry(executable, monkeypatch, phase):
    import errno

    original_error = OSError(errno.EIO, "/private/error-text-must-not-be-public")
    target, name = {
        "open": (identity.os, "open"),
        "descriptor_before": (identity.os, "fstat"),
        "read": (identity.os, "read"),
        "descriptor_after": (identity.os, "fstat"),
        "path_after": (Path, "lstat"),
    }[phase]
    original = getattr(target, name)
    calls = 0
    fail_at = 2 if phase in {"descriptor_after", "path_after"} else 1

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise original_error
        return original(*args, **kwargs)

    monkeypatch.setattr(target, name, fail)
    with pytest.raises(identity.ExecutableIdentityError) as failure:
        identity.executable_digest(executable)
    assert calls == fail_at and failure.value.__cause__ is original_error
    diagnostic = failure.value.diagnostic
    assert diagnostic is not None and diagnostic["reason"] == identity._IO_REASONS[phase]
    assert diagnostic["phase"] == phase and diagnostic["errno"] == errno.EIO
    assert diagnostic["bytes_read"] == (len(b"the exact executable bytes") if fail_at == 2 else 0)
    assert not diagnostic["cleanup_failed"] and "private/error-text" not in json.dumps(diagnostic)


def test_partial_read_then_error_keeps_exact_bytes_and_original_error(executable, monkeypatch):
    original = identity.os.read
    failure_error = OSError(5, "private read failure")
    calls = 0

    def read(descriptor, _count):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(descriptor, 4)
        raise failure_error

    monkeypatch.setattr(identity.os, "read", read)
    with pytest.raises(identity.ExecutableIdentityError) as failure:
        identity.executable_digest(executable)
    assert calls == 2 and failure.value.__cause__ is failure_error
    diagnostic = failure.value.diagnostic
    assert diagnostic is not None and diagnostic["bytes_read"] == 4
    assert diagnostic["reason"] == "read_failed" and set(diagnostic["metadata"]) == {"before", "opened"}


@pytest.mark.parametrize("read_failure", [False, True])
def test_close_failure_never_masks_original_read_failure_or_becomes_success(executable, monkeypatch, read_failure):
    original_close = identity.os.close
    read_error, close_error = OSError(5, "private read error"), OSError(9, "private close error")
    closed = []

    def close(descriptor):
        original_close(descriptor)
        closed.append(descriptor)
        raise close_error

    def read(*_args):
        raise read_error

    monkeypatch.setattr(identity.os, "close", close)
    if read_failure:
        monkeypatch.setattr(identity.os, "read", read)
    with pytest.raises(identity.ExecutableIdentityError) as failure:
        identity.executable_digest(executable)
    assert len(closed) == 1 and failure.value.__cause__ is (read_error if read_failure else close_error)
    diagnostic = failure.value.diagnostic
    assert diagnostic is not None and diagnostic["cleanup_failed"]
    assert diagnostic["reason"] == ("read_failed" if read_failure else "descriptor_close_failed")
    with pytest.raises(OSError):
        os.fstat(closed[0])


def test_resolver_failure_is_retained_without_retry_or_path_disclosure(tmp_path, monkeypatch):
    error = OSError(13, "private resolved toolchain path")
    calls = []

    def resolve(path, **_kwargs):
        calls.append(path)
        raise error

    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(identity.ExecutableIdentityError) as failure:
        identity.resolved_executable_digest(tmp_path / "python")
    assert len(calls) == 1 and failure.value.__cause__ is error
    assert failure.value.diagnostic == {
        "reason": "path_resolution_failed",
        "phase": "resolve",
        "errno": 13,
        "bytes_read": 0,
        "metadata": {},
        "cleanup_failed": False,
    }


def test_actual_admission_failure_is_retained_privately_and_projected_finitely(executable, tmp_path, monkeypatch):
    from scripts import scanner_pilot_ci as ci
    from scripts import scanner_pilot_public as public
    from scripts import scanner_pilot_worker as worker
    from scripts import secret_scan_benchmark_fixtures as fixtures
    from tests.scanner_pilot_fixtures import SOURCE_SHA

    monkeypatch.setitem(sys.modules, "secret_scan_benchmark_fixtures", fixtures)
    executable.chmod(0o775)

    def fail(*_args):
        return protocol._identity_stage(
            lambda: identity.executable_digest(executable), "python_executable_identity_failed"
        )

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
    value = json.loads((private / "worker.json").read_text())
    assert value["identity_failure"]["metadata"]["before"]["mode"] == stat.S_IFREG | 0o775
    assert value["identity_failure"]["reason"] == "metadata_writable"
    result = public.projection(
        tuple((path.name, path.read_bytes()) for path in private.iterdir()),
        source_sha=SOURCE_SHA,
        case="working_provider_large",
        run=0,
        selection="smoke",
    )
    assert result["worker_failure"] == "python_executable_identity_failed"
    assert result["identity_failure_reason"] == "metadata_writable" and result["planned"] == 24
    assert all(row["status"] == "unoffered" for row in result["observations"])
    assert not result["collection_complete"] and not result["installed_qualified"]
    assert "identity_failure" not in result and "metadata" not in result
    assert str(executable) not in json.dumps(result)
