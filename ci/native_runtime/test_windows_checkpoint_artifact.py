"""Synthetic-only controls for pinned artifact download and safe extraction."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import urllib.error
import zipfile
from email.message import Message
from types import SimpleNamespace

import pytest

from ci.native_runtime import windows_checkpoint_artifact as artifact
from ci.native_runtime import windows_checkpoint_identity as identity


def archive_bytes(entries=None):
    contents = entries or [(name, b"fixture") for name in sorted(artifact.EXPECTED_NAMES)]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in contents:
            zipped.writestr(name, data)
    return buffer.getvalue()


def pin(monkeypatch, archive):
    monkeypatch.setattr(artifact, "ZIP_BYTES", len(archive))
    monkeypatch.setattr(artifact, "ZIP_SHA256", hashlib.sha256(archive).hexdigest())


class Response(io.BytesIO):
    pass


class Opener:
    def __init__(self, archive, location="https://fixture.blob.core.windows.net/a?private-signed-query"):
        self.archive = archive
        self.location = location
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        assert timeout == 10
        if len(self.requests) == 1:
            return Response(
                json.dumps(
                    {
                        "id": artifact.ARTIFACT_ID,
                        "size_in_bytes": artifact.ZIP_BYTES,
                        "digest": "sha256:" + artifact.ZIP_SHA256,
                        "expired": False,
                        "workflow_run": {"id": artifact.RUN_ID, "head_sha": artifact.HEAD_SHA},
                    }
                ).encode()
            )
        if len(self.requests) == 2:
            headers = Message()
            headers["Location"] = self.location
            raise urllib.error.HTTPError(request.full_url, 302, "redirect", headers, None)
        return Response(self.archive)


def test_authenticated_redirect_is_not_followed(monkeypatch):
    archive = archive_bytes()
    pin(monkeypatch, archive)
    opener = Opener(archive)
    monkeypatch.setattr(artifact.urllib.request, "build_opener", lambda handler: opener)
    downloaded, report = artifact.fetch_original_archive("private-token")
    assert downloaded == archive and len(opener.requests) == 3
    assert all(request.get_header("Authorization") == "Bearer private-token" for request in opener.requests[:2])
    assert opener.requests[2].get_header("Authorization") is None
    assert "private-token" not in json.dumps(report)
    assert "private-signed-query" not in json.dumps(report)
    assert artifact.NoRedirect().redirect_request(None, None, None, None, None, None) is None


@pytest.mark.parametrize(
    "location",
    [
        "http://fixture.blob.core.windows.net/a",
        "https://user:pass@fixture.blob.core.windows.net/a",
        "https://fixture.blob.core.windows.net:444/a",
        "https://elsewhere.invalid/a",
    ],
)
def test_unadmitted_storage_origin_is_not_requested(monkeypatch, location):
    archive = archive_bytes()
    pin(monkeypatch, archive)
    opener = Opener(archive, location)
    monkeypatch.setattr(artifact.urllib.request, "build_opener", lambda handler: opener)
    with pytest.raises(RuntimeError, match="artifact_storage_origin"):
        artifact.fetch_original_archive("private-token")
    assert len(opener.requests) == 2


def test_exact_members_extract_once_with_original_hashes(monkeypatch, tmp_path):
    archive = archive_bytes()
    pin(monkeypatch, archive)
    members = artifact.extract_original_files(archive, tmp_path)
    assert len(members) == 4
    assert {row["output_name"] for row in members} == artifact.EXPECTED_NAMES
    assert all((tmp_path / row["output_name"]).read_bytes() == b"fixture" for row in members)
    with pytest.raises(FileExistsError):
        artifact.extract_original_files(archive, tmp_path)


@pytest.mark.parametrize(
    "bad_name",
    ["../native-default-auto.json", "/native-default-auto.json", "x/native-default-auto.json"],
)
def test_unsafe_or_unexpected_member_paths_are_refused(monkeypatch, tmp_path, bad_name):
    entries = [(name, b"fixture") for name in artifact.EXPECTED_NAMES if name != "native-default-auto.json"]
    archive = archive_bytes([*entries, (bad_name, b"private")])
    pin(monkeypatch, archive)
    with pytest.raises(RuntimeError):
        artifact.extract_original_files(archive, tmp_path)
    assert not (tmp_path.parent / "native-default-auto.json").exists()


def test_symlink_member_is_refused(monkeypatch, tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        for name in sorted(artifact.EXPECTED_NAMES):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(info, "private-target")
    archive = buffer.getvalue()
    pin(monkeypatch, archive)
    with pytest.raises(RuntimeError, match="artifact_member_kind"):
        artifact.extract_original_files(archive, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_wrong_archive_digest_is_refused_before_any_extraction(monkeypatch, tmp_path):
    archive = archive_bytes()
    pin(monkeypatch, archive)
    with pytest.raises(RuntimeError, match="artifact_archive_digest"):
        artifact.extract_original_files(archive[:-1] + b"x", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_bounded_reader_refuses_excess_and_expired_deadline():
    with pytest.raises(RuntimeError, match="artifact_download_size"):
        artifact.bounded_read(Response(b"12345"), 4, float("inf"))
    with pytest.raises(RuntimeError, match="artifact_download_deadline"):
        artifact.bounded_read(Response(b"12345"), 4, 0)


@pytest.mark.parametrize("partial", [None, b"partial-install-output"])
def test_mandatory_install_timeout_retains_partial_output_and_same_exception(tmp_path, monkeypatch, partial):
    source = tmp_path / "source"
    executable = source / ".venv" / "Scripts" / "python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"synthetic interpreter")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    uv = tmp_path / "uv.exe"
    uv.write_bytes(b"synthetic uv")
    monkeypatch.setattr(identity.sys, "executable", str(executable))
    monkeypatch.setattr(identity, "original_wheel_bytes", lambda _root: b"synthetic wheel")
    failure = subprocess.TimeoutExpired(["synthetic"], 180, output=partial, stderr=partial)
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        if len(commands) == 1:
            return SimpleNamespace(stdout=b"uv 0.9.26\n")
        raise failure

    monkeypatch.setattr(identity.subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        identity.install_original_wheel(source, artifacts, uv)
    assert caught.value is failure
    assert len(commands) == 2
    assert commands[1][1]["timeout"] == 180
    assert "--require-hashes" in commands[1][0]
    binding = json.loads((artifacts / "native-wheel-install-binding.json").read_bytes())
    assert binding["passed"] is False and binding["timed_out"] is True
    assert binding["failure_type"] == "TimeoutExpired"
    for name in ("stdout", "stderr"):
        state = binding["timeout_" + name]
        assert state["explicit_absent"] is (partial is None)
        assert state["available"] is (partial is not None)
        file = artifacts / f"native-wheel-install-{name}.log"
        if partial is None:
            assert not file.exists()
        else:
            assert file.read_bytes() == partial
            assert state["retained_bytes"] == len(partial)
