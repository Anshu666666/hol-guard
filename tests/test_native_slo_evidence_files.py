from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import native_slo_evidence_archive as archive
from scripts import native_slo_evidence_files as files
from scripts import native_slo_evidence_format as fmt


@pytest.mark.parametrize("kind", ["directory", "hardlink", "symlink", "unexpected", "fifo", "casefold"])
def test_reject_nonflat_or_aliased_source(tmp_path, kind):
    source = tmp_path / "samples"
    source.mkdir()
    sample = source / "sample.json"
    if kind == "directory":
        sample.mkdir()
    elif kind == "unexpected":
        (source / "sample.txt").write_text("private")
    elif kind == "fifo":
        if os.name == "nt":
            pytest.skip("POSIX FIFO")
        os.mkfifo(sample)
    elif kind == "casefold":
        sample.write_text("private")
        (source / "SAMPLE.json").write_text("private")
        if len(list(source.iterdir())) != 2:
            pytest.skip("case-insensitive filesystem")
    else:
        outside = tmp_path / "outside.json"
        outside.write_text("private")
        try:
            if kind == "hardlink":
                os.link(outside, sample)
            else:
                sample.symlink_to(outside)
        except OSError:
            pytest.skip("link privilege unavailable")
    with pytest.raises((fmt.ArchiveError, OSError)):
        files.read_samples(source)


def test_source_ancestor_and_missing_traversal_reject(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "x.json").write_text("private")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    with pytest.raises(fmt.ArchiveError, match="path"):
        files.read_samples(link)
    with pytest.raises(fmt.ArchiveError, match="path"):
        archive.encrypt_samples(
            source=tmp_path / "absent" / ".." / "missing",
            output=tmp_path / "out",
            public_key=tmp_path / "key",
            recipient_id="x",
            context={},
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX retained fd mutation injection")
@pytest.mark.parametrize("mutation", ["rewrite", "replace", "inventory", "directory"])
def test_source_changes_during_read_rejected(monkeypatch, tmp_path, mutation):
    source = tmp_path / "samples"
    source.mkdir()
    sample = source / "x.json"
    sample.write_bytes(b"1234")
    original = os.read
    changed = False

    def mutate(descriptor, maximum):
        nonlocal changed
        result = original(descriptor, maximum)
        if not changed:
            changed = True
            if mutation == "rewrite":
                sample.write_bytes(b"5678")
            elif mutation == "replace":
                sample.unlink()
                sample.write_bytes(b"1234")
            elif mutation == "inventory":
                (source / "new.json").write_bytes(b"new")
            else:
                source.rename(tmp_path / "moved")
                source.mkdir()
        return result

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises((fmt.ArchiveError, OSError)):
        files.read_samples(source)


def test_bounds_precede_source_reads(monkeypatch, tmp_path):
    source = tmp_path / "samples"
    source.mkdir()
    (source / "a.json").write_bytes(b"123")
    (source / "b.json").write_bytes(b"456")
    monkeypatch.setattr(files, "MAX_TOTAL_BYTES", 5)
    monkeypatch.setattr(files, "_read_child", lambda *a, **k: pytest.fail("oversize total read"))
    with pytest.raises(fmt.ArchiveError, match="bounds"):
        files.read_samples(source)


def test_count_and_file_size_caps(monkeypatch, tmp_path):
    source = tmp_path / "samples"
    source.mkdir()
    (source / "a.json").write_bytes(b"123")
    monkeypatch.setattr(files, "MAX_FILE_BYTES", 2)
    with pytest.raises(fmt.ArchiveError):
        files.read_samples(source)
    monkeypatch.setattr(files, "MAX_FILE_BYTES", 3)
    monkeypatch.setattr(files, "MAX_FILES", 0)
    with pytest.raises(fmt.ArchiveError, match="bounds"):
        files.read_samples(source)


def test_exclusive_atomic_output_and_recovery_never_overwrite(tmp_path):
    output = tmp_path / "cipher.hge"
    files.atomic_exclusive(output, b"first")
    with pytest.raises(FileExistsError):
        files.atomic_exclusive(output, b"second")
    assert output.read_bytes() == b"first"
    assert not list(tmp_path.glob(".evidence-*.tmp"))
    recovery = tmp_path / "recovery"
    recovery.mkdir()
    (recovery / "x.json").write_bytes(b"original")
    with pytest.raises(FileExistsError):
        files.recover_files(recovery, [("x.json", b"replace")])
    assert (recovery / "x.json").read_bytes() == b"original"


def test_private_key_rejects_public_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("covered by Windows DACL contract")
    key = tmp_path / "key.pem"
    key.write_bytes(b"private-placeholder")
    key.chmod(0o644)
    with pytest.raises(fmt.ArchiveError, match="not_private"):
        files.read_file(key, 1024, private=True)


def test_fixed_cli_errors_do_not_include_private_paths_payloads(tmp_path, capsys):
    source = tmp_path / "secret-directory-name"
    source.mkdir()
    (source / "secret-filename.txt").write_text("secret-payload-text")
    receipt = tmp_path / "receipt.json"
    status = archive.main(
        [
            "encrypt",
            "--source",
            str(source),
            "--output",
            str(tmp_path / "archive.hge"),
            "--public-key",
            str(tmp_path / "key.pem"),
            "--recipient-id",
            "0" * 64,
            "--receipt",
            str(receipt),
        ]
    )
    assert status == 1
    captured = capsys.readouterr()
    assert not captured.err
    assert "secret" not in captured.out and str(tmp_path) not in captured.out
    result = json.loads(receipt.read_text())
    assert result["status"] == "archive_failed" and result["archive_created"] is False
    assert result["reason"] == "archive_input_name_invalid"


def test_no_dependency_failure_receipt_and_empty_source_subprocess(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/native_slo_evidence_archive.py"
    for mode in ("failure", "empty"):
        receipt = tmp_path / f"{mode}.json"
        command = [sys.executable, "-I", "-S", str(script)]
        if mode == "failure":
            command += ["failure-receipt", "--receipt", str(receipt)]
        else:
            command += [
                "encrypt",
                "--source",
                str(tmp_path / "missing"),
                "--output",
                str(tmp_path / "archive.hge"),
                "--public-key",
                str(tmp_path / "missing.pem"),
                "--recipient-id",
                "0" * 64,
                "--receipt",
                str(receipt),
            ]
        result = subprocess.run(command, capture_output=True, check=False, text=True)
        assert result.returncode == (1 if mode == "failure" else 0), result.stderr
        assert not result.stderr
        payload = json.loads(receipt.read_text())
        assert payload["status"] == ("archive_failed" if mode == "failure" else "no_observations")
        assert payload["archive_created"] is False
