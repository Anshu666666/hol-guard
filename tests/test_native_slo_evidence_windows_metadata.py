from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_evidence_files as files
from scripts import native_slo_evidence_windows as windows
from scripts.native_slo_evidence_format import ArchiveError


def metadata(**changes):
    values = dict(
        st_dev=2**60 + 3,
        st_ino=2**120 + 5,
        st_mode=0o100600,
        st_size=0,
        st_mtime_ns=101,
        st_ctime_ns=202,
        st_nlink=1,
        st_file_attributes=0,
        st_uid=getattr(os, "geteuid", lambda: 0)(),
    )
    values.update(changes)
    return SimpleNamespace(**values)


def fake_handles(monkeypatch, observed):
    events = []

    def create(path, access, sharing, security, disposition, flags, template):
        events.append(("open", path, access, sharing, disposition, flags))
        return 711

    kernel = SimpleNamespace(CreateFileW=create)
    api = SimpleNamespace(
        _windows_dll=lambda name: kernel,
        _windows_close_handle=lambda _kernel, handle: events.append(("close-handle", handle)),
    )
    monkeypatch.setattr(windows, "_api", lambda: api)
    monkeypatch.setattr(windows, "_descriptor", lambda handle, flags: 712)
    monkeypatch.setattr(os, "fstat", lambda descriptor: observed)
    monkeypatch.setattr(os, "close", lambda descriptor: events.append(("close-descriptor", descriptor)))
    return events


def test_metadata_uses_attribute_only_nofollow_handle_and_preserves_every_field(monkeypatch):
    observed = metadata()
    events = fake_handles(monkeypatch, observed)
    assert windows.metadata_handle(Path("sample.json")) is observed
    assert events == [("open", "sample.json", 0x80, 0x7, 3, 0x02200000), ("close-descriptor", 712)]
    assert files.fingerprint(observed) == (2**60 + 3, 2**120 + 5, 0o100600, 0, 101, 202, 1)


def test_metadata_reparse_and_failed_descriptor_transfer_close_exact_owner(monkeypatch):
    events = fake_handles(monkeypatch, metadata(st_file_attributes=0x400))
    with pytest.raises(ArchiveError, match="archive_file_invalid"):
        windows.metadata_handle(Path("sample.json"))
    assert events[-1] == ("close-descriptor", 712)

    def fail(*args):
        raise OSError("transfer failed")

    monkeypatch.setattr(windows, "_descriptor", fail)
    with pytest.raises(OSError, match="transfer failed"):
        windows.metadata_handle(Path("sample.json"))
    assert events[-1] == ("close-handle", 711)


def test_path_metadata_does_not_compare_birthtime_domain_or_cached_direntry(monkeypatch, tmp_path):
    # CPython 3.12 lstat's ctime is birthtime, fstat's is ChangeTime. The
    # mismatch must be resolved by selecting one backend, never omitting ctime.
    changed = metadata()
    path_view = metadata(st_ctime_ns=100)
    assert files.fingerprint(path_view) != files.fingerprint(changed)
    monkeypatch.setattr(Path, "lstat", lambda *_args, **_kwargs: path_view)
    monkeypatch.setattr(windows, "metadata_handle", lambda _path: changed)
    assert files.fingerprint(files._stat(tmp_path, None, "sample.json")) == files.fingerprint(changed)

    def cached_stat(**kwargs):
        pytest.fail("Windows DirEntry metadata omits file identity and link count")

    @contextmanager
    def scan(_path):
        yield iter([SimpleNamespace(name="sample.json", stat=cached_stat)])

    monkeypatch.setattr(os, "scandir", scan)
    assert files._inventory(tmp_path, None) == {"sample.json": files.fingerprint(changed)}


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink"])
def test_no_fingerprint_field_is_discarded(field):
    original = metadata()
    assert files.fingerprint(original) != files.fingerprint(metadata(**{field: getattr(original, field) + 1}))


def test_windows_metadata_regression_runs_in_the_actual_experiment_matrix():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/native-claude-launcher-experiment.yml").read_text())
    job = workflow["jobs"]["paired-launchers"]
    assert any(item["runner"] == "windows-latest" for item in job["strategy"]["matrix"]["platform"])
    step = next(item for item in job["steps"] if item.get("name") == "Validate experiment contracts")
    assert "if" not in step
    assert "tests/test_native_slo_evidence_windows_metadata.py" in step["run"]


@pytest.mark.skipif(os.name != "nt", reason="actual Windows handle metadata and protected DACL required")
def test_windows_journals_inventory_and_archive_share_handle_identity(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from scripts import native_slo_evidence_archive as archive
    from scripts import native_slo_evidence_format as fmt
    from scripts.ci.native_claude_pilot_evidence import OutcomeJournal
    from scripts.native_slo_numeric_journal import NumericJournal

    samples = tmp_path / "samples"
    windows.create_directory(samples)
    numeric, outcome = samples / "numeric.jsonl", samples / "outcomes.jsonl"
    with NumericJournal(numeric) as journal:
        journal.record("INSTALLED_LAUNCHER.claude", [1.0])
    with OutcomeJournal(outcome) as journal:
        journal.append({"kind": "offered", "count": 1})
    expected = [(path.name, path.read_bytes()) for path in (numeric, outcome)]
    assert files.read_samples(samples) == expected
    for path in (numeric, outcome):
        with path.open("rb") as stream:
            assert files.fingerprint(windows.metadata_handle(path)) == files.fingerprint(os.fstat(stream.fileno()))

    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public, key, encrypted = tmp_path / "public.pem", tmp_path / "private.pem", tmp_path / "sealed.hge"
    public.write_bytes(public_pem)
    files.atomic_exclusive(key, private_pem)
    recipient = fmt.digest(
        private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert (
        archive.encrypt_samples(
            source=samples, output=encrypted, public_key=public, recipient_id=recipient, context={}
        )["files"]
        == 2
    )
    recovered = tmp_path / "recovered"
    archive.decrypt_samples(archive=encrypted, private_key=key, output=recovered)
    assert files.read_samples(recovered) == expected
