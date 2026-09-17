from __future__ import annotations

import json
import os

import pytest

from scripts import native_client_profile_records as records
from tests.native_client_profile_support import record


def test_valid_record_keeps_missing_and_inclusive_phase_facts():
    value = record()
    value["phases"]["discovery"] = {"calls": 0, "succeeded": 0, "nanoseconds": None}
    value["socket_count_complete"] = False
    assert records.decode_record(json.dumps(value).encode() + b"\n") == value


@pytest.mark.parametrize("change", ["extra", "bool", "phase", "missing", "success", "digest", "sequence", "float"])
def test_record_rejects_forged_or_unbounded_metadata(change):
    value = record()
    if change == "extra":
        value["path"] = "/private/fixture"
    elif change == "bool":
        value["socket_opened"] = True
    elif change == "phase":
        value["phases"]["unmeasured"] = value["phases"].pop("discovery")
    elif change == "missing":
        value["phases"]["discovery"]["nanoseconds"] = None
    elif change == "success":
        value["phases"]["discovery"]["succeeded"] = 2
    elif change == "digest":
        value["request_sha256"] = "bad"
    elif change == "sequence":
        value["sequence"] = 1025
    else:
        value["helper_request_nanoseconds"] = float("nan")
    with pytest.raises(ValueError, match="native_client_profile_invalid"):
        records.validate_record(value)


@pytest.mark.parametrize("line", [b'{"schema":1,"schema":2}\n', b"{}", b" " * 4096 + b"\n"])
def test_wire_bounds_and_duplicate_keys(line):
    with pytest.raises(ValueError):
        records.decode_record(line)


def test_journal_private_exclusive_durable_and_bounded(tmp_path, monkeypatch):
    path = tmp_path / "records.jsonl"
    tmp_path.chmod(0o700)
    monkeypatch.setattr(records, "MAX_RECORDS", 2)
    with records.Journal(path) as journal:
        journal.append({"number": 1})
        journal.append({"number": 2})
        assert path.read_bytes().splitlines() == [b'{"number":1}', b'{"number":2}']
        with pytest.raises(ValueError):
            journal.append({"number": 3})
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    before = path.read_bytes()
    with pytest.raises((ValueError, OSError)), records.Journal(path):
        pytest.fail("must not clobber")
    assert path.read_bytes() == before


def test_journal_write_failure_is_sticky(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    with records.Journal(tmp_path / "records.jsonl") as journal:
        monkeypatch.setattr(records.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("synthetic")))
        with pytest.raises(OSError):
            journal.append({"offered": 1})
        with pytest.raises(ValueError):
            journal.append({"offered": 2})
        assert journal.failed
