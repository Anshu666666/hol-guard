from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from scripts import native_slo_numeric_journal as module
from scripts.native_slo_numeric_journal import NumericJournal, recover_numeric_journal

SERIES = "DAEMON_INGRESS.claude-code.PostToolUse"


def test_complete_journal_conserves_names_values_order_and_remains_unqualified(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    expected = {"NATIVE_CLIENT.cold_oneshot": [3.0], SERIES: [2.0, 0.0, 2.0]}
    with NumericJournal(path) as journal:
        journal.record(SERIES, [2.0, 0.0])
        journal.record("NATIVE_CLIENT.cold_oneshot", [3.0])
        journal.record(SERIES, [2.0])
        journal.finish(expected)
        assert journal._stream is None  # Release Windows parent barriers before publishing the aggregate.
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == expected
    assert list(recovered["series"]) == list(expected)
    assert recovered["collection_complete"] is True
    assert recovered["qualification_complete"] is False
    assert recovered["truncated_tail"] is False
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_failed_batch_retains_prefix_and_never_copies_private_exception(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        journal.record(SERIES, [1.0])
        with pytest.raises(RuntimeError, match="PRIVATE"), journal.batch(SERIES, 3) as batch:
            batch.record([2.0])
            raise RuntimeError("PRIVATE credential payload /home/customer/path")
        before = path.read_bytes()
        with pytest.raises(ValueError):
            batch.record([3.0])
        with pytest.raises(ValueError):
            journal.finish({SERIES: [1.0, 2.0]})
        assert path.read_bytes() == before
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {SERIES: [1.0, 2.0]}
    assert recovered["batches"][-1] == {"series": SERIES, "offered": 3, "observed": 1, "status": "failed"}
    assert recovered["collection_complete"] is False
    assert b"PRIVATE" not in before and b"customer" not in before and str(tmp_path).encode() not in before


def test_hard_process_exit_retains_fsynced_prefix_and_outstanding_offer(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    child = """
import os, sys
from pathlib import Path
from scripts.native_slo_numeric_journal import NumericJournal
with NumericJournal(Path(sys.argv[1])) as journal:
    journal.record('NATIVE_CLIENT.cold_oneshot', [7.0])
    with journal.batch('NATIVE_CLIENT.cold_oneshot', 3) as batch:
        batch.record([8.0])
        os._exit(17)
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 17
    assert result.stdout == result.stderr == b""
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {"NATIVE_CLIENT.cold_oneshot": [7.0, 8.0]}
    assert recovered["batches"][-1]["status"] == "incomplete"
    assert recovered["batches"][-1]["offered"] == 3
    assert recovered["batches"][-1]["observed"] == 1
    assert recovered["collection_complete"] is recovered["qualification_complete"] is False


def test_uncertain_fsync_does_not_append_contradictory_failure_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "numeric.jsonl"
    real_fsync = os.fsync
    calls = 0

    def fail_once(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("PRIVATE filesystem detail")
        real_fsync(descriptor)

    with NumericJournal(path) as journal:
        journal.record(SERIES, [1.0])
        with pytest.raises(OSError), journal.batch(SERIES, 2) as batch:
            monkeypatch.setattr(module.os, "fsync", fail_once)
            batch.record([2.0])
        assert calls == 1  # No attempted terminal after an uncertain append.
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {SERIES: [1.0, 2.0]}
    assert recovered["batches"][-1]["status"] == "incomplete"
    assert recovered["collection_complete"] is False


def test_partial_final_line_does_not_erase_complete_records(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        journal.record(SERIES, [1.0, 2.0])
    with path.open("ab") as stream:
        stream.write(b'{"kind":"observed",')
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {SERIES: [1.0, 2.0]}
    assert recovered["truncated_tail"] is True
    assert recovered["collection_complete"] is False


def test_short_append_is_poisoned_and_recovers_only_its_complete_prefix(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        journal.record(SERIES, [1.0])
        with pytest.raises(RuntimeError, match="short_write"), journal.batch(SERIES, 2) as batch:
            real_stream = journal._stream
            assert real_stream is not None

            class ShortWriter:
                def write(self, data: bytes) -> int:
                    assert real_stream is not None
                    written = real_stream.write(data[:7])
                    real_stream.flush()
                    return written

            journal._stream = cast(BinaryIO, cast(object, ShortWriter()))
            batch.record([2.0])
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {SERIES: [1.0]}
    assert recovered["batches"][-1]["status"] == "incomplete"
    assert recovered["truncated_tail"] is True


@pytest.mark.parametrize("value", [True, -1.0, float("nan"), float("inf"), "PRIVATE"])
def test_invalid_numeric_values_are_not_written(tmp_path: Path, value: object) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal, pytest.raises(ValueError):
        journal.record(SERIES, [cast(float, value)])
    assert recover_numeric_journal(path)["series"] == {SERIES: []}
    assert b"PRIVATE" not in path.read_bytes()


def test_bounded_batches_and_record_capacity_keep_failed_offer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        with pytest.raises(ValueError), journal.batch(SERIES, module.MAX_BATCH + 1):
            pytest.fail("invalid batch was offered")
        with pytest.raises(ValueError), journal.batch(SERIES, 2) as batch:
            monkeypatch.setattr(module, "MAX_BYTES", journal.size + module.MAX_RECORD_BYTES)
            batch.record([1.0])
    assert recover_numeric_journal(path)["batches"][-1]["status"] == "failed"


def test_existing_file_is_never_replaced(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    path.write_bytes(b"private existing evidence")
    with pytest.raises(FileExistsError), NumericJournal(path):
        pytest.fail("existing evidence replaced")
    assert path.read_bytes() == b"private existing evidence"


def test_recovery_rejects_count_drift(tmp_path: Path) -> None:
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal:
        journal.record(SERIES, [1.0])
    lines = [json.loads(line) for line in path.read_bytes().splitlines()]
    lines[-1]["observed"] = 0
    path.write_text("".join(json.dumps(record) + "\n" for record in lines))
    with pytest.raises(ValueError):
        recover_numeric_journal(path)
