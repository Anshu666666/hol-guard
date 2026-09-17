"""Private, bounded numeric checkpoints; partial evidence never qualifies a run."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, TypedDict

from scripts.native_slo_evidence_files import _file, _stat, atomic_exclusive, directory, fingerprint, read_file

SCHEMA = "hol-guard.native-numeric-journal.v1"
MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 300_000
MAX_RECORD_BYTES = 4096
MAX_BATCH = 100_000
_SERIES = re.compile(r"(?:DAEMON_INGRESS|NATIVE_CLIENT|DAEMON_PROCESS|INSTALLED_LAUNCHER)\.[A-Za-z0-9_.-]{1,96}\Z")


class _RecoveredBatch(TypedDict):
    series: str
    offered: int
    observed: int
    status: str


class NumericRecovery(TypedDict):
    schema: str
    series: dict[str, list[float]]
    batches: list[_RecoveredBatch]
    collection_complete: bool
    truncated_tail: bool
    qualification_complete: bool


def _require(value: bool) -> None:
    if not value:
        raise ValueError("qualification_numeric_journal_invalid")


def _values(values: Sequence[float]) -> list[float]:
    _require(1 <= len(values) <= 100)
    _require(all(type(value) in {int, float} and math.isfinite(value) and value >= 0 for value in values))
    return [float(value) for value in values]


class NumericBatch:
    def __init__(self, journal: NumericJournal, identifier: int, series: str, count: int) -> None:
        self.journal = journal
        self.identifier = identifier
        self.series = series
        self.expected = count
        self.observed = 0
        self.closed = False

    def record(self, values: Sequence[float]) -> None:
        """Call only after the measured operation's stop timestamp was captured."""
        numbers = _values(values)
        _require(not self.closed and self.observed + len(numbers) <= self.expected)
        self.journal._append({"kind": "observed", "batch": self.identifier, "offset": self.observed, "values": numbers})
        self.observed += len(numbers)
        self.journal.values.setdefault(self.series, []).extend(numbers)


class NumericJournal:
    """Exclusive private file, flushed and fsynced before another operation starts.

    Offered batches identify missing observations after a hard interruption.
    Observations remain unvalidated until their batch's terminal record. The
    original JSON aggregate is still emitted only after complete collection.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.values: dict[str, list[float]] = {}
        self.size = 0
        self.records = 0
        self.batches = 0
        self.offered = 0
        self.pending = 0
        self.complete = False
        self.failed = False
        self.io_failed = False
        self._stack = ExitStack()
        self._stream: BinaryIO | None = None

    def __enter__(self) -> NumericJournal:
        try:
            # This creates a private Windows DACL as well as POSIX mode 0600.
            atomic_exclusive(self.path, b"")
            parent, directory_fd = self._stack.enter_context(directory(self.path.parent))
            before = _stat(parent, directory_fd, self.path.name)
            _file(before, 0, private=True)
            descriptor = os.open(
                parent / self.path.name if directory_fd is None else self.path.name,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
                dir_fd=directory_fd,
            )
            try:
                _require(fingerprint(os.fstat(descriptor)) == fingerprint(before))
                self._stream = self._stack.enter_context(os.fdopen(descriptor, "wb"))
            except BaseException:
                os.close(descriptor)
                raise
            self._append({"kind": "header", "schema": SCHEMA, "qualification_complete": False})
            return self
        except BaseException:
            self._stack.close()
            raise

    def __exit__(
        self, _kind: type[BaseException] | None, _error: BaseException | None, _tb: TracebackType | None
    ) -> None:
        self._stack.close()
        self._stream = None

    def _append(self, record: Mapping[str, object]) -> None:
        raw = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode() + b"\n"
        reserve = MAX_RECORD_BYTES if record.get("kind") == "observed" else 0
        _require(
            self._stream is not None
            and not self.complete
            and not self.io_failed
            and len(raw) <= MAX_RECORD_BYTES
            and self.size + len(raw) + reserve <= MAX_BYTES
            and self.records + bool(reserve) < MAX_RECORDS
        )
        assert self._stream is not None
        try:
            if self._stream.write(raw) != len(raw):
                raise RuntimeError("qualification_numeric_journal_short_write")
            self._stream.flush()
            os.fsync(self._stream.fileno())
        except BaseException:
            # The final line may have reached disk despite an I/O error. Never
            # append contradictory counts after an uncertain write or fsync.
            self.io_failed = True
            raise
        self.size += len(raw)
        self.records += 1

    @contextmanager
    def batch(self, series: str, count: int) -> Iterator[NumericBatch]:
        _require(_SERIES.fullmatch(series) is not None and type(count) is int and 1 <= count <= MAX_BATCH)
        _require(self.pending == 0 and self.offered + count <= MAX_RECORDS)
        _require(self.size + 2 * MAX_RECORD_BYTES <= MAX_BYTES and self.records + 2 <= MAX_RECORDS)
        self.batches += 1
        self.offered += count
        batch = NumericBatch(self, self.batches, series, count)
        self._append({"kind": "offered", "batch": batch.identifier, "series": series, "count": count})
        self.pending += 1
        try:
            yield batch
            _require(batch.observed == count)
        except BaseException as error:
            self.failed = True
            if not self.io_failed:
                self._append(
                    {
                        "kind": "failed",
                        "batch": batch.identifier,
                        "observed": batch.observed,
                        "reason": "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "error",
                    }
                )
            raise
        else:
            self._append({"kind": "validated", "batch": batch.identifier, "observed": batch.observed})
        finally:
            batch.closed = True
            self.pending -= 1

    def record(self, series: str, values: Sequence[float]) -> None:
        with self.batch(series, len(values)) as batch:
            batch.record(values)

    def finish(self, raw: Mapping[str, list[float]]) -> None:
        _require(self.pending == 0 and not self.failed and dict(raw) == self.values)
        self._append({"kind": "collection_complete", "series_order": list(raw)})
        self.complete = True
        # Sibling aggregate publication on Windows needs to release every
        # retained parent barrier before its atomic rename can proceed.
        self._stack.close()
        self._stream = None


def recover_numeric_journal(path: Path) -> NumericRecovery:
    """Recover only complete bounded lines, explicitly retaining unknown outcomes."""
    data = read_file(path, MAX_BYTES, private=True)
    lines = data.splitlines(keepends=True)
    _require(len(lines) <= MAX_RECORDS)
    values: dict[str, list[float]] = {}
    batches: dict[int, _RecoveredBatch] = {}
    offered = 0
    complete = False
    truncated = False
    for index, line in enumerate(lines):
        _require(len(line) <= MAX_RECORD_BYTES and not complete)
        if not line.endswith(b"\n"):
            _require(index == len(lines) - 1)
            truncated = True
            break
        record = json.loads(line)
        _require(isinstance(record, dict))
        kind = record.get("kind")
        if index == 0:
            _require(record == {"kind": "header", "schema": SCHEMA, "qualification_complete": False})
        elif kind == "offered":
            _require(set(record) == {"kind", "batch", "series", "count"})
            identifier, series, count = record["batch"], record["series"], record["count"]
            _require(type(identifier) is int and identifier == len(batches) + 1)
            _require(isinstance(series, str) and _SERIES.fullmatch(series) is not None)
            _require(type(count) is int and 1 <= count <= MAX_BATCH)
            offered += count
            _require(offered <= MAX_RECORDS)
            batches[identifier] = {"series": series, "offered": count, "observed": 0, "status": "incomplete"}
            values.setdefault(series, [])
        elif kind in {"observed", "failed", "validated"}:
            identifier = record.get("batch")
            _require(type(identifier) is int and identifier in batches)
            batch = batches[identifier]
            _require(batch["status"] == "incomplete")
            if kind == "observed":
                _require(set(record) == {"kind", "batch", "offset", "values"})
                _require(type(record["offset"]) is int and record["offset"] == batch["observed"])
                _require(isinstance(record["values"], list))
                numbers = _values(record["values"])
                observed = batch["observed"] + len(numbers)
                _require(observed <= batch["offered"])
                values[batch["series"]].extend(numbers)
                batch["observed"] = observed
            else:
                _require(
                    set(record)
                    == ({"kind", "batch", "observed", "reason"} if kind == "failed" else {"kind", "batch", "observed"})
                )
                _require(type(record["observed"]) is int and record["observed"] == batch["observed"])
                _require(kind != "validated" or batch["observed"] == batch["offered"])
                _require(kind != "failed" or record["reason"] in {"error", "interrupted"})
                batch["status"] = kind
        elif kind == "collection_complete":
            _require(set(record) == {"kind", "series_order"})
            order = record["series_order"]
            _require(isinstance(order, list) and all(isinstance(key, str) for key in order))
            _require(len(order) == len(values) and set(order) == set(values))
            _require(all(batch["status"] == "validated" for batch in batches.values()))
            values = {key: values[key] for key in order}
            complete = True
        else:
            _require(False)
    return {
        "schema": SCHEMA,
        "series": values,
        "batches": list(batches.values()),
        "collection_complete": complete and not truncated,
        "truncated_tail": truncated,
        "qualification_complete": False,
    }
