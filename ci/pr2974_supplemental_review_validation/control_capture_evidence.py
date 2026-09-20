"""Persist one immutable control contract and append every actual phase once."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

# Capture the observer syscall before test-scoped patches of the shared os module.
_OPEN = os.open

CAPTURE_BYTES = 16 * 1024 * 1024
RETENTION_SCHEMA = "pr2974-control-capture-retention.v1"
LOGICAL_SCHEMA = "hol-guard-native-controls-observation.v1"


def encode(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def names(target: Path) -> tuple[Path, Path]:
    assert target.suffix == ".json"
    return target.with_suffix(".contract.json"), target.with_suffix(".phases.jsonl")


def read_owned(path: Path, maximum: int = CAPTURE_BYTES) -> bytes:
    descriptor = _OPEN(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert 0 <= before.st_size <= maximum
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        )
        assert len(raw) == before.st_size
        return raw
    finally:
        os.close(descriptor)


class CaptureEvidence:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.contract_path, self.phases_path = names(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.pid = os.getpid()
        self.contract_object = None
        self.contract_raw = None
        self.contract_reference = None
        self.phase_count = 0
        self.phase_bytes = 0
        self.phase_hash = hashlib.sha256()
        self.finished = False
        descriptor = _OPEN(
            self.phases_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
        )
        try:
            info = os.fstat(descriptor)
            self.phase_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(descriptor)

    def save(self, value: dict, *, final: bool = False) -> None:
        assert os.getpid() == self.pid and not self.finished
        assert value["schema"] == LOGICAL_SCHEMA and "capture_retention" not in value
        contract = value["contract"]
        if self.contract_reference is None and contract is not None:
            raw = encode(contract)
            assert len(raw) <= CAPTURE_BYTES
            with self.contract_path.open("xb") as stream:
                assert stream.write(raw) == len(raw)
            assert read_owned(self.contract_path) == raw
            self.contract_object = contract
            self.contract_raw = raw
            self.contract_reference = {
                "file": self.contract_path.name, "bytes": len(raw), "sha256": digest(raw),
            }
        assert contract is self.contract_object
        reports = value["reports"]
        assert type(reports) is list and len(reports) >= self.phase_count
        for row in reports[self.phase_count:]:
            raw = encode(row)
            assert len(self.contract_raw or b"") + self.phase_bytes + len(raw) <= CAPTURE_BYTES
            descriptor = _OPEN(self.phases_path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                assert stat.S_ISREG(info.st_mode) and info.st_uid == self.pid_owner()
                assert (info.st_dev, info.st_ino) == self.phase_identity and info.st_size == self.phase_bytes
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    assert stream.write(raw) == len(raw)
                    stream.flush()
            finally:
                os.close(descriptor)
            self.phase_hash.update(raw)
            self.phase_bytes += len(raw)
            self.phase_count += 1
        if final:
            if contract is not None:
                assert encode(contract) == self.contract_raw, "Immutable contract changed"
                assert read_owned(self.contract_path) == self.contract_raw
            observed = read_owned(self.phases_path)
            assert len(observed) == self.phase_bytes and digest(observed) == self.phase_hash.hexdigest()
            expected = hashlib.sha256()
            for row in reports:
                expected.update(encode(row))
            assert len(reports) == self.phase_count and expected.hexdigest() == self.phase_hash.hexdigest()
        snapshot = dict(value)
        snapshot["contract"] = None
        snapshot["reports"] = []
        snapshot["capture_retention"] = {
            "schema": RETENTION_SCHEMA, "complete": final,
            "contract": self.contract_reference,
            "phases": {"file": self.phases_path.name, "bytes": self.phase_bytes,
                       "sha256": self.phase_hash.hexdigest(), "records": self.phase_count},
            "aggregate_limit_bytes": CAPTURE_BYTES,
        }
        raw = encode(snapshot)
        assert len(raw) + len(self.contract_raw or b"") + self.phase_bytes <= CAPTURE_BYTES
        temporary = self.target.with_suffix(".new")
        temporary.write_bytes(raw)
        temporary.replace(self.target)
        self.finished = final

    def pid_owner(self) -> int:
        assert os.getpid() == self.pid
        return os.getuid()


def read_capture_file(target: Path) -> dict:
    raw = read_owned(target)
    value = json.loads(raw)
    assert value["schema"] == LOGICAL_SCHEMA and value["contract"] is None and value["reports"] == []
    retention = value["capture_retention"]
    assert set(retention) == {"schema", "complete", "contract", "phases", "aggregate_limit_bytes"}
    assert retention["schema"] == RETENTION_SCHEMA and type(retention["complete"]) is bool
    assert retention["aggregate_limit_bytes"] == CAPTURE_BYTES
    contract_path, phases_path = names(target)
    total = len(raw)
    if retention["contract"] is not None:
        row = retention["contract"]
        assert set(row) == {"file", "bytes", "sha256"} and row["file"] == contract_path.name
        content = read_owned(contract_path)
        assert len(content) == row["bytes"] and digest(content) == row["sha256"]
        value["contract"] = json.loads(content)
        assert encode(value["contract"]) == content
        total += len(content)
    else:
        assert not contract_path.exists()
    row = retention["phases"]
    assert set(row) == {"file", "bytes", "sha256", "records"} and row["file"] == phases_path.name
    content = read_owned(phases_path)
    assert len(content) == row["bytes"] and digest(content) == row["sha256"]
    assert not content or content.endswith(b"\n")
    reports = []
    for line in content.splitlines():
        report = json.loads(line)
        assert encode(report) == line + b"\n"
        reports.append(report)
    assert type(row["records"]) is int and len(reports) == row["records"]
    total += len(content)
    assert total <= CAPTURE_BYTES
    value["reports"] = reports
    return value
