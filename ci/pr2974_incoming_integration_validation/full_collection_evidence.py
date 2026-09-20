"""Retain complete collection evidence in bounded, indexed byte members."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import traceback

MEMBER_BYTES = 1024 * 1024
TOTAL_BYTES = 48 * 1024 * 1024
MAX_MEMBERS = 64
MAX_RECORDS = 60000


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class CollectionEvidence:
    def __init__(self, report: Path, source_sha: str, source_tree: str) -> None:
        self.report = report
        self.directory = report / "full-collection-members"
        self.directory.mkdir(exist_ok=False)
        self.source_sha = source_sha
        self.source_tree = source_tree
        self.streams = {}
        self.total_bytes = 0
        self.member_count = 0
        self.finished = False

    def reference(self, name: str) -> dict:
        return {"index": "full-collection-index.json", "stream": name}

    def write_records(self, name: str, records, expected_count: int) -> dict:
        assert not self.finished and name not in self.streams
        assert name and all(character in "abcdefghijklmnopqrstuvwxyz_" for character in name)
        assert 0 <= expected_count <= MAX_RECORDS
        row = {
            "expected_records": expected_count, "records_offered": 0,
            "records_encoded": 0, "records_retained": 0, "encoded_bytes": 0,
            "retained_bytes": 0, "members": [], "complete": False, "error": None,
        }
        self.streams[name] = row
        pending = bytearray()
        encoded_hash = hashlib.sha256()

        def flush() -> None:
            if not pending:
                return
            assert self.member_count < MAX_MEMBERS, "Collection member count bound exceeded"
            raw = bytes(pending)
            assert len(raw) <= MEMBER_BYTES
            relative = f"full-collection-members/{name}-{len(row['members']):04d}.part"
            path = self.report / relative
            with path.open("xb") as stream:
                assert stream.write(raw) == len(raw)
            observed = path.read_bytes()
            assert observed == raw, "Collection member readback differs"
            row["members"].append({
                "path": relative, "ordinal": len(row["members"]),
                "bytes": len(raw), "sha256": digest(raw),
            })
            row["retained_bytes"] += len(raw)
            row["records_retained"] += raw.count(b"\n")
            self.member_count += 1
            pending.clear()

        try:
            for value in records:
                row["records_offered"] += 1
                assert row["records_offered"] <= expected_count
                raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True) + "\n").encode("ascii")
                assert self.total_bytes + len(raw) <= TOTAL_BYTES, "Collection evidence byte bound exceeded"
                self.total_bytes += len(raw)
                row["encoded_bytes"] += len(raw)
                encoded_hash.update(raw)
                position = 0
                while position < len(raw):
                    size = min(MEMBER_BYTES - len(pending), len(raw) - position)
                    pending.extend(raw[position:position + size])
                    position += size
                    if len(pending) == MEMBER_BYTES:
                        flush()
                row["records_encoded"] += 1
            flush()
            assert row["records_offered"] == row["records_encoded"] == expected_count
            assert row["records_retained"] == expected_count
            assert row["retained_bytes"] == row["encoded_bytes"]
            row["sha256"] = encoded_hash.hexdigest()
            row["complete"] = True
        except BaseException:
            row["error"] = traceback.format_exc()
            try:
                flush()
            except BaseException:
                row["partial_retention_error"] = traceback.format_exc()
            raise
        return self.reference(name)

    def _verify(self) -> None:
        expected_paths = set()
        total_bytes = 0
        total_members = 0
        for name, row in self.streams.items():
            assert row["complete"] and row["error"] is None, name
            count = 0
            byte_count = 0
            hasher = hashlib.sha256()
            pending = bytearray()
            for ordinal, member in enumerate(row["members"]):
                relative = f"full-collection-members/{name}-{ordinal:04d}.part"
                assert member["path"] == relative and member["ordinal"] == ordinal
                assert relative not in expected_paths
                expected_paths.add(relative)
                path = self.report / relative
                info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                assert not path.is_symlink() and path.resolve().is_relative_to(self.directory.resolve())
                raw = path.read_bytes()
                assert 0 < len(raw) == info.st_size == member["bytes"] <= MEMBER_BYTES
                assert digest(raw) == member["sha256"]
                assert raw.isascii()
                hasher.update(raw)
                byte_count += len(raw)
                pending.extend(raw)
                while (end := pending.find(b"\n")) >= 0:
                    line = bytes(pending[:end])
                    del pending[:end + 1]
                    value = json.loads(line)
                    assert json.dumps(value, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode("ascii") == line
                    count += 1
            assert not pending, "Collection stream ends inside a record"
            assert count == row["expected_records"] == row["records_offered"]
            assert count == row["records_encoded"] == row["records_retained"]
            assert byte_count == row["encoded_bytes"] == row["retained_bytes"]
            assert hasher.hexdigest() == row["sha256"]
            total_bytes += byte_count
            total_members += len(row["members"])
        actual_paths = {path.relative_to(self.report).as_posix()
                        for path in self.directory.iterdir()}
        assert actual_paths == expected_paths, "Collection member inventory differs"
        assert total_bytes == self.total_bytes <= TOTAL_BYTES
        assert total_members == self.member_count <= MAX_MEMBERS

    def snapshot(self) -> dict:
        return {
            "schema": "pr2974-full-collection-members.v1",
            "source_sha": self.source_sha, "source_tree": self.source_tree,
            "streams": self.streams, "encoded_bytes": self.total_bytes,
            "member_count": self.member_count, "complete": self.finished,
            "bounds": {"member_bytes": MEMBER_BYTES, "total_bytes": TOTAL_BYTES,
                       "members": MAX_MEMBERS, "records_per_stream": MAX_RECORDS},
        }

    def finish(self) -> dict:
        assert not self.finished
        error = None
        verified = False
        try:
            self._verify()
            verified = True
        except BaseException:
            error = traceback.format_exc()
        value = {**self.snapshot(), "complete": verified, "verification_error": error}
        raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        assert len(raw) <= 1024 * 1024
        path = self.report / "full-collection-index.json"
        with path.open("xb") as stream:
            assert stream.write(raw) == len(raw)
        assert path.read_bytes() == raw
        self.finished = verified
        return {"path": path.name, "bytes": len(raw), "sha256": digest(raw),
                "complete": self.finished, "verification_error": error}
