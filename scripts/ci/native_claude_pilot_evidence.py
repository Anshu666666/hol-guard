"""Private per-attempt proof and strict encrypted-retention finalization."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_evidence_files import (  # noqa: E402
    _file,
    _stat,
    atomic_exclusive,
    directory,
    fingerprint,
    read_file,
)
from scripts.native_slo_evidence_format import MAX_ARCHIVE_BYTES  # noqa: E402

MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 25_000
MAX_RECORD_BYTES = 4096
RECIPIENT_ID = "d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb"


class OutcomeJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stack = ExitStack()
        self.stream: Any = None
        self.size = 0
        self.records = 0
        self.failed = False

    def __enter__(self) -> OutcomeJournal:
        try:
            atomic_exclusive(self.path, b"")
            parent, directory_fd = self.stack.enter_context(directory(self.path.parent))
            before = _stat(parent, directory_fd, self.path.name)
            _file(before, 0, private=True)
            descriptor = os.open(
                parent / self.path.name if directory_fd is None else self.path.name,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
                dir_fd=directory_fd,
            )
            try:
                if fingerprint(os.fstat(descriptor)) != fingerprint(before):
                    raise RuntimeError("claude_pilot_journal_identity_changed")
                self.stream = self.stack.enter_context(os.fdopen(descriptor, "wb"))
            except BaseException:
                os.close(descriptor)
                raise
            self.append(
                {
                    "kind": "header",
                    "schema": "hol-guard.claude-pilot-outcomes.v1",
                    "qualification_complete": False,
                    "capture_identity": "utf8_reencoded_contained_capture",
                }
            )
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
        self.stream = None

    def append(self, value: dict[str, object], *, reserve: int = 0) -> None:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if (
            self.failed
            or self.stream is None
            or len(encoded) > MAX_RECORD_BYTES
            or self.size + len(encoded) + reserve * MAX_RECORD_BYTES > MAX_BYTES
            or self.records + 1 + reserve > MAX_RECORDS
        ):
            raise RuntimeError("claude_pilot_journal_limit")
        try:
            if self.stream.write(encoded) != len(encoded):
                raise RuntimeError("claude_pilot_journal_short_write")
            self.stream.flush()
            os.fsync(self.stream.fileno())
        except BaseException:
            self.failed = True
            raise
        self.size += len(encoded)
        self.records += 1


def verify_retention(receipt: Path, archive: Path) -> None:
    value = json.loads(read_file(receipt, 4096))
    encoded = read_file(archive, MAX_ARCHIVE_BYTES)
    if (
        not isinstance(value, dict)
        or value.get("schema") != "hol-guard.native-qualification-archive-receipt.v1"
        or value.get("status") != "encrypted"
        or value.get("archive_created") is not True
        or type(value.get("files")) is not int
        or value["files"] < 6
        or value.get("recipient_key_id") != RECIPIENT_ID
        or type(value.get("archive_bytes")) is not int
        or value.get("archive_bytes") != len(encoded)
        or value.get("archive_sha256") != hashlib.sha256(encoded).hexdigest()
    ):
        raise RuntimeError("claude_pilot_retention_incomplete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    verify_retention(args.receipt, args.archive)


if __name__ == "__main__":
    main()
