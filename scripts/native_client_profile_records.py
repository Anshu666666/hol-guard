"""Closed native-client diagnostic records and bounded private journals."""

from __future__ import annotations

import json
import os
import re
import threading
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from scripts.native_slo_evidence_files import _file, _stat, atomic_exclusive, directory, fingerprint

PHASES = (
    "runtime_identity",
    "discovery",
    "peer_validation",
    "connect",
    "authentication",
    "request_write",
    "response_read",
)
MAX_RECORDS = 2048
MAX_RECORD_BYTES = 4096
MAX_BYTES = MAX_RECORDS * MAX_RECORD_BYTES


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("native_client_profile_invalid")


def count(value: Any, maximum: int = (1 << 63) - 1) -> int:
    require(type(value) is int and 0 <= value <= maximum)
    return value


def validate_record(value: Any) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "sequence",
            "request_sha256",
            "helper_request_nanoseconds",
            "phases",
            "socket_opened",
            "socket_count_complete",
            "overflow",
            "span_semantics",
            "headline_timing_eligible",
        }
    )
    require(value["schema"] == "hol-guard.native-client-profile.v1")
    require(count(value["sequence"], 1024) >= 1)
    digest = value["request_sha256"]
    require(digest is None or (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None))
    require(value["helper_request_nanoseconds"] is None or count(value["helper_request_nanoseconds"]) >= 0)
    require(value["span_semantics"] == "inclusive_do_not_sum" and value["headline_timing_eligible"] is False)
    require(type(value["overflow"]) is bool and type(value["socket_count_complete"]) is bool)
    count(value["socket_opened"], 100000)
    spans = value["phases"]
    require(isinstance(spans, dict) and set(spans) == set(PHASES))
    for span in spans.values():
        require(isinstance(span, dict) and set(span) == {"calls", "succeeded", "nanoseconds"})
        calls, succeeded = count(span["calls"], 100000), count(span["succeeded"], 100000)
        require(succeeded <= calls)
        require((span["nanoseconds"] is None) == (calls == 0))
        if calls:
            count(span["nanoseconds"])
    return value


def decode_record(line: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    require(len(line) <= MAX_RECORD_BYTES and line.endswith(b"\n"))
    value = json.loads(line, object_pairs_hook=unique)
    if isinstance(value, dict) and value.get("schema") == "hol-guard.native-resident-profile.v1":
        from scripts.native_client_profile_resident import validate_resident_record

        return validate_resident_record(value)
    if isinstance(value, dict) and value.get("schema") == "hol-guard.native-resident-profile-relay.v1":
        from scripts.native_client_profile_resident import validate_relay_record

        return validate_relay_record(value)
    return validate_record(value)


class Journal:
    """Exclusive private-at-birth file, retained ancestry and bounded durable records."""

    def __init__(self, path: Path) -> None:
        self.path, self.stack = path, ExitStack()
        self.lock = threading.Lock()
        self.stream: Any = None
        self.records = self.size = 0
        self.failed = False

    def __enter__(self) -> Journal:
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
                require(fingerprint(os.fstat(descriptor)) == fingerprint(before))
                self.stream = self.stack.enter_context(os.fdopen(descriptor, "wb"))
            except BaseException:
                os.close(descriptor)
                raise
            return self
        except BaseException:
            self.stack.close()
            raise

    def append(self, value: dict[str, Any]) -> None:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        with self.lock:
            require(not self.failed and self.stream is not None and len(encoded) <= MAX_RECORD_BYTES)
            require(self.records < MAX_RECORDS and self.size + len(encoded) <= MAX_BYTES)
            assert self.stream is not None
            try:
                require(self.stream.write(encoded) == len(encoded))
                self.stream.flush()
                os.fsync(self.stream.fileno())
            except BaseException:
                self.failed = True
                raise
            self.records += 1
            self.size += len(encoded)

    def __exit__(self, *_args: object) -> None:
        with self.lock:
            self.stack.close()
            self.stream = None
