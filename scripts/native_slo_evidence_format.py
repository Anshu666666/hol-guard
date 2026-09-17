"""Bounded authenticated format for encrypted synthetic qualification evidence."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import cast

MAGIC = b"HGQE\x00\x01\r\n"
SCHEMA = "hol-guard.native-qualification-archive.v1"
SUITE = "RSA-OAEP-SHA256+A256GCM"
DOMAIN = b"hol-guard.native-qualification-archive.v1\x00"
MAX_FILES = 256
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 96 * 1024
MAX_HEADER_BYTES = 4096
MAX_CIPHERTEXT_BYTES = MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES + 4 + 16
MAX_ARCHIVE_BYTES = len(MAGIC) + 4 + MAX_HEADER_BYTES + MAX_CIPHERTEXT_BYTES
MAX_KEY_BYTES = 16384
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.(?:json|jsonl)\Z")
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class ArchiveError(ValueError):
    """A fixed privacy-safe archive error; never include paths or payload text."""


def require(condition: bool, code: str = "archive_invalid") -> None:
    if not condition:
        raise ArchiveError(code)


def valid_name(name: str) -> bool:
    return bool(_NAME.fullmatch(name)) and ".." not in name and name.split(".", 1)[0].casefold() not in _RESERVED


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode_canonical(encoded: bytes, maximum: int) -> dict[str, object]:
    require(0 < len(encoded) <= maximum)
    try:
        result = json.loads(encoded, object_pairs_hook=_unique_object)
        require(isinstance(result, dict) and canonical(result) == encoded)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise ArchiveError("archive_invalid") from error
    return cast(dict[str, object], result)


def bounded_int(value: object, maximum: int, *, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= maximum)
    return cast(int, value)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def context_fields(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ArchiveError("archive_invalid")
    value = cast(dict[str, object], value)
    allowed = {"source_sha", "target", "run_id", "run_attempt"}
    require(set(value) <= allowed)
    if "source_sha" in value:
        source_sha = value["source_sha"]
        require(isinstance(source_sha, str) and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None)
    if "target" in value:
        require(
            isinstance(value["target"], str)
            and value["target"]
            in {"x86_64-unknown-linux-musl", "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"}
        )
    for key in ("run_id", "run_attempt"):
        if key in value:
            bounded_int(value[key], 2**63 - 1, minimum=1)
    return value


def pack_plaintext(files: list[tuple[str, bytes]], context: dict[str, object]) -> tuple[bytes, str]:
    require(0 < len(files) <= MAX_FILES)
    seen: set[str] = set()
    entries: list[dict[str, object]] = []
    total = 0
    for name, data in files:
        require(valid_name(name) and name.casefold() not in seen)
        seen.add(name.casefold())
        total += len(data)
        require(len(data) <= MAX_FILE_BYTES and total <= MAX_TOTAL_BYTES, "archive_bounds_exceeded")
        entries.append({"name": name, "bytes": len(data), "sha256": digest(data)})
    manifest = canonical({"schema": SCHEMA, "files": entries, "total_bytes": total, "context": context_fields(context)})
    require(len(manifest) <= MAX_MANIFEST_BYTES, "archive_bounds_exceeded")
    return struct.pack(">I", len(manifest)) + manifest + b"".join(data for _, data in files), digest(manifest)


def unpack_plaintext(plaintext: bytes) -> tuple[list[tuple[str, bytes]], str]:
    require(4 <= len(plaintext) <= MAX_CIPHERTEXT_BYTES - 16)
    length = struct.unpack(">I", plaintext[:4])[0]
    require(0 < length <= MAX_MANIFEST_BYTES and 4 + length <= len(plaintext))
    encoded_manifest = plaintext[4 : 4 + length]
    manifest = decode_canonical(encoded_manifest, MAX_MANIFEST_BYTES)
    require(set(manifest) == {"schema", "files", "total_bytes", "context"} and manifest["schema"] == SCHEMA)
    context_fields(manifest["context"])
    raw_entries = manifest["files"]
    require(isinstance(raw_entries, list) and 0 < len(raw_entries) <= MAX_FILES)
    raw_entries = cast(list[object], raw_entries)
    total = bounded_int(manifest["total_bytes"], MAX_TOTAL_BYTES)
    require(len(plaintext) == 4 + length + total)
    files: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    offset = 4 + length
    for entry in raw_entries:
        require(isinstance(entry, dict) and set(entry) == {"name", "bytes", "sha256"})
        entry = cast(dict[str, object], entry)
        name = entry["name"]
        if not isinstance(name, str):
            raise ArchiveError("archive_invalid")
        require(valid_name(name) and name.casefold() not in seen)
        seen.add(name.casefold())
        size = bounded_int(entry["bytes"], MAX_FILE_BYTES)
        require(offset + size <= len(plaintext))
        content = plaintext[offset : offset + size]
        expected_hash = entry["sha256"]
        require(
            isinstance(expected_hash, str) and bool(HEX64.fullmatch(expected_hash)) and digest(content) == expected_hash
        )
        files.append((name, content))
        offset += size
    require(offset == len(plaintext))
    return files, digest(encoded_manifest)
