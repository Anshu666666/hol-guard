"""Project only bounded completed report bytes; retain complete originals as artifacts."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

EMITTED = []
EMITTED_RAW = 0
EMITTED_COMPRESSED = 0

def digest(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def safe_name(name: str) -> str:
    assert isinstance(name, str) and name and "\0" not in name and "\\" not in name
    assert not name.startswith("/") and not re.match(r"^[A-Za-z]:", name)
    parts = name.rstrip("/").split("/")
    assert all(part and part not in {".", ".."} for part in parts), "Unsafe archive member"
    assert PurePosixPath(name).as_posix() == name.rstrip("/"), "Noncanonical archive member"
    return name


def frame(label: str, data: bytes, *, limit: int) -> None:
    global EMITTED_RAW, EMITTED_COMPRESSED
    safe_name(label)
    assert label not in EMITTED, "Duplicate frame label"
    assert len(data) <= limit, "Original frame exceeds explicit byte limit: " + label
    compressed = gzip.compress(data, compresslevel=9, mtime=0)
    assert len(compressed) <= 4 * 1024 * 1024, "Compressed frame too large"
    assert EMITTED_RAW + len(data) <= 48 * 1024 * 1024, "Aggregate raw-frame limit"
    assert EMITTED_COMPRESSED + len(compressed) <= 8 * 1024 * 1024, "Aggregate compressed-frame limit"
    EMITTED.append(label)
    EMITTED_RAW += len(data)
    EMITTED_COMPRESSED += len(compressed)
    encoded = base64.b64encode(compressed).decode("ascii")
    chunks = [encoded[index:index + 8192] for index in range(0, len(encoded), 8192)]
    meta = {"label": label, **digest(data), "encoding": "gzip+base64",
            "compressed_bytes": len(compressed), "compressed_sha256": digest(compressed)["sha256"],
            "chunks": len(chunks), "chunk_characters": 8192, "raw_limit": limit}
    print("RSP130_OPCODE_FRAME_BEGIN " + json.dumps(meta, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"RSP130_OPCODE_FRAME_CHUNK {label} {index}/{len(chunks)} {chunk}", flush=True)
    print("RSP130_OPCODE_FRAME_END " + json.dumps(meta, sort_keys=True), flush=True)


def reconciliation_frames(path: Path, *, label: str | None = None) -> None:
    label = path.name if label is None else label
    safe_name(label)
    data = path.read_bytes()
    limit = 1024 * 1024
    if len(data) <= limit:
        frame(label, data, limit=limit)
        return
    assert len(data) <= 16 * limit, "Reconciliation exceeds bounded lossless projection"
    parts = [(label + ".part-" + str(index // limit + 1).zfill(4), index, data[index:index + limit])
             for index in range(0, len(data), limit)]
    manifest = {
        "schema": "hol-guard.rsp130-opcode.byte-parts.v1",
        "original_file": label, "original": digest(data),
        "reconstruction": "concatenate decoded part bytes in listed order",
        "part_byte_limit": limit,
        "parts": [{"label": label, "offset": offset, **digest(part)} for label, offset, part in parts]}
    raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    frame(label + ".parts.json", raw_manifest, limit=limit)
    for label, _offset, part in parts:
        frame(label, part, limit=limit)


def main() -> None:
    root = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    paths = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "projection-summary.json")
    assert len(paths) <= 256, "Report member count exceeds bound"
    for path in paths:
        assert not path.is_symlink()
        reconciliation_frames(path, label=path.relative_to(root).as_posix())
    projection = {
        "labels": EMITTED, "raw_bytes": EMITTED_RAW, "compressed_bytes": EMITTED_COMPRESSED,
        "all_original_assertions_and_actual_failure_records_retained": True,
        "qualification_complete": False,
    }
    (root / "projection-summary.json").write_text(json.dumps(projection, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
