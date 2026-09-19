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
    print("LSC_VALIDATION_FRAME_BEGIN " + json.dumps(meta, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"LSC_VALIDATION_FRAME_CHUNK {label} {index}/{len(chunks)} {chunk}", flush=True)
    print("LSC_VALIDATION_FRAME_END " + json.dumps(meta, sort_keys=True), flush=True)


def reconciliation_frames(path: Path) -> None:
    data = path.read_bytes()
    limit = 1024 * 1024
    if len(data) <= limit:
        frame(path.name, data, limit=limit)
        return
    assert len(data) <= 16 * limit, "Reconciliation exceeds bounded lossless projection"
    parts = [(path.name + ".part-" + str(index // limit + 1).zfill(4), index, data[index:index + limit])
             for index in range(0, len(data), limit)]
    manifest = {
        "schema": "hol-guard.lsc-validation.byte-parts.v1",
        "original_file": path.name, "original": digest(data),
        "reconstruction": "concatenate decoded part bytes in listed order",
        "part_byte_limit": limit,
        "parts": [{"label": label, "offset": offset, **digest(part)} for label, offset, part in parts]}
    raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    frame(path.name + ".parts.json", raw_manifest, limit=limit)
    for label, _offset, part in parts:
        frame(label, part, limit=limit)


def main() -> None:
    root = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    names = ("source-contract.json", "existing-test-selection.json",
             "existing-collection-comparison.json", "finite-results.json", "job-outcome.json")
    for name in names:
        path = root / name
        if path.is_file():
            frame(name, path.read_bytes(), limit=1024 * 1024)
    for path in sorted(root.glob("*-reconciliation.json")):
        reconciliation_frames(path)
    members = root / "package-members.json"
    if members.is_file():
        source = json.loads(members.read_bytes())
        summary = {"source_sha": source["source_sha"], "source_tree": source["source_tree"],
                   "all_actual_members_verified": source["all_actual_members_verified"],
                   "all_wheel_record_rows_verified": source["all_wheel_record_rows_verified"],
                   "qualification_complete": False}
        for name in ("wheel", "sdist"):
            summary[name] = {key: value for key, value in source[name].items() if key != "members"}
        raw = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode()
        (root / "package-summary.json").write_bytes(raw)
        frame("package-summary.json", raw, limit=1024 * 1024)


if __name__ == "__main__":
    main()
