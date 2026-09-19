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
    print("LSC_INSTALLED_FRAME_BEGIN " + json.dumps(meta, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"LSC_INSTALLED_FRAME_CHUNK {label} {index}/{len(chunks)} {chunk}", flush=True)
    print("LSC_INSTALLED_FRAME_END " + json.dumps(meta, sort_keys=True), flush=True)


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
        "schema": "hol-guard.lsc-installed-validation.byte-parts.v1",
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
    names = (
        "job-outcome.json", "installed-only-results.json", "original-metadata-admission.json",
        "original-central-directory.json", "original-lsc-download.json", "original-artifact-admission.json",
        "original-package-admission.json", "original-installed-reconciliation.json",
        "installed-seam-finalization.json", "installed-seam-execution-reconciliation.json",
        "installed-original-collection-bridge.json",
        "installed-before.json", "installed-after.json", "environment-before.json", "environment-after.json",
        "source-before.json", "source-after.json", "package-members.json",
        "installed-seam-collection.json", "installed-seam-execution.json",
        "installed-seam-execution-junit.xml", "installed-seam-execution.log",
    )
    for name in names:
        path = root / name
        if path.is_file():
            reconciliation_frames(path)
    for name in (
        "installed-before.json",
        "installed-seam-collection.json", "installed-seam-execution.json",
        "installed-seam-execution-junit.xml", "installed-seam-collection.log", "installed-seam-execution.log",
    ):
        path = root / "original" / name
        if path.is_file():
            # Copy no bytes or semantics; the relative label keeps historical and new cases distinct.
            reconciliation_frames(path, label="original/" + name)
    members = root / "package-members.json"
    if members.is_file():
        source = json.loads(members.read_bytes())
        summary = {
            "source_sha": source["source_sha"], "source_tree": source["source_tree"],
            "all_actual_members_verified": source["all_actual_members_verified"],
            "all_wheel_record_rows_verified": source["all_wheel_record_rows_verified"],
            "qualification_complete": False,
        }
        for name in ("wheel", "sdist"):
            summary[name] = {key: value for key, value in source[name].items() if key != "members"}
        raw = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode()
        (root / "package-summary.json").write_bytes(raw)
        frame("package-summary.json", raw, limit=1024 * 1024)
    projection = {
        "labels": EMITTED, "raw_bytes": EMITTED_RAW, "compressed_bytes": EMITTED_COMPRESSED,
        "all_original_and_fresh_files_retained_in_artifact": True,
        "qualification_complete": False,
    }
    (root / "projection-summary.json").write_text(json.dumps(projection, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
