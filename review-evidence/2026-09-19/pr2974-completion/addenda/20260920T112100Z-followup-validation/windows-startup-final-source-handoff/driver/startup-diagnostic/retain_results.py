"""Retain a bounded, hash-bound subset of original diagnostic files in the job log."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

MAX_FILE = 1048576
MAX_TOTAL = 4194304
CHUNK = 3072
NAMES = (
    "original-capture.json",
    "original-selector-gate.json",
    "original-selector.xml",
    "original-selector.stdout",
    "original-selector.stderr",
    "original-selector.process.json",
    "runtime-before.json",
    "runtime-after.json",
    "source-before.json",
    "source-after.json",
    "binding-comparison.json",
    "python-control-gate.json",
    "rust-control-gate.json",
    "python-controls.xml",
    "python-controls.stdout",
    "python-controls.stderr",
    "rust-default-controls.stdout",
    "rust-default-controls.stderr",
    "rust-diagnostic-controls.stdout",
    "rust-diagnostic-controls.stderr",
    "python-collection.stdout",
    "python-collection.stderr",
    "rust-default-collection.stdout",
    "rust-default-collection.stderr",
    "rust-diagnostic-collection.stdout",
    "rust-diagnostic-collection.stderr",
    "python-types.stdout",
    "python-types.stderr",
    "python-format.stdout",
    "python-format.stderr",
    "python-lint.stdout",
    "python-lint.stderr",
    "rust-format.stdout",
    "rust-format.stderr",
    "rust-clippy-default.stdout",
    "rust-clippy-default.stderr",
    "rust-clippy-diagnostic.stdout",
    "rust-clippy-diagnostic.stderr",
    "diagnostic-build.stdout",
    "diagnostic-build.stderr",
    "driver-error-before.json",
    "driver-error-static.json",
    "driver-error-python.json",
    "driver-error-rust.json",
    "driver-error-build.json",
    "driver-error-workload.json",
    "driver-error-after.json",
)


def _line(value: dict) -> None:
    print("HG_WINDOWS_STARTUP_FILE_V1 " + json.dumps(value, separators=(",", ":")), flush=True)


def _emit(name: str, content: bytes) -> dict:
    sha = hashlib.sha256(content).hexdigest()
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    count = (len(content) + CHUNK - 1) // CHUNK
    info = {"name": name, "bytes": len(content), "sha256": sha, "git_blob": blob, "chunks": count}
    _line({"kind": "begin", **info})
    for index in range(count):
        part = content[index * CHUNK : (index + 1) * CHUNK]
        _line({"kind": "chunk", "name": name, "index": index, "base64": base64.b64encode(part).decode("ascii")})
    _line({"kind": "end", "name": name, "sha256": sha})
    return info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    output = parser.parse_args().output.resolve()
    records, missing, refused = [], [], []
    total = 0
    for name in NAMES:
        path = output / name
        if not path.exists():
            missing.append(name)
            continue
        try:
            before = path.stat()
            if path.is_symlink() or not path.is_file() or before.st_size > MAX_FILE:
                refused.append(name)
                continue
            with path.open("rb") as handle:
                content = handle.read(MAX_FILE + 1)
            after = path.stat()
            if (
                len(content) > MAX_FILE
                or before.st_size != after.st_size
                or len(content) != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or total + len(content) > MAX_TOTAL
            ):
                refused.append(name)
                continue
            total += len(content)
            records.append(_emit(name, content))
        except OSError:
            refused.append(name)
    index = {
        "schema": "pr2974-windows-startup-log-subset.v1",
        "files": records,
        "missing": missing,
        "refused": refused,
        "bytes": total,
        "subset_only": True,
        "complete_artifact": False,
        "original_result_unchanged": True,
        "qualification_complete": False,
    }
    content = (json.dumps(index, indent=2, sort_keys=True) + "\n").encode()
    with (output / "log-subset-index.json").open("xb") as handle:
        handle.write(content)
    _emit("log-subset-index.json", content)
    if refused:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
