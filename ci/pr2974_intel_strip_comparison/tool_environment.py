"""Retain the base interpreter's actual pip download-tool bytes and RECORD."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
from pathlib import Path
import sys
import traceback

from archives import save_archive
from common import ARTIFACTS, REPORT, file_identity, require, write_json


def main() -> int:
    result = {"passed": False, "tool": "base-interpreter pip", "files": {}}
    destination = REPORT / "pip-download-tool.json"
    write_json(destination, result)
    try:
        dist = importlib.metadata.distribution("pip")
        record = dist.read_text("RECORD")
        result.update(version=dist.version, metadata=dist.read_text("METADATA"), record=record,
                      direct_url=dist.read_text("direct_url.json"), prefix=sys.prefix)
        write_json(destination, result)
        require(record is not None, "Pip download tool has no original RECORD")
        entries = list(dist.files or ())
        records = list(csv.reader(io.StringIO(record, newline="")))
        require([str(entry) for entry in entries] == [row[0] for row in records]
                and all(len(row) == 3 for row in records), "Pip RECORD population differs")
        require(len(entries) == len({str(entry) for entry in entries}) <= 10000,
                "Duplicate/excessive pip RECORD members")
        prefix = Path(sys.prefix).resolve(strict=True)
        archive_rows = []
        for entry in entries:
            path = Path(dist.locate_file(entry)).absolute()
            require(path.resolve(strict=True).is_relative_to(prefix), "Pip tool member escaped base prefix")
            pin = file_identity(path, maximum=32 * 1024 * 1024)
            raw = path.read_bytes()
            require(file_identity(path) == pin, "Pip member changed")
            if entry.hash is not None:
                digest = hashlib.new(entry.hash.mode, raw).digest()
                require(base64.urlsafe_b64encode(digest).decode().rstrip("=") == entry.hash.value,
                        "Pip RECORD hash mismatch")
            if entry.size is not None:
                require(entry.size == len(raw), "Pip RECORD size mismatch")
            name = path.relative_to(prefix).as_posix()
            require(name not in result["files"], "Pip canonical file alias")
            result["files"][name] = pin
            archive_rows.append((name, path, pin))
        result["original_archive"] = save_archive(ARTIFACTS / "pip-download-tool.tar.gz", archive_rows)
        result["passed"] = True
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        write_json(destination, result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
