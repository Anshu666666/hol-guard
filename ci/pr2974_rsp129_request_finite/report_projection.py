"""Project retained finite evidence as bounded lossless frames; execute no workloads."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import traceback

PREFIX = "RSP129_REQUEST_FOLLOWUP_V1"
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
RAW_LIMIT = 16 * 1024 * 1024
COMPRESSED_LIMIT = 2 * 1024 * 1024
TOTAL_RAW_LIMIT = 64 * 1024 * 1024
TOTAL_COMPRESSED_LIMIT = 8 * 1024 * 1024


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    result = {"passed": False, "frames": [], "raw_bytes": 0, "gzip_bytes": 0,
              "source_sha": "3d4fda0d366da972e69a244b14c8f813bd2271f9",
              "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
              "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "qualification_complete": False, "scope": "Evidence projection only; no project execution."}
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        entries = sorted(path for path in REPORT.rglob("*") if path.is_file() or path.is_symlink())
        entries = [path for path in entries if path.name != "report-framing.json"]
        assert 0 < len(entries) <= 256
        # Bound and construct every frame before printing any payload.
        packets = []
        for path in entries:
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not path.is_symlink()
            assert info.st_size <= RAW_LIMIT
            raw = path.read_bytes()
            name = path.relative_to(REPORT).as_posix()
            assert len(name) <= 256 and "\n" not in name and "\r" not in name
            try:
                text = raw.decode("utf-8")
                encoding, framed = "utf-8", raw
            except UnicodeDecodeError:
                encoding = "base64-json-envelope"
                framed = (json.dumps({"encoding": "base64", "original_bytes": len(raw),
                                      "original_sha256": sha256(raw),
                                      "content": base64.b64encode(raw).decode("ascii")},
                                     sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            assert len(framed) <= RAW_LIMIT
            compressed = gzip.compress(framed, compresslevel=9, mtime=0)
            assert len(compressed) <= COMPRESSED_LIMIT
            packet = base64.b64encode(compressed).decode("ascii")
            parts = [packet[index:index + 6000] for index in range(0, len(packet), 6000)]
            record = {"path": name, "encoding": encoding, "original_bytes": len(raw),
                      "original_sha256": sha256(raw), "raw_bytes": len(framed), "raw_sha256": sha256(framed),
                      "gzip_bytes": len(compressed), "gzip_sha256": sha256(compressed),
                      "base64_characters": len(packet), "parts": len(parts)}
            result["raw_bytes"] += len(framed)
            result["gzip_bytes"] += len(compressed)
            assert result["raw_bytes"] <= TOTAL_RAW_LIMIT
            assert result["gzip_bytes"] <= TOTAL_COMPRESSED_LIMIT
            result["frames"].append(record)
            packets.append((record, parts))
        for number, (record, parts) in enumerate(packets, 1):
            header = dict(record, index=number, count=len(packets))
            print(PREFIX + " BEGIN " + json.dumps(header, sort_keys=True, separators=(",", ":")), flush=True)
            for index, part in enumerate(parts, 1):
                print(PREFIX + " PART " + str(number) + " " + str(index) + "/" + str(len(parts)) + " " + part,
                      flush=True)
            print(PREFIX + " END " + json.dumps(header, sort_keys=True, separators=(",", ":")), flush=True)
        result["passed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    raw = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    (REPORT / "report-framing.json").write_bytes(raw)
    print(PREFIX + " OUTCOME " + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
