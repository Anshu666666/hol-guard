"""Frame every original harvest report byte; no workload runs in this projection."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, write_json

EXCLUDED = {
    "log-projection.json", "log-projection-error.json",
    "log-projection-packet.json", "log-projection-packet.json.gz",
}
RAW_LIMIT = 48 * 1024 * 1024
GZIP_LIMIT = 8 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    paths = [path for path in sorted(REPORT.rglob("*")) if path.is_file()
             and path.relative_to(REPORT).as_posix() not in EXCLUDED]
    assert 0 < len(paths) <= 256, ("Unexpected report file count", len(paths))
    files = {}
    input_bytes = 0
    for path in paths:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert not path.is_symlink() and path.resolve().is_relative_to(REPORT)
        assert info.st_size <= 16 * 1024 * 1024, str(path)
        raw = path.read_bytes()
        assert len(raw) == info.st_size
        input_bytes += len(raw)
        assert input_bytes <= RAW_LIMIT
        name = path.relative_to(REPORT).as_posix()
        try:
            content = raw.decode("utf-8")
            assert content.encode("utf-8") == raw
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(raw).decode("ascii")
            encoding = "base64"
        assert name not in files
        files[name] = {"sha256": digest(raw), "bytes": len(raw),
                       "encoding": encoding, "content": content}
    packet = {
        "schema": "pr2974-combined-corpus-harvest-complete-reports.v1",
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "file_count": len(files), "original_bytes": input_bytes, "files": files,
        "all_original_report_bytes_included": True,
        "original_report_and_generated_report_are_distinct": True,
        "failure_logs_and_partial_snapshots_are_not_truncated": True,
        "immutable_final_source_validation": False, "qualification_complete": False,
    }
    raw = json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert len(raw) <= RAW_LIMIT, ("Complete projection exceeds its fixed raw cap", len(raw))
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    assert len(compressed) <= GZIP_LIMIT, ("Complete projection exceeds its fixed gzip cap", len(compressed))
    encoded = base64.b64encode(compressed).decode("ascii")
    pieces = [encoded[index:index + 6000] for index in range(0, len(encoded), 6000)]
    framing = {
        "schema": "pr2974-combined-corpus-harvest-frame.v1",
        "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "harness_sha": os.environ["GITHUB_SHA"], "source_sha": CONFIG["source_sha"],
        "source_tree": CONFIG["source_tree"], "raw_bytes": len(raw), "raw_sha256": digest(raw),
        "gzip_bytes": len(compressed), "gzip_sha256": digest(compressed),
        "base64_chars": len(encoded), "parts": len(pieces), "files": len(files),
        "qualification_complete": False,
    }
    (REPORT / "log-projection-packet.json").write_bytes(raw)
    (REPORT / "log-projection-packet.json.gz").write_bytes(compressed)
    write_json(REPORT / "log-projection.json", framing)
    print("PR2974_COMBINED_CORPUS_HARVEST_BEGIN " + json.dumps(framing, sort_keys=True), flush=True)
    for index, piece in enumerate(pieces, 1):
        print(f"PR2974_COMBINED_CORPUS_HARVEST_PART {index:04d}/{len(pieces):04d} {piece}", flush=True)
    print("PR2974_COMBINED_CORPUS_HARVEST_END " + json.dumps(framing, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        REPORT.mkdir(parents=True, exist_ok=True)
        write_json(REPORT / "log-projection-error.json", {
            "error": repr(error), "complete_projection": False, "qualification_complete": False})
        raise
