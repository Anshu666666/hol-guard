"""Emit one bounded ASCII frame while retaining every original report member."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import PurePosixPath
import stat
import traceback
import unicodedata

from common import ARTIFACTS, CONFIG, REPORT, file_identity, require, sha256, write_json


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    require(name and str(path) == name and not path.is_absolute() and "\\" not in name,
            "Unsafe report name")
    require(all(part not in {"", ".", ".."} for part in path.parts)
            and all(ord(char) >= 32 and ord(char) != 127 for char in name), "Unsafe report component")
    return unicodedata.normalize("NFC", name).casefold()


def main() -> int:
    try:
        files, payloads, aliases = {}, {}, set()
        bounds = CONFIG["bounds"]
        for path in sorted(REPORT.rglob("*")):
            if path.is_dir():
                continue
            require(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(), "Nonregular original report")
            name = path.relative_to(REPORT).as_posix()
            if name in {"artifact-manifest.json", "projection-failure.json"}:
                continue
            alias = safe_name(name)
            require(alias not in aliases and len(files) < bounds["projection_files"], "Report alias/count bound")
            aliases.add(alias)
            pin = file_identity(path, maximum=bounds["projection_per_file_bytes"])
            raw = path.read_bytes()
            require(file_identity(path) == pin and sha256(raw) == pin["sha256"], "Report changed during retention")
            files[name] = {"bytes": len(raw), "sha256": pin["sha256"]}
            if pin["sha256"] not in payloads:
                payloads[pin["sha256"]] = {"bytes": len(raw), "base64": base64.b64encode(raw).decode("ascii")}
        artifact_rows, total = {}, 0
        for path in sorted(ARTIFACTS.rglob("*")):
            if path.is_dir():
                continue
            name = path.relative_to(ARTIFACTS).as_posix()
            safe_name(name)
            pin = file_identity(path, maximum=bounds["complete_artifact_archive_bytes"])
            total += pin["bytes"]
            require(total <= bounds["complete_artifact_archive_bytes"], "Complete binary artifact set exceeds bound")
            artifact_rows[name] = pin
        manifest = {"reports": files, "report_original_bytes": sum(row["bytes"] for row in files.values()),
                    "content_addressed_payloads": len(payloads), "artifacts": artifact_rows,
                    "artifact_total_bytes": total, "source_sha": CONFIG["source_sha"],
                    "duplicate_payloads_reconstruct_exact_original_files": True}
        write_json(REPORT / "artifact-manifest.json", manifest)
        packet = {"schema": "pr2974.intel-strip-original-reports.v1", "manifest": manifest,
                  "files": files, "payloads_by_sha256": payloads, "qualification_complete": False}
        raw = json.dumps(packet, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        require(len(raw) <= bounds["projection_raw_bytes"], "Report projection raw bound")
        zipped = gzip.compress(raw, mtime=0)
        require(len(zipped) <= bounds["projection_gzip_bytes"] and zipped[3] == 0, "Gzip projection bound/flags")
        encoded = base64.b64encode(zipped).decode("ascii")
        width = bounds["base64_chunk_characters"]
        parts = [encoded[index:index + width] for index in range(0, len(encoded), width)]
        header = {"schema": packet["schema"], "raw_bytes": len(raw), "raw_sha256": sha256(raw),
                  "gzip_bytes": len(zipped), "gzip_sha256": sha256(zipped),
                  "files": len(files), "parts": len(parts), "source_sha": CONFIG["source_sha"]}
        print("INTEL_STRIP_FRAME_BEGIN " + json.dumps(header, sort_keys=True), flush=True)
        for index, part in enumerate(parts, 1):
            print("INTEL_STRIP_FRAME_PART " + str(index) + "/" + str(len(parts)) + " " + part, flush=True)
        print("INTEL_STRIP_FRAME_END " + json.dumps(header, sort_keys=True), flush=True)
        return 0
    except BaseException:
        result = {"passed": False, "error": traceback.format_exc(), "original_report_directory_retained": str(REPORT),
                  "qualification_complete": False, "complete_projection_emitted": False}
        write_json(REPORT / "projection-failure.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
