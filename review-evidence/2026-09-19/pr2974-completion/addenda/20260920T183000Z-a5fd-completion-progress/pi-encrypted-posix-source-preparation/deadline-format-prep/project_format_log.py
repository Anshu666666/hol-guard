"""Export bounded exact formatter evidence to framed workflow-log records."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

PREFIX = "HOL_GUARD_FORMAT_PROJECTION"
MAX_FILE_BYTES = 1048576
MAX_TOTAL_BYTES = 4194304
MAX_FILES = 64
CHUNK_BYTES = 4096
SOURCE_NAMES = (
    'main.rs',
    'native_client_failure_observation.rs',
    'native_client_read_observation.rs',
    'resident_client.rs',
    'resident_client_deadline.rs',
    'resident_client_read_observation_tests.rs',
)
SOURCE_PATHS = {
    f"formatted/{role}/rust/crates/guard-runtime/src/{name}"
    for role in ("candidate",) for name in SOURCE_NAMES
}
STDERR_PATH = re.compile(r"commands/[0-9]{2}-[a-z0-9_-]+\.stderr\Z")


def emit(kind: str, value: object) -> None:
    print(PREFIX + "_" + kind + " " + json.dumps(value, sort_keys=True), flush=True)


def describe(data: bytes) -> dict[str, object]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
    }


def read_owned(root: Path, relative: str) -> bytes:
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("projection_symlink")
    if not current.resolve().is_relative_to(root) or not stat.S_ISREG(current.stat().st_mode):
        raise ValueError("projection_not_owned_regular")
    with current.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("projection_file_bound")
    return data


def publish_file(path: str, data: bytes) -> dict[str, object]:
    chunks = (len(data) + CHUNK_BYTES - 1) // CHUNK_BYTES
    row = {"path": path, **describe(data), "chunks": chunks}
    emit("BEGIN", row)
    for index, offset in enumerate(range(0, len(data), CHUNK_BYTES)):
        emit("CHUNK", {
            "path": path, "index": index,
            "base64": base64.b64encode(data[offset:offset + CHUNK_BYTES]).decode("ascii"),
        })
    emit("END", row)
    return row


def selected_paths(result: object) -> tuple[list[tuple[str, dict[str, object] | None]], bool]:
    if not isinstance(result, dict) or result.get("schema") != "pr2974.deadline-rustfmt-preparation.v1":
        raise ValueError("projection_result_schema")
    formatted = result.get("formatted_files")
    commands = result.get("commands")
    if not isinstance(formatted, list) or len(formatted) > 6:
        raise ValueError("projection_formatted_shape")
    if not isinstance(commands, list) or len(commands) > MAX_FILES:
        raise ValueError("projection_command_shape")
    selected: list[tuple[str, dict[str, object] | None]] = [("formatting-result.json", None)]
    seen = {"formatting-result.json"}
    for rows, kind in ((formatted, "output"), (commands, "stderr")):
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("projection_record_shape")
            evidence = row.get(kind)
            if not isinstance(evidence, dict):
                raise ValueError("projection_missing_file_descriptor")
            path = row.get("output_path") if kind == "output" else evidence.get("path")
            allowed = path in SOURCE_PATHS if isinstance(path, str) and kind == "output" else (
                isinstance(path, str) and STDERR_PATH.fullmatch(path) is not None
            )
            if not allowed or not isinstance(path, str) or path in seen:
                raise ValueError("projection_path_set")
            selected.append((path, evidence))
            seen.add(path)
    if len(selected) > MAX_FILES:
        raise ValueError("projection_file_count")
    passed = result.get("formatting_preparation_passed") is True
    if passed and {path for path, _expected in selected if path in SOURCE_PATHS} != SOURCE_PATHS:
        raise ValueError("projection_incomplete_passed_sources")
    return selected, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.output).resolve()
    index: dict[str, object] = {
        "schema": "pr2974.deadline-format-log-projection.v1",
        "projection_complete": False,
        "formatter_preparation_passed": None,
        "native_compilation_executed": False,
        "native_controls_executed": False,
        "scope": "Actual returned formatted source, original formatter result and command stderr; artifact retains stdout and diffs separately.",
        "limits": {"file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                   "files": MAX_FILES, "chunk_bytes": CHUNK_BYTES},
        "files": [],
    }
    files: list[dict[str, object]] = []
    index["files"] = files
    total = 0
    try:
        result_bytes = read_owned(root, "formatting-result.json")
        files.append(publish_file("formatting-result.json", result_bytes))
        total = len(result_bytes)
        selected, passed = selected_paths(json.loads(result_bytes))
        index["formatter_preparation_passed"] = passed
        index["selected_file_count"] = len(selected)
        for path, expected in selected[1:]:
            data = read_owned(root, path)
            if expected is not None and describe(data) != {
                key: expected.get(key) for key in ("bytes", "sha256", "git_blob")
            }:
                raise ValueError("projection_file_hash_mismatch")
            if total + len(data) > MAX_TOTAL_BYTES:
                raise ValueError("projection_total_bound")
            files.append(publish_file(path, data))
            total += len(data)
        index["projection_complete"] = True
    except Exception as error:
        index["failure"] = {
            "kind": type(error).__name__,
            "code": str(error) if isinstance(error, ValueError) and str(error).startswith("projection_")
                    else "projection_exception",
        }
    index["emitted_bytes"] = total
    index["emitted_file_count"] = len(files)
    body = (json.dumps(index, indent=2, sort_keys=True) + "\n").encode()
    try:
        if root.is_dir():
            (root / "log-projection-index.json").write_bytes(body)
    except OSError:
        index["index_write_failed"] = True
        index["projection_complete"] = False
        body = (json.dumps(index, indent=2, sort_keys=True) + "\n").encode()
    index_frame = publish_file("log-projection-index.json", body)
    emit("SUMMARY", {
        "projection_complete": index["projection_complete"],
        "formatter_preparation_passed": index["formatter_preparation_passed"],
        "original_files_emitted": len(files), "index_frame": index_frame,
        "log_is_selected_subset_of_artifact": True,
    })
    return 0 if index["projection_complete"] is True else 1


if __name__ == "__main__":
    sys.exit(main())
