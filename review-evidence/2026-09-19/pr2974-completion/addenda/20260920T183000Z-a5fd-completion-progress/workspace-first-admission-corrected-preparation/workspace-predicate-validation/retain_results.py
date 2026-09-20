"""Return a finite allowlisted diagnostic projection without changing stage status."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import stat
from pathlib import Path
from typing import Any

MAX_TOTAL = 8 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
CHUNK = 12288
NAMES = (
    "validation-result.json",
    "original-invocation.json",
    "predicates/00.json",
    "predicate-admission.json",
    "commands.json",
    "binding-before.json",
    "binding-after.json",
    "reused-source-controls.json",
    "installed-before.json",
    "installed-after.json",
    "reader-controls-result.json",
    "reader-controls.xml",
    "workspace-lifecycle.json",
    "workspace-lifecycle.jsonl",
    "reconstructed-cells.json",
    "commands/reader-collect.stdout",
    "commands/reader-collect.stderr",
    "commands/reader-controls.stdout",
    "commands/reader-controls.stderr",
    "commands/types.stdout",
    "commands/types.stderr",
    "commands/ruff.stdout",
    "commands/ruff.stderr",
    "commands/format.stdout",
    "commands/format.stderr",
    "commands/original-first-admission.stdout",
    "commands/original-first-admission.stderr",
    "commands/admit-original.stdout",
    "commands/admit-original.stderr",
    "commands/installed-before.stdout",
    "commands/installed-before.stderr",
    "commands/installed-after.stdout",
    "commands/installed-after.stderr",
)


def emit(value: dict[str, Any]) -> None:
    print("HG_WORKSPACE_PREDICATE_FILE_V1 " + json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def frame(name: str, raw: bytes) -> dict[str, Any]:
    identity = {
        "path": name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }
    parts = max(1, (len(raw) + CHUNK - 1) // CHUNK)
    for part in range(parts):
        emit(
            {
                "kind": "part",
                **identity,
                "part": part,
                "parts": parts,
                "base64": base64.b64encode(raw[part * CHUNK : (part + 1) * CHUNK]).decode("ascii"),
            }
        )
    return identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.absolute()
    admitted, unavailable = [], []
    total = 0
    for name in NAMES:
        path = root / name
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or path.is_symlink()
                or metadata.st_size > MAX_FILE
                or total + metadata.st_size > MAX_TOTAL
            ):
                raise ValueError("projection_bound_or_type")
            with path.open("rb") as stream:
                raw = stream.read(MAX_FILE + 1)
            if len(raw) != metadata.st_size:
                raise ValueError("projection_size_changed")
            admitted.append(frame(name, raw))
            total += len(raw)
        except FileNotFoundError:
            unavailable.append({"path": name, "status": "missing"})
        except Exception:
            unavailable.append({"path": name, "status": "unavailable"})
    index = {
        "schema": "hol-guard.workspace100-log-projection.v1",
        "admitted": admitted,
        "unavailable": unavailable,
        "total_source_bytes": total,
        "total_bound": MAX_TOTAL,
        "file_bound": MAX_FILE,
        "scope": "allowlisted_subset_full_build_stdout_and_binary_bytes_remain_artifact_only",
        "original_stage_status_changed": False,
    }
    raw = json.dumps(index, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    frame("projection-index.json", raw)
    # The original validation step retains its own failure. This step never
    # turns missing preparation/control/workload records into admission.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
