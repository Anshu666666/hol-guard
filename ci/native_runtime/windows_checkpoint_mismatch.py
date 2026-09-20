"""Read-only source-byte mismatch evidence; never admit a transformed source."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_source_bytes(source: Path, manifest: dict, installation: dict) -> dict:
    files = manifest["source"]["files"]
    wheel = installation["wheel_files"]
    installed = installation["installed_record_files"]
    paths = []
    for name in files:
        if name.startswith("src/codex_plugin_scanner/") and name.endswith(".py"):
            paths.append(name)
    paths.sort()
    if len(paths) > 1500:
        raise RuntimeError("mismatch_source_population_bound")
    rows = {}
    total = 0
    for path in paths:
        file = source / path
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError("mismatch_source_file_changed")
        raw = file.read_bytes()
        total += len(raw)
        if len(raw) > 4 * 1024 * 1024 or total > 64 * 1024 * 1024:
            raise RuntimeError("mismatch_source_byte_bound")
        pinned = files[path]
        if len(raw) != pinned["bytes"] or digest(raw) != pinned["sha256"]:
            raise RuntimeError("mismatch_source_hash_changed")
        relative = path.removeprefix("src/")
        candidate = raw.replace(b"\n", b"\r\n") if b"\r" not in raw else None
        raw_identity = {"bytes": len(raw), "sha256": digest(raw)}
        crlf_identity = None
        if candidate is not None:
            crlf_identity = {"bytes": len(candidate), "sha256": digest(candidate)}
        wheel_identity = wheel.get(relative)
        installed_identity = installed.get(relative)
        rows[relative] = {
            "source_git_blob": pinned["blob"],
            "raw": raw_identity,
            "lf_to_crlf_candidate": crlf_identity,
            "original_wheel": wheel_identity,
            "installed_record": installed_identity,
            "raw_matches_wheel": wheel_identity == raw_identity,
            "candidate_matches_wheel": crlf_identity is not None and wheel_identity == crlf_identity,
            "installed_matches_wheel": installed_identity is not None and installed_identity == wheel_identity,
        }
    return {
        "schema": "hol-guard.windows-source-mismatch.v1",
        "strict_source_admission_unchanged": True,
        "transformed_source_admitted": False,
        "source_files": len(rows),
        "source_bytes": total,
        "comparisons": rows,
    }


def capture_imports(source: Path, report: dict, modules: dict | None = None) -> None:
    imported = []
    selected = sys.modules if modules is None else modules
    entries = sorted(
        (name, module)
        for name, module in list(selected.items())
        if type(name) is str and (name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."))
    )
    if len(entries) > 512:
        raise RuntimeError("mismatch_import_population_bound")
    root = (source / ".venv" / "Lib" / "site-packages").resolve(strict=True)
    first = None
    for position, (_name, module) in enumerate(entries):
        if type(module) is not ModuleType:
            raise RuntimeError("mismatch_module_type")
        filename = vars(module).get("__file__")
        if filename is None:
            continue
        if type(filename) is not str:
            raise RuntimeError("mismatch_module_file_type")
        file = Path(filename).resolve(strict=True)
        if not file.is_relative_to(root):
            raise RuntimeError("mismatch_import_outside_prefix")
        relative = file.relative_to(root).as_posix()
        row = report["comparisons"].get(relative)
        if row is None:
            imported.append({"position": position, "source_path_admitted": False})
            if first is None:
                first = {"position": position, "source_path_admitted": False}
            continue
        if file.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError("mismatch_import_byte_bound")
        raw = file.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("mismatch_import_byte_bound")
        actual = {"bytes": len(raw), "sha256": digest(raw)}
        entry = {
            "position": position,
            "path": relative,
            "loaded_file": actual,
            "matches_recorded_install": actual == row["installed_record"],
            "matches_raw_source": actual == row["raw"],
            "matches_lf_to_crlf_candidate": actual == row["lf_to_crlf_candidate"],
        }
        imported.append(entry)
        if first is None and not entry["matches_raw_source"]:
            first = entry
    report["imported_files"] = imported
    report["first_mismatching_import"] = first
    report["historical_checkpoint_cause_identified"] = False
