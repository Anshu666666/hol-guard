"""Closed projections of original invalidation arguments and marker returns."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

MAX_CHANGED_PATHS = 4096
MAX_PATH_BYTES = 4096
CATEGORIES = {"database", "control_marker", "verifier_key", "home_config", "other_metadata"}


def marker(value: Any) -> dict[str, Any]:
    if value is None:
        return {"kind": "none"}
    if type(value) is not str:
        raise ValueError("database_marker_shape")
    if value == "unavailable":
        return {"kind": "unavailable"}
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("database_marker_shape")
    return {"kind": "digest", "sha256": value}


def changed_inputs(value: Any, home: Path) -> dict[str, Any]:
    """No path resolution/stat, filesystem access, getters or policy queries."""
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import (
        AUTHORITY_FILE_NAME,
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    if type(home) is not type(Path()):
        raise ValueError("publisher_home_shape")
    if value is None:
        paths: list[str] = []
        kind = "none"
    elif type(value) is set and len(value) <= MAX_CHANGED_PATHS:
        # Snapshot the actual builtin set; never alter the forwarded argument.
        paths = list(value)
        kind = "set"
    else:
        raise ValueError("changed_paths_shape")
    if any(type(path) is not str or len(path.encode("utf-8")) > MAX_PATH_BYTES for path in paths):
        raise ValueError("changed_path_shape")
    databases = {str(home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")}
    control = str(home / NATIVE_RUNTIME_STATE_DIRECTORY / AUTHORITY_FILE_NAME)
    verifier = str(home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME)
    config = str(home / "config.toml")
    rows = []
    for path in paths:
        if path in databases:
            category = "database"
        elif path == control:
            category = "control_marker"
        elif path == verifier:
            category = "verifier_key"
        elif path == config:
            category = "home_config"
        else:
            category = "other_metadata"
        rows.append({"category": category, "sha256": hashlib.sha256(path.encode("utf-8")).hexdigest()})
    rows.sort(key=lambda row: (row["category"], row["sha256"]))
    other = [row for row in rows if row["category"] != "control_marker"]
    database_only = bool(other) and all(row["category"] == "database" for row in other)
    if not rows:
        branch = "empty_or_none_database_marker"
    elif database_only:
        branch = "database_paths_marker"
    elif other:
        branch = "non_database_metadata_force"
    else:
        branch = "control_marker_only_compile"
    return {
        "kind": kind,
        "count": len(rows),
        "paths": rows,
        "argument_branch": branch,
        "control_marker_present": any(row["category"] == "control_marker" for row in rows),
    }
