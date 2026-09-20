"""Bind every prepared integration component to its exact reviewed source bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def verify_preparation(config: dict, here: Path, source: Path) -> dict:
    raw = (here / "component-source.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == config["component_manifest_sha256"]
    rows = json.loads(raw)
    assert len(rows) == len({row["path"] for row in rows}) == config["component_file_count"]
    actual = {}
    for row in rows:
        path = source / row["path"]
        assert path.is_file() and not path.is_symlink()
        data = path.read_bytes()
        assert len(data) == row["bytes"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob"]
        actual[row["path"]] = {key: row[key] for key in ("bytes", "sha256", "git_blob")}
    assert not (source / "src/codex_plugin_scanner/guard/adapters/pi_extension_migration_source.py").exists()
    assert not (source / "tests/test_pi_extension_migration_ownership.py").exists()
    return {
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "component_count": len(actual), "components": actual, "passed": True,
        "historical_components_are_source_provenance_only": True,
        "fixture_and_body_execution_still_required": True, "qualification_complete": False,
    }
