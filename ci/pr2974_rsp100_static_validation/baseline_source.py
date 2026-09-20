"""Bind the separate immutable parent checkout used only for type diagnostics."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from common import CONFIG, REPORT, SOURCE, HARNESS, commit_headers, git, write_json


def baseline_witness(label: str) -> dict:
    root = Path(os.environ["VALIDATION_BASELINE"]).resolve(strict=True)
    assert root != SOURCE and root != HARNESS
    assert not root.is_relative_to(SOURCE) and not SOURCE.is_relative_to(root)
    assert not root.is_relative_to(HARNESS) and not HARNESS.is_relative_to(root)
    assert git("rev-parse", "HEAD", cwd=root).decode().strip() == CONFIG["baseline_sha"]
    assert commit_headers(CONFIG["baseline_sha"], root) == {
        "tree": CONFIG["baseline_tree"], "parents": [CONFIG["baseline_parent"]],
    }
    files = {}
    for entry in git("ls-tree", "-rz", "--full-tree", CONFIG["baseline_sha"], cwd=root).split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        relative = raw_path.decode()
        assert kind == "blob" and mode in {"100644", "100755"}
        path = root / relative
        info, raw = path.lstat(), path.read_bytes()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert bool(info.st_mode & 0o111) == (mode == "100755")
        assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == blob
        files[relative] = {"git_blob": blob, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    assert len(files) == CONFIG["baseline_tracked_files"]
    for path in ("pyproject.toml", "uv.lock"):
        assert files[path]["sha256"] == CONFIG["fixed_files"][path]
    assert not git("status", "--porcelain", "--untracked-files=no", cwd=root).strip()
    result = {"source_sha": CONFIG["baseline_sha"], "source_tree": CONFIG["baseline_tree"], "files": files,
              "scope": "separate exact parent type-diagnostic checkout only", "qualification_complete": False}
    write_json(REPORT / ("baseline-source-" + label + ".json"), result)
    return result
