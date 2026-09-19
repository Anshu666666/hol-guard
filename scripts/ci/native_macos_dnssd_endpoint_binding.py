"""Separate retained campaign evidence from this attempt's source and SDK admission."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.ci import native_macos_resolver_path as original
from scripts.ci.native_macos_dnssd_python_evidence import _object
from scripts.ci.native_macos_python_resolver_child import file_sha

ROOT = original.ROOT
DATA = ROOT / "review-evidence/2026-09-19/macos-dlopen-context"
MANIFEST = DATA / "source-manifest.json"
HISTORY = DATA / "original-reports.json"
HISTORY_SHA = "ed71f487c8e07ad225adc99a49154c2c6eb715ed538c3ca3b5c412a5628dc973"
OLD_COMMIT = "c5e2c8eb722d577dcb36b2ce7e3db0eac88dcb6c"
OLD_RUN = 35438429333


def _json(path: Path, maximum: int) -> Any:
    digest = file_sha(path, maximum)
    data = path.read_bytes()
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("input changed")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_object)


def source_identity() -> dict[str, Any]:
    manifest = _json(MANIFEST, 64 * 1024)
    source = original.source_identity()
    if manifest["historical_source"] != OLD_COMMIT or source["sha256"] != manifest["historical_files"]:
        raise ValueError("original source closure changed")
    names = manifest["added_paths"]
    if (
        not isinstance(names, list) or len(names) != len(set(names)) or not 1 <= len(names) <= 32
        or any(not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts for name in names)
        or str(MANIFEST.relative_to(ROOT)) not in names or str(HISTORY.relative_to(ROOT)) not in names
    ):
        raise ValueError("new source paths")
    new = {}
    for name in names:
        digest = file_sha(ROOT / name, maximum=256 * 1024)
        committed = subprocess.check_output(["git", "show", source["head"] + ":" + name], cwd=ROOT, timeout=5)
        if hashlib.sha256(committed).hexdigest() != digest:
            raise ValueError("new source changed")
        new[name] = digest
    return {"head": source["head"], "historical_files": source["sha256"], "added_files": new}


def historical_admission() -> dict[str, Any]:
    if file_sha(HISTORY, 256 * 1024) != HISTORY_SHA:
        raise ValueError("historical payload")
    payload = _json(HISTORY, 256 * 1024)
    if payload["source_commit"] != OLD_COMMIT or payload["original_run_id"] != OLD_RUN or payload["original_run_attempt"] != 1:
        raise ValueError("historical run")
    labels = ("prepared", "resolver-path", "python-admission", "python-resolver-path", "dnssd-admission",
              "dnssd-python-path", "phase-admission", "dnssd-phase-path", "job-outcome")
    expected = {f"native/{architecture}/{label}.json" for architecture in ("arm64", "x86_64") for label in labels}
    if set(payload["files"]) != expected:
        raise ValueError("historical population")
    reports = {}
    for name, row in payload["files"].items():
        data = row["content"].encode("utf-8")
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("historical file")
        reports[name] = json.loads(data, object_pairs_hook=_object)
    for architecture in ("arm64", "x86_64"):
        rows = []
        for label, count in (("resolver-path", 5), ("python-resolver-path", 4), ("dnssd-python-path", 2), ("dnssd-phase-path", 4)):
            report = reports[f"native/{architecture}/{label}.json"]
            if (
                report["workflow_commit"] != OLD_COMMIT or str(report["workflow_run"]) != str(OLD_RUN)
                or str(report["workflow_attempt"]) != "1" or len(report["rows"]) != count
                or report["diagnostic_passed"] is not False or report["status"] != "experiment_finished"
                or report["stage"] != "complete"
            ):
                raise ValueError("historical outcome")
            rows.extend(report["rows"])
        if (
            sum(row["capture"]["status"] == "completed" for row in rows) != 6
            or sum(row["capture"]["status"] == "deadline_exceeded" for row in rows) != 9
            or any(row["capture"]["direct_child_reaped"] is not True for row in rows)
        ):
            raise ValueError("historical children")
    return {
        "source": OLD_COMMIT, "run": OLD_RUN, "attempt": 1, "payload_sha256": HISTORY_SHA,
        "files": {name: {"sha256": row["sha256"], "bytes": row["bytes"]} for name, row in payload["files"].items()},
        "historical_only": True, "same_current_run_claimed": False, "original_failures_preserved": True,
        "source_to_installed_library_equivalence_claimed": False,
    }


def tool_identity() -> dict[str, Any]:
    result = original.tool_identity()
    sdk = Path(original._fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"))).resolve(strict=True)
    result["endpoint_headers_sha256"] = {
        name: file_sha(sdk / "usr/include" / name)
        for name in ("sys/socket.h", "sys/stat.h", "fcntl.h", "pthread.h", "signal.h", "dlfcn.h", "unistd.h")
    }
    result["loader_flags"] = {"RTLD_NOW": os.RTLD_NOW, "RTLD_LOCAL": os.RTLD_LOCAL, "effective": os.RTLD_NOW | os.RTLD_LOCAL}
    return result
