"""Bind one owned interpreter's internal argv representation before observation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from .installation import canonical

PROBE = """import json,sys,sysconfig
print(json.dumps({"executable":sys.executable,"orig_argv":sys.orig_argv,
"python":list(sys.version_info[:3]),"platform":sys.platform,
"prefix":sys.prefix,"framework":bool(sysconfig.get_config_var("PYTHONFRAMEWORK"))},
sort_keys=True,separators=(",",":")))
"""


def image(path: Path) -> dict[str, Any]:
    """Hash a regular interpreter image; no executable or permission mutation."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 * 1024:
            raise ValueError("child_invocation_image_bound")
        read_bytes = 0
        while block := stream.read(65536):
            read_bytes += len(block)
            if read_bytes > 64 * 1024 * 1024:
                raise ValueError("child_invocation_image_bound")
            digest.update(block)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError("child_invocation_image_changed")
    return {"bytes": before.st_size, "sha256": digest.hexdigest()}


def parse(body: bytes, executable: str, prefix: str, python: list[int]) -> tuple[str, dict[str, Any]]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("child_invocation_duplicate")
            result[key] = value
        return result

    if len(body) > 16384:
        raise ValueError("child_invocation_report_bound")
    value = json.loads(body, object_pairs_hook=pairs)
    command = [executable, "-I", "-c", PROBE]
    if (
        type(value) is not dict
        or set(value) != {"executable", "orig_argv", "python", "platform", "prefix", "framework"}
        or value["executable"] != executable
        or value["prefix"] != prefix
        or type(value["python"]) is not list
        or any(type(item) is not int for item in value["python"])
        or value["python"] != python
        or type(value["platform"]) is not str
        or type(value["framework"]) is not bool
        or type(value["orig_argv"]) is not list
        or len(value["orig_argv"]) != len(command)
        or any(type(item) is not str for item in value["orig_argv"])
        or value["orig_argv"][1:] != command[1:]
    ):
        raise ValueError("child_invocation_binding")
    observed = value["orig_argv"][0]
    if not Path(observed).is_absolute() or len(observed) > 4096:
        raise ValueError("child_invocation_argv0")
    changed = observed != executable
    if changed and not (value["platform"] == "darwin" and value["framework"]):
        raise ValueError("child_invocation_transform_unsupported")
    return observed, {
        "schema": "hol-guard.priority-child-invocation-preflight.v1",
        "python": python,
        "platform": value["platform"],
        "framework": value["framework"],
        "argv0_transform": "darwin_framework_argv0" if changed else "unchanged",
        "registered_probe_argv_sha256": hashlib.sha256(canonical(command)).hexdigest(),
        "observed_probe_argv_sha256": hashlib.sha256(canonical(value["orig_argv"])).hexdigest(),
        "observed_argv0_sha256": hashlib.sha256(observed.encode()).hexdigest(),
        "all_arguments_after_argv0_exact": True,
        "product_imported": False,
        "original_launcher_invoked": False,
        "scope": "one untimed owned-interpreter metadata process; no product workload",
    }


def preflight(executable: str, prefix: str) -> tuple[str, dict[str, Any]]:
    before = image(Path(executable))
    completed = subprocess.run([executable, "-I", "-c", PROBE], capture_output=True, timeout=5, check=False)
    if completed.returncode != 0 or completed.stderr:
        raise ValueError("child_invocation_process")
    observed, record = parse(completed.stdout, executable, prefix, list(sys.version_info[:3]))
    if record["platform"] != sys.platform:
        raise ValueError("child_invocation_platform")
    after = image(Path(executable))
    if before != after:
        raise ValueError("child_invocation_executable_changed")
    record.update(executable_image=before, observed_argv0_image=image(Path(observed)))
    return observed, record
