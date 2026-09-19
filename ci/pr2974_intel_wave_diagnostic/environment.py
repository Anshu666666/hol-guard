"""Observe the actual frozen-lock environment and every installed wheel member."""

from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import tomllib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import CONFIG, REPORT, SOURCE, digest, write_json


def observe(destination):
    assert sys.flags.isolated and sys.flags.dont_write_bytecode
    assert platform.python_version() == CONFIG["python_version"]
    assert platform.system() == "Darwin" and platform.machine() == "x86_64"
    prefix = Path(sys.prefix).resolve(strict=True)
    assert prefix == Path(os.environ["VALIDATION_VENV"]).resolve(strict=True)
    locked = tomllib.loads((SOURCE / "uv.lock").read_text())
    allowed = {(row["name"].lower().replace("_", "-"), row["version"]) for row in locked["package"]}
    versions = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata["Name"].lower().replace("_", "-")
        assert name not in versions, name
        versions[name] = distribution.version
        assert (name, distribution.version) in allowed, (name, distribution.version)
    installed = importlib.metadata.distribution("hol-guard")
    assert installed.version == "3.0.1"
    direct = json.loads(installed.read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable", False)
    wheel = json.loads((REPORT / "wheel-verification.json").read_text())
    files = {}
    for name, pin in wheel["members"].items():
        actual = Path(str(installed.locate_file(name)))
        assert actual.is_file() and not actual.is_symlink()
        assert actual.resolve(strict=True).is_relative_to(prefix)
        data = actual.read_bytes()
        if name != wheel["record"]:
            assert digest(data) == {"bytes": pin["bytes"], "sha256": pin["sha256"]}, name
        files[name] = {**digest(data), "mode": actual.stat().st_mode & 0o777}
    runtime = Path(str(installed.locate_file(wheel["runtime_member"]))).resolve(strict=True)
    assert runtime.stat().st_mode & 0o111
    launcher = Path(sys.executable)
    value = {
        "python_version": platform.python_version(), "platform": platform.platform(),
        "machine": platform.machine(), "prefix": str(prefix),
        "launcher": {"path": str(launcher), "resolved": str(launcher.resolve(strict=True)),
                     **digest(launcher.resolve(strict=True).read_bytes())},
        "versions": dict(sorted(versions.items())), "frozen_lock_sha256": digest((SOURCE / "uv.lock").read_bytes())["sha256"],
        "installed_wheel_files": files, "runtime_path": str(runtime),
        "direct_url": direct, "package_record": digest((installed.read_text("RECORD") or "").encode()),
        "scope": "actual_distribution_versions_and_all_original_wheel_member_bytes",
        "dependency_distribution_file_bytes": "not_inventoried",
        "qualification_complete": False}
    write_json(destination, value)


if __name__ == "__main__":
    observe(Path(sys.argv[1]))
