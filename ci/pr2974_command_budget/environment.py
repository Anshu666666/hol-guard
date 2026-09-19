"""Capture actual owned environments against each unchanged frozen lock."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
SOURCE = Path(os.environ["BUDGET_SOURCE"]).resolve()


def main() -> None:
    expected = Path(os.environ["BUDGET_VENV"]).resolve()
    assert Path(sys.prefix).resolve() == expected
    assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
    assert "include-system-site-packages = false" in (expected / "pyvenv.cfg").read_text().lower()
    launchers = {}
    for name in ("python", "python3", "python3.12"):
        path = expected / "bin" / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o755
        launchers[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(set(launchers.values())) == 1
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    versions = {}
    for dist in importlib.metadata.distributions():
        name = normalize(dist.metadata["Name"])
        assert name not in versions
        versions[name] = dist.version
    pinned = {}
    for package in tomllib.loads((SOURCE / "uv.lock").read_text())["package"]:
        pinned.setdefault(normalize(package["name"]), set()).add(package["version"])
    assert all(version in pinned.get(name, set()) for name, version in versions.items())
    direct = json.loads(importlib.metadata.distribution("hol-guard").read_text("direct_url.json"))
    assert direct == {"url": SOURCE.as_uri(), "dir_info": {"editable": True}}
    assert versions["pytest-cov"] == "7.1.0" and versions["coverage"] == "7.13.5"
    coverage = tomllib.loads((SOURCE / "pyproject.toml").read_text())["tool"]["coverage"]["run"]
    assert "patch" not in coverage
    result = {"python_version": sys.version, "executable": sys.executable, "prefix": sys.prefix,
              "launchers": launchers, "installed_versions": versions, "installed_count": len(versions),
              "all_versions_match_frozen_lock": True, "editable_project": direct,
              "coverage_config": coverage, "sys_trace_active": sys.gettrace() is not None,
              "sys_profile_active": sys.getprofile() is not None, "qualification_complete": False}
    Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
