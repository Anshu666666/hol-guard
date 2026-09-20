"""Record the actual owned interpreter and installed dependency closure."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()


def normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> None:
    backend = "--backend" in sys.argv
    output = Path(sys.argv[1])
    expected_prefix = Path(os.environ["VALIDATION_BUILD_VENV" if backend else "VALIDATION_VENV"]).resolve()
    assert Path(sys.prefix).resolve() == expected_prefix
    assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
    cfg = (expected_prefix / "pyvenv.cfg").read_text().lower()
    assert "include-system-site-packages = false" in cfg
    launchers = {}
    for name in ("python", "python3", "python3.12"):
        path = expected_prefix / "bin" / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), str(path)
        assert stat.S_IMODE(info.st_mode) == 0o755, str(path)
        launchers[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode))}
    assert len({item["sha256"] for item in launchers.values()}) == 1
    versions = {}
    records = []
    for dist in importlib.metadata.distributions():
        name = normal(dist.metadata["Name"])
        assert name not in versions, name
        versions[name] = dist.version
        metadata = dist.read_text("METADATA")
        records.append({"name": name, "version": dist.version,
                        "metadata_sha256": hashlib.sha256(metadata.encode()).hexdigest() if metadata else None})
    result = {
        "python_version": sys.version, "executable": sys.executable, "prefix": sys.prefix,
        "base_prefix": sys.base_prefix, "launchers": launchers, "installed_count": len(versions),
        "installed_versions": versions, "distribution_metadata": sorted(records, key=lambda row: row["name"]),
        "platform": sys.platform, "backend_environment": backend, "qualification_complete": False,
    }
    if backend:
        assert versions == CONFIG["backend_versions"], versions
        result["backend_requirement"] = tomllib.loads((SOURCE / "pyproject.toml").read_text())["build-system"]
    else:
        lock = tomllib.loads((SOURCE / "uv.lock").read_text())
        pinned = {}
        for package in lock["package"]:
            pinned.setdefault(normal(package["name"]), set()).add(package["version"])
        mismatches = {name: version for name, version in versions.items() if version not in pinned.get(name, set())}
        assert not mismatches, mismatches
        assert versions == CONFIG["installed_versions"], versions
        project = importlib.metadata.distribution("hol-guard")
        direct = json.loads(project.read_text("direct_url.json"))
        assert direct == {"url": SOURCE.as_uri(), "dir_info": {"editable": True}}, direct
        package = importlib.import_module("codex_plugin_scanner")
        origin = Path(package.__file__).resolve()
        assert origin.is_relative_to(SOURCE / "src")
        result.update(
            all_versions_match_frozen_lock=True, editable_project=direct, package_origin=str(origin),
            package_origin_sha256=hashlib.sha256(origin.read_bytes()).hexdigest(),
            prior_69_reference_matches=versions == CONFIG["installed_versions"],
            prior_reference_differences={
                name: {"reference": CONFIG["installed_versions"].get(name), "actual": versions.get(name)}
                for name in sorted(versions.keys() | CONFIG["installed_versions"].keys())
                if versions.get(name) != CONFIG["installed_versions"].get(name)
            },
        )
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
