"""Bind the clean installed wheel and its complete fresh dependency closure."""

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
import zipfile

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())


def normal(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def main() -> None:
    output = Path(sys.argv[1])
    wheel = Path(os.environ["LSC_INSTALLED_WHEEL"]).resolve(strict=True)
    prefix = Path(sys.prefix).resolve(strict=True)
    assert prefix == Path(os.environ["LSC_INSTALLED_VENV"]).resolve(strict=True)
    assert sys.version_info[:3] == (3, 12, 13)
    assert "include-system-site-packages = false" in (prefix / "pyvenv.cfg").read_text().lower()
    launchers = {}
    for name in ("python", "python3", "python3.12"):
        path = prefix / "bin" / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o755
        launchers[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(set(launchers.values())) == 1
    versions, dependencies = {}, {}
    for dist in importlib.metadata.distributions():
        name = normal(dist.metadata["Name"])
        assert name not in versions
        versions[name] = dist.version
        for item in dist.files or ():
            path = Path(dist.locate_file(item))
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
            resolved = path.resolve()
            assert resolved.is_relative_to(prefix), str(path)
            raw = path.read_bytes()
            key = str(resolved.relative_to(prefix))
            row = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                   "mode": oct(stat.S_IMODE(info.st_mode))}
            assert key not in dependencies or dependencies[key] == row
            dependencies[key] = row
    assert versions == CONFIG["installed_versions"], versions
    project = importlib.metadata.distribution("hol-guard")
    direct = json.loads(project.read_text("direct_url.json"))
    assert direct["url"] == wheel.as_uri() and not direct.get("dir_info", {}).get("editable"), direct
    package = importlib.import_module("codex_plugin_scanner")
    package_root = Path(package.__file__).resolve().parent
    assert package_root.is_relative_to(prefix)
    product_root = package_root.parent
    for key in ("VALIDATION_SOURCE", "VALIDATION_BASELINE", "VALIDATION_HARNESS"):
        root = Path(os.environ[key]).resolve()
        assert not package_root.is_relative_to(root)
    matched = {}
    with zipfile.ZipFile(wheel) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if not name.startswith("codex_plugin_scanner/"):
                continue
            path = product_root / name
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and not path.is_symlink(), name
            raw = path.read_bytes()
            assert raw == archive.read(name), name
            matched[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    actual = {str(path.relative_to(product_root)) for path in package_root.rglob("*") if path.is_file()}
    assert actual == set(matched), sorted(actual ^ set(matched))
    output.write_text(json.dumps({
        "python_version": sys.version, "prefix": str(prefix), "launchers": launchers,
        "installed_versions": versions, "installed_count": len(versions), "direct_url": direct,
        "dependency_files": dependencies, "product_root": str(product_root),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "installed_package_files": matched, "qualification_complete": False},
        sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
