"""Bind the fresh nine-package environment, actual runtime and installed file bytes."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, digest, write_json


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(data)
    return value.hexdigest()


def main() -> None:
    root = Path(os.environ["VALIDATION_VENV"]).resolve()
    assert Path(sys.prefix).resolve() == root
    assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
    assert sys.platform == "linux" and os.uname().machine == "x86_64"
    assert "include-system-site-packages = false" in (root / "pyvenv.cfg").read_text().lower()
    launchers = {}
    for name in ("python", "python3", "python3.12"):
        path = root / "bin" / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o755
        launchers[name] = {"sha256": file_digest(path), "mode": "0755", "uid": info.st_uid}
    assert len({row["sha256"] for row in launchers.values()}) == 1
    versions, metadata = {}, {}
    for dist in importlib.metadata.distributions():
        name = re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
        assert name not in versions, name
        versions[name] = dist.version
        metadata[name] = digest((dist.read_text("METADATA") or "").encode())
        assert dist.read_text("direct_url.json") is None, name
    assert versions == CONFIG["installed_versions"], versions
    files = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            assert path.resolve().is_relative_to(root), relative
            files[relative] = {"link": os.readlink(path)}
        elif stat.S_ISREG(info.st_mode):
            assert info.st_uid == os.getuid(), relative
            files[relative] = {"sha256": file_digest(path), "bytes": info.st_size,
                               "mode": oct(stat.S_IMODE(info.st_mode))}
        else:
            assert stat.S_ISDIR(info.st_mode), relative
    runtime = {}
    for name in ("_socket", "_ctypes"):
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        runtime[name] = {"path": str(path), "sha256": file_digest(path)}
    write_json(Path(sys.argv[1]), {
        "python_version": sys.version, "executable": sys.executable, "prefix": sys.prefix,
        "base_prefix": sys.base_prefix, "launchers": launchers, "runtime_extensions": runtime,
        "installed_versions": versions, "distribution_metadata_sha256": metadata, "files": files,
        "process_environment_sha256": digest(json.dumps(dict(os.environ), sort_keys=True).encode()),
        "image": {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
        "native_qualification_credit": False, "installed_qualification_credit": False,
        "qualification_complete": False,
    })


if __name__ == "__main__":
    main()
