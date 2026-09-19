"""Record the explicitly selected interpreter and its installed dependency source files."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_bytes())


def main():
    prefix = Path(os.environ["VALIDATION_VENV"]).resolve(strict=True)
    assert Path(sys.prefix).resolve(strict=True) == prefix
    assert sys.flags.isolated == 1 and sys.dont_write_bytecode
    primary = prefix / "bin/python"
    assert Path(sys.executable).resolve(strict=True) == primary
    info = primary.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
    requested = {
        "cryptography": ("cryptography/__init__.py", "cryptography/fernet.py"),
        "keyring": ("keyring/__init__.py", "keyring/backends/macOS/__init__.py"),
    }
    dependencies = {}
    for name, paths in requested.items():
        distribution = importlib.metadata.distribution(name)
        assert distribution.version == CONFIG["installed_versions"][name]
        actual_files = {str(item): item for item in distribution.files or ()}
        records = []
        for relative in paths:
            assert relative in actual_files, (name, relative)
            path = Path(distribution.locate_file(actual_files[relative])).resolve(strict=True)
            assert path.is_relative_to(prefix), str(path)
            raw = path.read_bytes()
            records.append({"path": str(path), "relative": relative, "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
        dependencies[name] = {"version": distribution.version, "source_files": records}
    default = shutil.which("python3")
    result = {
        "python_executable": str(primary), "python_prefix": sys.prefix,
        "python_base_prefix": sys.base_prefix, "python_version": sys.version,
        "python_sha256": hashlib.sha256(primary.read_bytes()).hexdigest(),
        "isolated_probe_sys_path": list(sys.path),
        "basedpyright_search_path_values_not_directly_observed": True,
        "path_default_python3": default,
        "path_default_python3_resolved": str(Path(default).resolve(strict=True)) if default else None,
        "basedpyright_explicit_pythonpath": str(primary), "dependencies": dependencies,
        "dependency_modules_imported_by_this_witness": [],
        "prior_failed_run_search_path_was_not_observed": True,
        "passed": True, "qualification_complete": False,
    }
    Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
