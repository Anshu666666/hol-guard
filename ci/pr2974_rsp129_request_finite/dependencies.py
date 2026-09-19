"""Bind the owned pytest fixture sources before collection and after all bodies."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
import traceback

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    label = sys.argv[1]
    assert label in {"before", "after"}
    result = {"source_sha": CONFIG["source_sha"], "passed": False, "files": {},
              "scope": "Complete owned pytest Python sources that may provide collected fixtures.",
              "qualification_complete": False}
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        prefix = Path(os.environ["VALIDATION_VENV"]).resolve(strict=True)
        assert Path(sys.prefix).resolve(strict=True) == prefix
        assert sys.version.split()[0] == CONFIG["python_version"]
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules)
        admission = json.loads((REPORT / "source-contract.json").read_bytes())
        assert admission["passed"] is True and admission["source_sha"] == CONFIG["source_sha"]
        distribution = importlib.metadata.distribution("pytest")
        assert distribution.version == CONFIG["installed_versions"]["pytest"]
        listed = distribution.files
        assert listed is not None
        selected = [entry for entry in listed
                    if entry.suffix == ".py" and entry.parts[0] in {"pytest", "_pytest"}]
        assert 0 < len(selected) <= 512
        total = 0
        for entry in sorted(selected, key=str):
            supplied = Path(distribution.locate_file(entry))
            assert not supplied.is_symlink()
            path = supplied.resolve(strict=True)
            assert path.is_relative_to(prefix) and not path.is_relative_to(SOURCE)
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            raw = path.read_bytes()
            total += len(raw)
            assert len(raw) <= 2 * 1024 * 1024 and total <= 16 * 1024 * 1024
            relative = path.relative_to(prefix).as_posix()
            assert relative not in result["files"]
            result["files"][relative] = {"sha256": digest(raw), "bytes": len(raw)}
        result.update(passed=True, source_files=len(selected), source_bytes=total,
                      distribution="pytest", version=distribution.version)
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    target = REPORT / ("dependency-contract-" + label + ".json")
    temporary = target.with_name(target.name + ".new")
    temporary.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    temporary.replace(target)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
