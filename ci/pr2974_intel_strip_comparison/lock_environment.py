"""Evaluate one frozen uv export for the admitted Darwin/Python environment."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement

from common import CONFIG, REPORT, SOURCE, require, sha256, write_json


def main() -> None:
    require(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, "Isolated lock parser required")
    raw = (REPORT / "runtime-export.txt").read_text(encoding="utf-8")
    environment = default_environment()
    require(environment["sys_platform"] == "darwin" and environment["platform_machine"] == "x86_64",
            "Wrong marker environment")
    require(environment["python_full_version"] == CONFIG["python_version"], "Wrong Python marker version")
    versions, rows = {}, []
    for original in raw.splitlines():
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        name = re.sub(r"[-_.]+", "-", requirement.name).lower()
        specifiers = list(requirement.specifier)
        require(not requirement.url and not requirement.extras and len(specifiers) == 1
                and specifiers[0].operator == "==" and "*" not in specifiers[0].version,
                "Export is not an exact version pin")
        selected = requirement.marker is None or requirement.marker.evaluate(environment)
        rows.append({"original": original, "name": name, "version": specifiers[0].version,
                     "marker": str(requirement.marker) if requirement.marker else None, "selected": selected})
        if selected:
            require(name not in versions, "Duplicate selected frozen export package")
            versions[name] = specifiers[0].version
    write_json(REPORT / "runtime-lock-raw.json",
               {"export_original": raw, "evaluated_rows": rows, "marker_environment": environment})
    require(versions and "hol-guard" not in versions, "Project must be installed only from the native wheel")
    require(versions.get("nodejs-wheel-binaries") == "24.16.0", "Frozen Node version differs")
    write_json(REPORT / "runtime-lock-admission.json",
               {"versions": versions, "marker_environment": environment, "passed": True,
                "uv_lock_sha256": sha256((SOURCE / "uv.lock").read_bytes()),
                "export_sha256": sha256(raw.encode()), "project_excluded": True})


if __name__ == "__main__":
    main()
