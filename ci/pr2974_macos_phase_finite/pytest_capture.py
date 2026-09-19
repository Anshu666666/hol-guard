"""Capture the single actual portable cohort, source origins and compiled fixture files."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve()
CONFIG = json.loads((Path(__file__).resolve().parent / "manifest.json").read_text())
FORWARDING = "tests/test_native_macos_dnssd_phase_forwarding.py"


class Capture:
    def __init__(self):
        self.nodes = []
        self.reports = []
        self.cases = []

    def pytest_collection_finish(self, session):
        self.nodes = [item.nodeid for item in session.items]
        for item in session.items:
            if item.nodeid.split("::", 1)[0] == FORWARDING:
                self.cases.append({"nodeid": item.nodeid, "parameters": item.callspec.params})

    def pytest_runtest_logreport(self, report):
        self.reports.append({
            "nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
            "duration_seconds": report.duration, "wasxfail": getattr(report, "wasxfail", None),
            "longrepr": str(report.longrepr) if report.failed or report.skipped else None,
        })


def main() -> int:
    sys.path.insert(0, str(SOURCE))
    import pytest

    capture = Capture()
    code, error, origins, fixtures = 99, None, {}, {}
    try:
        code = int(pytest.main(sys.argv[1:], plugins=[capture]))
    except BaseException as failure:
        error = repr(failure)
    finally:
        for name, module in sorted(sys.modules.copy().items()):
            filename = getattr(module, "__file__", None)
            if not filename:
                continue
            path = Path(filename).resolve()
            relevant_name = name == "scripts" or name.startswith("scripts.") or name.startswith("test_native_macos_")
            if not relevant_name and not path.is_relative_to(SOURCE):
                continue
            if not path.is_relative_to(SOURCE):
                error = "Selected source module resolved outside candidate: " + name
                code = code or 98
                continue
            relative = str(path.relative_to(SOURCE))
            data = path.read_bytes()
            origins[name] = {"path": relative, "sha256": hashlib.sha256(data).hexdigest()}
        basetemp = Path(os.environ["VALIDATION_PYTEST_BASETEMP"]).resolve()
        programs = sorted({path.resolve() for path in basetemp.glob("phase-forwarding*/probe")
                           if not path.parent.is_symlink()}) if basetemp.is_dir() else []
        for program in programs:
            for path in sorted(program.parent.iterdir()):
                if not path.is_file() or path.is_symlink():
                    continue
                data = path.read_bytes()
                relative = str(path.relative_to(basetemp))
                target = REPORT / "portable-c-fixture" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                fixtures[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        value = {
            "nodeids": capture.nodes, "count": len(capture.nodes), "pytest_exit_code": code,
            "actual_reports": capture.reports, "source_origins": origins, "error": error,
            "portable_c_cases": capture.cases, "portable_c_programs": len(programs),
            "portable_c_fixture_files": fixtures, "native_qualification_credit": False,
            "installed_qualification_credit": False, "qualification_complete": False,
        }
        (REPORT / "pytest-capture.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
