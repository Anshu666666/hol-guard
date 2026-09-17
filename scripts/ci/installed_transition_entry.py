"""Retain bounded failures even when the installed probe cannot import."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from scripts.ci.installed_transition_diagnostics import exception_metadata


def main() -> int:
    print("HOL_GUARD_TRANSITION_STAGE=import_probe", file=sys.stderr, flush=True)
    try:
        spec = importlib.util.spec_from_file_location(
            "scripts.ci.installed_artifact_transition_probe",
            Path(__file__).with_name("installed_artifact_transition_probe.py"),
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("transition_probe_import_unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema": "hol-guard.installed-artifact-transition-phase.v1",
                    "passed": False,
                    "cleanup_confirmed": False,
                    "last_stage": "import_probe",
                    "failure": exception_metadata(error),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
