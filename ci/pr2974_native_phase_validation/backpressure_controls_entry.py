"""Run bounded helper controls after exact source admission."""

from __future__ import annotations

import hashlib
import importlib
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import CONFIG, REPORT, SOURCE, write_json
from preparation_contract import verify_preparation
from backpressure_controls import run_controls


def main() -> int:
    result = {"passed": False, "qualification_complete": False, "error": None}
    relative = "ci/native_runtime/native_phase_lifecycle_support.py"
    try:
        verify_preparation(CONFIG, HERE, SOURCE)
        for root in (SOURCE / "src", SOURCE):
            sys.path.insert(0, str(root))
        assert sys.executable == os.environ["VALIDATION_PYTHON"]
        source = (SOURCE / relative).read_bytes()
        assert hashlib.sha256(source).hexdigest() == CONFIG["source_inputs"][relative]
        support = importlib.import_module("ci.native_runtime.native_phase_lifecycle_support")
        assert Path(support.__file__).resolve(strict=True) == SOURCE / relative
        result = run_controls(support)
        assert len(result["cases"]) == CONFIG["helper_controls_expected"] == 26
        result["source_sha"] = CONFIG["source_sha"]
        result["support_sha256"] = hashlib.sha256(source).hexdigest()
        result["source_unchanged"] = (SOURCE / relative).read_bytes() == source
        result["qualification_complete"] = False
        assert result["source_unchanged"]
        return 0 if result["passed"] else 1
    except BaseException as error:
        result.update(passed=False, error={"type": type(error).__name__, "traceback": traceback.format_exc()})
        return 1
    finally:
        write_json(REPORT / "backpressure-controls.json", result)


if __name__ == "__main__":
    raise SystemExit(main())
