"""Fresh-child actual package witnesses for the bounded MCP risk pair."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or sys.implementation.name != "cpython"
    or sys.version_info[:3] not in ((3, 12, 13), (3, 12, 14)),
    reason="The initial risk-pair source profile is exact POSIX CPython 3.12.13/.14.",
)

CASES = (
    "stock",
    "fresh",
    "dotted-fallback",
    "opaque-hash",
    "opaque-evaluator",
    "opaque-categories",
    "opaque-config",
    "policy-mutation",
    "constructor-mutation",
    "constructor-failure-baseline",
    "constructor-failure-candidate",
    "authority-baseline",
    "authority-candidate",
)


@pytest.mark.parametrize("case", CASES, ids=CASES)
def test_real_package_risk_pair(case: str, tmp_path: Path, record_property) -> None:
    # A fresh interpreter has normal signal handlers; pytest-timeout's parent
    # handler must not silently force the supported positive into fallback.
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; "
            "from tests.mcp_risk_pair_runtime_cases import run_case; "
            "run_case(sys.argv[1], Path(sys.argv[2]))",
            case,
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    record_property("child_stdout", child.stdout)
    record_property("child_stderr", child.stderr)
    record_property("child_returncode", child.returncode)
    assert child.returncode == 0, child.stdout + "\n" + child.stderr
    result = json.loads(child.stdout)
    assert result["case"] == case
    assert result["status"] == "passed"
    assert result["profile_loaded"] is True
    assert result["signals_unchanged"] is True
    assert result["python"] == list(sys.version_info[:3])
    assert result["observations"]
