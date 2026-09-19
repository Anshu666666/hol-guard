"""Pure capture-error tests: mocked subprocess results, no child execution."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from bind_loaded_sqlite import ObserverUnavailableError
from build_and_verify import run


def controls() -> dict[str, object]:
    cases = [
        (subprocess.CompletedProcess([], 0, b"finite_stdout", b"finite_stderr"), None),
        (subprocess.CompletedProcess([], 7, b"finite_failure", b"finite_stderr"), "component_process_failed"),
        (subprocess.TimeoutExpired([], 45, b"finite_partial", b"finite_partial_error"), "component_process_timeout"),
        (subprocess.TimeoutExpired([], 45), "component_process_timeout"),
        (OSError("private_launch_error_not_exported"), "component_process_launch_failed"),
        (subprocess.CompletedProcess([], 0, b"x" * (1024 * 1024 + 1), b""), "component_output_limit"),
        (subprocess.CompletedProcess([], 0, b"", b"x" * (256 * 1024 + 1)), "component_output_limit"),
    ]
    with tempfile.TemporaryDirectory(prefix="hol-finite-capture-control-") as directory:
        root = Path(directory)
        for i, (response, expected) in enumerate(cases):
            kwargs = {"side_effect": response} if isinstance(response, BaseException) else {"return_value": response}
            label = "case-" + str(i)
            with patch("build_and_verify.subprocess.run", **kwargs):
                try:
                    run(["unexecuted_finite_command"], root, label)
                except ObserverUnavailableError as error:
                    assert str(error) == expected
                else:
                    assert expected is None
            status = json.loads((root / (label + ".status.json")).read_text())
            stdout = (root / (label + ".stdout")).read_bytes()
            stderr = (root / (label + ".stderr")).read_bytes()
            assert len(stdout) <= 1024 * 1024 and len(stderr) <= 256 * 1024
            if i == 2:
                assert stdout == b"finite_partial" and stderr == b"finite_partial_error"
                assert status["timed_out"] and not status["complete_output_claimed"]
            if i == 3:
                assert stdout == stderr == b"" and status["timed_out"]
            if i == 4:
                assert status["launch_failed"] and not status["complete_output_claimed"]
            if i >= 5:
                assert not status["complete_output_claimed"]
                assert status["stdout_retained_truncated"] or status["stderr_retained_truncated"]
            assert b"private_launch_error" not in (root / (label + ".status.json")).read_bytes()
    return {
        "schema": "hol_sqlite_finite_capture_controls_v1",
        "controls": len(cases),
        "actual_child_processes_executed": 0,
        "timeout_partial_output_preserved": True,
        "launch_and_truncation_failures_preserved": True,
    }


if __name__ == "__main__":
    print(json.dumps(controls(), sort_keys=True))
