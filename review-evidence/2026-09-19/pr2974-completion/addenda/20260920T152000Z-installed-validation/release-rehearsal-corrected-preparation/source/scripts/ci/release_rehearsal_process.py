"""Bound local build children and retain their original output and identities."""

from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import Any


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))


def run(arguments: list[str], *, cwd: Path, output: Path, timeout: int = 300) -> dict[str, Any]:
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "SOURCE_DATE_EPOCH"):
        environment.pop(name, None)
    environment.update(PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONNOUSERSITE="1")
    started = time.monotonic()
    timed_out = False
    output_limit = False
    with output.with_suffix(".stdout").open("xb") as stdout, output.with_suffix(".stderr").open("xb") as stderr:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            preexec_fn=_limits,
        )
        while process.poll() is None:
            timed_out = time.monotonic() - started >= timeout
            output_limit = any(
                path.stat().st_size > 8 * 1024 * 1024
                for path in (output.with_suffix(".stdout"), output.with_suffix(".stderr"))
            )
            if timed_out or output_limit:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.05)
        code = process.wait(timeout=10)
        output_limit = output_limit or any(
            path.stat().st_size > 8 * 1024 * 1024
            for path in (output.with_suffix(".stdout"), output.with_suffix(".stderr"))
        )
    leftover = False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        leftover = True
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    record = {
        "argv": arguments,
        "cwd": str(cwd),
        "returncode": code,
        "timed_out": timed_out,
        "output_limit": output_limit,
        "remaining_process_group_killed": leftover,
        "seconds": time.monotonic() - started,
        "source_date_epoch": None,
        "scope": "Linux process-group containment; no escaped-session claim",
    }
    output.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if code or timed_out or output_limit or leftover:
        raise ValueError(f"bounded child failed: {output.name}")
    return record
