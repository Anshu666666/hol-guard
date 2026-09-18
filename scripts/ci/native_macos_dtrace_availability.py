"""Record bounded DTrace provider-listing evidence without enabling tracing.

Apple's proc provider requires kernel tracing privileges which restricted root
may lack. Listing is an availability diagnostic, never a descendants/retirement
certificate. In particular, proc:::exit precedes task termination in XNU; the
later proc:::exited probe would be necessary for any future terminal witness.

https://github.com/apple-oss-distributions/xnu/blob/
f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_OUTPUT_LIMIT = 128 * 1024
_CSR = ("/usr/bin/csrutil", "status")
_PROBES = ("create", "exit", "exited")
_LIST = (
    "/usr/bin/sudo",
    "-n",
    "/usr/sbin/dtrace",
    "-l",
    "-n",
    "proc:::create",
    "-n",
    "proc:::exit",
    "-n",
    "proc:::exited",
)


def _limit_child_output() -> None:
    # This CLI starts no threads. A per-file kernel limit bounds both temporary
    # captures even if a fixed system command produces unexpected output.
    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = _OUTPUT_LIMIT if hard == resource.RLIM_INFINITY else min(_OUTPUT_LIMIT, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _bounded_capture(arguments: tuple[str, ...], *, timeout: float = 5.0) -> dict[str, Any]:
    started = time.monotonic()
    report: dict[str, Any] = {
        "argv": list(arguments),
        "status": "unavailable",
        "return_code": None,
        "termination_attempted": False,
        "completed_without_intervention": False,
    }
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child: subprocess.Popen[bytes] | None = None
        try:
            child = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                preexec_fn=_limit_child_output,
            )
            report["return_code"] = child.wait(timeout=timeout)
            report["status"] = "completed"
            report["completed_without_intervention"] = True
        except subprocess.TimeoutExpired:
            report["status"] = "deadline_exceeded"
            report["termination_attempted"] = True
            if child is not None:
                try:
                    child.kill()
                    report["return_code"] = child.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired) as error:
                    report["cleanup_error"] = type(error).__name__
        except (OSError, subprocess.SubprocessError) as error:
            report["error_category"] = type(error).__name__
            report["errno"] = getattr(error, "errno", None)
        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            report["status"] = "deadline_exceeded"
            report["completed_without_intervention"] = False
        for label, stream in (("stdout", stdout), ("stderr", stderr)):
            stream.seek(0)
            data = stream.read(_OUTPUT_LIMIT + 1)
            report[label + "_bytes"] = len(data)
            report[label + "_sha256"] = hashlib.sha256(data).hexdigest()
            report[label] = data[:_OUTPUT_LIMIT].decode("utf-8", errors="replace")
            if len(data) >= _OUTPUT_LIMIT:
                report["status"] = "output_limit"
                report["completed_without_intervention"] = False
        report["elapsed_ms"] = round(elapsed * 1000, 3)
    return report


def collect() -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.macos-dtrace-availability.v1",
        "scope": "provider_listing_only_before_cohort",
        "qualification_pass": False,
        "ownership_verified": False,
        "descendant_coverage_verified": False,
        "enabled_probe_verified": False,
        "tracing_enabled": False,
        "security_configuration_modified": False,
        "safe_to_run_cohort": False,
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "platform": platform.platform(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    if (
        sys.platform != "darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
        or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
    ):
        return report | {"status": "not_disposable_macos_ci"}
    report["security_status"] = _bounded_capture(_CSR)
    report["provider_listing"] = _bounded_capture(_LIST)
    listing = report["provider_listing"]
    listed = set()
    for line in listing["stdout"].splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].isdigit() and fields[1] == "proc":
            listed.add(fields[-1])
    report["required_probes"] = list(_PROBES)
    report["listed_required_probes"] = sorted(listed.intersection(_PROBES))
    report["all_required_probes_listed"] = listing["return_code"] == 0 and set(_PROBES) <= listed
    # A completed denial or missing provider is retained and does not skip either
    # arm. A hung/oversize diagnostic blocks this new cohort instead of leaving
    # uncertain activity beside timed measurements. No tracer is ever enabled.
    report["safe_to_run_cohort"] = all(
        report[key]["completed_without_intervention"] is True for key in ("security_status", "provider_listing")
    )
    report["status"] = "listing_recorded" if report["safe_to_run_cohort"] else "diagnostic_incomplete"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = collect()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["safe_to_run_cohort"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
