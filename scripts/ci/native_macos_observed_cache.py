"""Measure one resolver-cache signal against the freshly verified Apple service.

This standalone diagnostic builds no wheels and runs no qualification cohort.
The original libc probes, five-second bounds, and host/DNS observations remain
unchanged. launchctl acceptance is distinct from evidence of signal handling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import native_loopback_cache as cache
from scripts.ci import native_macos_service_identity as identity


def _target(report: dict[str, Any]) -> str | None:
    service = report.get("service", {})
    label = service.get("label")
    if (
        report.get("service_identity_verified") is not True
        or not isinstance(label, str)
        or identity._LABEL.fullmatch(label) is None
        or service.get("service_target") != "system/" + label
    ):
        return None
    return "system/" + label


def collect(*, progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.macos-observed-cache-diagnostic.v1",
        "scope": "one_disposable_host_service_cache_experiment_no_installed_cohort",
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "signal_attempts": 0,
        "launchctl_signal_accepted": False,
        "service_signal_handled_verified": False,
        "security_configuration_modified": False,
        "hosts_or_dns_configuration_modified": False,
        "baseline_artifact_modified": False,
        "fixture_deadline_changed": False,
        "qualification_pass": False,
        "installed_baseline_startup_verified": False,
        "ownership_verified": False,
        "libc_recovered_after_signal": False,
        "diagnostic_passed": False,
    }

    def checkpoint() -> None:
        if progress is not None:
            progress(report)

    def probes(key: str) -> None:
        report[key] = []
        for operation in cache._LOOKUPS:
            report[key].append(cache.libc_probe(operation))
            checkpoint()

    if (
        sys.platform != "darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
        or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
    ):
        return report | {"status": "not_disposable_macos_ci"}
    report["status"] = "configuration_before"
    report["hosts_before"] = cache.hosts_mapping_witness()
    report["dns_before"], _ = cache._fixed_command(cache._DNS, limit=256 * 1024)
    checkpoint()
    if not cache._hosts_eligible(report["hosts_before"]) or report["dns_before"]["status"] != "completed":
        return report | {"status": "configuration_witness_unavailable"}
    report["status"] = "libc_before"
    probes("libc_before")
    # Revalidate on this runner after all pre-signal probes. Never reuse the
    # previous cohort's identity or substitute a guessed launchd label.
    report["service_before"] = identity.collect()
    target = _target(report["service_before"])
    checkpoint()
    if target is None:
        return report | {"status": "service_identity_unverified"}
    arguments = ("/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGHUP", target)
    report.update(status="signal_pending", signal_attempts=1, signal_argv=list(arguments))
    checkpoint()
    report["signal"] = identity._capture(arguments)
    report["launchctl_signal_accepted"] = (
        report["signal"]["status"] == "completed" and report["signal"]["return_code"] == 0
    )
    report["status"] = "signal_observed"
    checkpoint()
    # Retain all three post-signal probes even if launchctl fails. No retry,
    # configuration rewrite, service restart, or longer lookup is permitted.
    report["status"] = "libc_after"
    probes("libc_after")
    report["hosts_after"] = cache.hosts_mapping_witness()
    report["dns_after"], _ = cache._fixed_command(cache._DNS, limit=256 * 1024)
    report["service_after"] = identity.collect()
    report["hosts_unchanged"] = report["hosts_before"] == report["hosts_after"]
    report["dns_configuration_unchanged"] = (
        report["dns_after"]["status"] == "completed"
        and report["dns_before"]["stdout_sha256"] == report["dns_after"]["stdout_sha256"]
    )
    report["service_files_unchanged"] = _target(report["service_after"]) == target and all(
        report["service_before"].get(key + "_before") == report["service_after"].get(key + "_after")
        for key in ("plist", "executable")
    )
    report["libc_completed_before"] = cache._libc_completed(report["libc_before"])
    report["libc_completed_after"] = cache._libc_completed(report["libc_after"])
    report["diagnostic_passed"] = all(
        report[key]
        for key in (
            "launchctl_signal_accepted",
            "hosts_unchanged",
            "dns_configuration_unchanged",
            "service_files_unchanged",
            "libc_completed_after",
        )
    )
    report["libc_recovered_after_signal"] = report["diagnostic_passed"] and not report["libc_completed_before"]
    return report | {"status": "experiment_finished"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)

    def save(report: dict[str, Any]) -> None:
        temporary = arguments.output.with_suffix(".pending")
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        temporary.replace(arguments.output)

    report = collect(progress=save)
    save(report)
    return 0 if report["diagnostic_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
