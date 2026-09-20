"""Separate source-level diagnostics after an original installed readiness failure.

Two predeclared fresh-process trials retain the original readiness function and
400 ms deadline. Profiler timings include overhead and may finish after that
deadline. These diagnostic trials never establish platform or SLO acceptance.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))
from ci.native_runtime.installed_readiness_profile import ReadinessProfile, publisher_targets  # noqa: E402
from ci.native_runtime.installed_scoped_policy_fixture import SignedPolicyFixture  # noqa: E402
from ci.native_runtime.probe_installed_scoped_policy import (  # noqa: E402
    ProbeError,
    environment_is_clean,
    require,
    require_initial_readiness,
)
from scripts.native_slo_session import stop_native_resident  # noqa: E402

_REPORT_LIMIT = 32_768
_TRIALS = ("control", "profiled")
_PROCESS_LIMIT_SECONDS = 30


def read_report(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            payload = handle.read(_REPORT_LIMIT + 1)
        if len(payload) > _REPORT_LIMIT:
            return None
        decoded = json.loads(payload)
        return decoded if isinstance(decoded, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def original_failure(report: object, expected_source: str) -> str | None:
    if not isinstance(report, dict):
        return None
    runtime = report.get("runtime_sha256")
    if (
        re.fullmatch(r"[0-9a-f]{40}", expected_source) is None
        or report.get("schema") != "guard.installed-scoped-policy.v1"
        or report.get("source_sha") != expected_source
        or report.get("passed") is not False
        or report.get("failure") != "readiness_deadline"
        or not isinstance(runtime, str)
        or re.fullmatch(r"[0-9a-f]{64}", runtime) is None
    ):
        return None
    return runtime


def trial(mode: str, source_sha: str, runtime_sha256: str) -> dict[str, object]:
    report: dict[str, object] = {
        "schema": "guard.installed-readiness-profile-trial.v1",
        "trial": mode,
        "source_sha": source_sha,
        "runtime_sha256": runtime_sha256,
        "acceptance_claim": False,
        "readiness_budget_ms": 400,
        "outcome": "setup_failed",
        "cleanup": "unverified",
    }
    require(mode in _TRIALS, "trial_invalid")
    require("site-packages" in Path(codex_plugin_scanner.__file__).resolve().parts, "not_installed_package")
    require(environment_is_clean(os.environ) and native_mode() == "auto", "native_environment_override")
    require(os.environ.get("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT") == "1", "canonical_lane_disabled")
    status = native_runtime_status()
    identity, capabilities = status.identity, status.capabilities
    if (
        not status.available
        or not status.compatible
        or identity is None
        or capabilities is None
        or capabilities.build_sha != source_sha
        or identity.sha256 != runtime_sha256
    ):
        raise ProbeError("installed_identity_mismatch")
    previous_ca = os.environ.get("SSL_CERT_FILE")
    with tempfile.TemporaryDirectory(prefix="hg-readiness-profile-") as temporary:
        fixture = None
        publisher = None
        observation = None
        runtime_cleanup_attempted = False

        def cleanup_runtime() -> None:
            nonlocal runtime_cleanup_attempted
            if runtime_cleanup_attempted:
                return
            runtime_cleanup_attempted = True
            failed = False
            if publisher is not None:
                try:
                    publisher.close()
                except BaseException:
                    failed = True
            if fixture is not None:
                try:
                    stopped = stop_native_resident(identity.path, fixture.store.guard_home, write_diagnostic=False)
                    failed = failed or not stopped.contained
                except BaseException:
                    failed = True
                report["cleanup"] = "failed" if failed else "contained"

        try:
            fixture = SignedPolicyFixture(Path(temporary).resolve())
            os.environ["SSL_CERT_FILE"] = str(fixture.ca_file)
            publisher = get_native_policy_snapshot_publisher(fixture.store)
            observation = ReadinessProfile(publisher_targets(publisher), enabled=mode == "profiled")
            with observation.attach(publisher):
                try:
                    started = time.monotonic()
                    try:
                        require_initial_readiness(publisher, fixture.workspace)
                        report["outcome"] = "ready_observed"
                    except ProbeError as error:
                        report["outcome"] = "readiness_deadline" if str(error) == "readiness_deadline" else "probe_refused"
                    finally:
                        report["caller_wall_ms_including_observer_setup"] = round(
                            min(999_999, max(0, (time.monotonic() - started) * 1000)), 3
                        )
                finally:
                    cleanup_runtime()
        except BaseException:
            if report["outcome"] == "setup_failed":
                report["outcome"] = "execution_failed"
        finally:
            cleanup_runtime()
            if fixture is not None:
                try:
                    fixture.close()
                except BaseException:
                    report["cleanup"] = "failed"
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca
            if observation is not None:
                report["profile"] = observation.snapshot()
    return report


def run_trials(original: dict[str, Any] | None, expected_source: str) -> dict[str, object]:
    runtime = original_failure(original, expected_source)
    report: dict[str, object] = {
        "schema": "guard.installed-readiness-source-profile.v1",
        "source_sha": expected_source if re.fullmatch(r"[0-9a-f]{40}", expected_source) else None,
        "acceptance_claim": False,
        "original_failure_preserved": True,
        "trial_order": list(_TRIALS),
        "readiness_budget_ms": 400,
        "profile_timings_are_instrumented": True,
        "process_timeout_semantics": "trial_leader_terminated_descendants_unverified",
        "unverified_cleanup_stops_remaining_trials": True,
        "trials": [],
    }
    if runtime is None:
        report["disposition"] = "original_readiness_failure_not_admitted"
        return report
    report["runtime_sha256"] = runtime
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="hg-readiness-reports-") as temporary:
        for mode in _TRIALS:
            output = Path(temporary) / (mode + ".json")
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(Path(__file__).resolve()),
                        "--trial",
                        mode,
                        "--expected-source-sha",
                        expected_source,
                        "--expected-runtime-sha256",
                        runtime,
                        "--json",
                        str(output),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=_PROCESS_LIMIT_SECONDS,
                )
                result = read_report(output)
                if (
                    completed.returncode != 0
                    or result is None
                    or result.get("schema") != "guard.installed-readiness-profile-trial.v1"
                    or result.get("source_sha") != expected_source
                    or result.get("runtime_sha256") != runtime
                    or result.get("trial") != mode
                    or result.get("acceptance_claim") is not False
                ):
                    results.append({"trial": mode, "outcome": "trial_unavailable", "cleanup": "unverified"})
                    break
                results.append(result)
                if result.get("cleanup") != "contained":
                    break
            except (OSError, subprocess.TimeoutExpired):
                results.append({"trial": mode, "outcome": "trial_unavailable", "cleanup": "unverified"})
                break
    report["trials"] = results
    report["disposition"] = "diagnostic_only"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--original-report", type=Path)
    parser.add_argument("--trial", choices=_TRIALS)
    parser.add_argument("--expected-runtime-sha256")
    args = parser.parse_args()
    result: dict[str, object]
    try:
        if args.trial:
            require(
                re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha) is not None
                and isinstance(args.expected_runtime_sha256, str)
                and re.fullmatch(r"[0-9a-f]{64}", args.expected_runtime_sha256) is not None,
                "trial_identity_invalid",
            )
            result = trial(args.trial, args.expected_source_sha, args.expected_runtime_sha256)
        else:
            result = run_trials(read_report(args.original_report) if args.original_report else None, args.expected_source_sha)
        payload = json.dumps(result, sort_keys=True, allow_nan=False) + "\n"
        if len(payload.encode("utf-8")) > _REPORT_LIMIT:
            raise ValueError("profile_report_limit")
    except BaseException:
        payload = '{"schema":"guard.installed-readiness-profile-error.v1","acceptance_claim":false}\n'
    args.json.write_text(payload, encoding="utf-8")
    if not args.trial:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
