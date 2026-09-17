"""One fixed fixture/run shard; all production CLI work remains in children."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import platform
import signal
import sys
from pathlib import Path
from typing import Any

from scripts.native_slo_evidence_format import canonical, digest
from scripts.scanner_pilot_identity import IdentityError
from scripts.scanner_pilot_process import AttemptFailedError, full_cli, run_command
from scripts.scanner_pilot_protocol import (
    CONTROLLER_SECONDS,
    STATES,
    BudgetExceededError,
    fixture_identity,
    identities,
    planned,
    private_write,
    read_json,
)


def _record_call(private: Path, identity: dict[str, Any], operation: Any) -> tuple[dict[str, Any], Any]:
    name = identity["id"]
    private_write(private, name + ".offered.json", identity)
    try:
        evidence, public = operation()
    except AttemptFailedError as error:
        private_write(
            private,
            name + ".terminal.json",
            {"identity": identity, "status": "failed", "failure": error.code, "process": error.evidence},
        )
        raise
    except BaseException as error:
        failure = "controller_deadline" if isinstance(error, BudgetExceededError) else "collector_operation_failed"
        private_write(
            private,
            name + ".terminal.json",
            {"identity": identity, "status": "failed", "failure": failure, "process": None},
        )
        raise
    private_write(
        private,
        name + ".terminal.json",
        {
            "identity": identity,
            "status": "completed",
            "failure": None,
            "process": evidence,
            "result_sha256": digest(canonical(public)),
        },
    )
    return evidence, public


def _detector(root: Path, binary: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    code = "import json;from bench_guard_secret_scans import _qualify_detector;"
    if binary is not None:
        code += (
            "import sys;from pathlib import Path;from secret_scan_native_pilot import install;"
            "pilot=install(Path(sys.argv[1]));result=_qualify_detector();pilot.close();"
        )
    else:
        code += "result=_qualify_detector();"
    code += "print(json.dumps(result,sort_keys=True))"
    evidence = run_command([sys.executable, "-c", code, *([str(binary)] if binary else [])], root)
    if evidence["failure"] or evidence["returncode"] != 0:
        raise AttemptFailedError(evidence["failure"] or "detector_oracle_failed", evidence)
    try:
        value = json.loads(base64.b64decode(evidence["stdout"]["base64"]))
        if (
            set(value)
            != {"provider_rules", "context_examples", "public_hmac_sha256", "independent_expectations_passed"}
            or value["provider_rules"] != 17
            or value["context_examples"] != 14
            or value["independent_expectations_passed"] is not True
        ):
            raise ValueError("detector_contract")
    except (ValueError, TypeError, KeyError) as error:
        raise AttemptFailedError("detector_oracle_failed", evidence) from error
    return evidence, value


def _check_public(public: Any, dimensions: dict[str, Any], case: Any) -> None:
    expected = dimensions["file_occurrences"] * {"safe": 0, "providers": 1, "catalog": 17, "dense": 170}[case.content]
    if (
        not isinstance(public, dict)
        or public["files_scanned"] != dimensions["file_occurrences"]
        or public["bytes_scanned"] != dimensions["file_occurrences"] * case.size
        or public["finding_count"] != expected
        or public["truncated"]
        or public["errors"]
    ):
        raise ValueError("scanner_coverage_mismatch")


def preflight(root: Path, binary: Path, target: Path, case: Any, dimensions: dict[str, Any], private: Path) -> str:
    expected = None
    for arm, candidate in (("optimized_python", None), ("native_regex_pilot", binary)):
        _, value = _record_call(
            private,
            {"id": "oracle-" + arm, "phase": "detector", "arm": arm},
            lambda candidate=candidate: _detector(root, candidate),
        )
        if expected is not None and value != expected:
            raise ValueError("scanner_detector_parity_failed")
        expected = value
    finding_count = (
        dimensions["file_occurrences"] * {"safe": 0, "providers": 1, "catalog": 17, "dense": 170}[case.content]
    )
    variants = [
        ("complete", (), 0, False),
        ("findings", ("--fail-on-findings",), 3 if finding_count else 0, False),
        ("files", ("--max-files", "1", "--fail-on-findings"), 2, False),
        ("bytes", ("--max-total-bytes", "1", "--fail-on-findings"), 2, False),
        ("default", (), 2 if finding_count >= 500 else 0, True),
        ("missing", (), 2, False),
    ]
    if finding_count:
        variants.append(("finding-limit", ("--max-findings", "1", "--fail-on-findings"), 2, False))
    expected_complete = None
    for label, options, exit_code, defaults in variants:
        pair = []
        for arm, candidate in (("optimized_python", None), ("native_regex_pilot", binary)):
            _, public = _record_call(
                private,
                {"id": f"preflight-{label}-{arm}", "phase": "cli_contract", "arm": arm},
                lambda candidate=candidate, options=options, exit_code=exit_code, defaults=defaults, label=label: (
                    full_cli(
                        root,
                        target / "absent" if label == "missing" else target,
                        "working" if label == "missing" else case.workflow,
                        extra_args=options,
                        expected_exit=exit_code,
                        default_bounds=defaults,
                        native_pilot_binary=candidate,
                    )
                ),
            )
            if label == "missing":
                if public is not None:
                    raise ValueError("scanner_missing_target_contract")
            elif not isinstance(public, dict) or bool(public["truncated"]) != (exit_code == 2):
                raise ValueError("scanner_incomplete_contract")
            elif label in {"complete", "findings"}:
                _check_public(public, dimensions, case)
            elif label == "finding-limit" and public["finding_count"] != 1:
                raise ValueError("scanner_finding_limit_contract")
            pair.append(public)
        if pair[0] != pair[1]:
            raise ValueError("scanner_public_parity_failed")
        if label == "complete":
            expected_complete = digest(canonical(pair[0]))
    assert expected_complete is not None
    private_write(
        private,
        "preflight.json",
        {
            "passed": True,
            "complete_result_sha256": expected_complete,
            "detector": expected,
            "variants": [v[0] for v in variants],
        },
    )
    return expected_complete


def collect(root: Path, binary: Path, private: Path, *, expected_source: str, lock: Path) -> bool:
    # Imported only by explicit collection, never by production CLI entrypoints.
    from scripts.secret_scan_benchmark_cache import cache_failure_reason, prepare_cache
    from scripts.secret_scan_benchmark_fixtures import WORKLOADS, create_fixture

    if root.resolve() != Path(__file__).resolve().parents[1]:
        raise ValueError("scanner_controller_source_mismatch")

    plan = read_json(private / "plan.json")
    case = next(item for item in WORKLOADS if item.name == plan["case"])
    run = plan["run"]
    offers = planned(case.name, run)
    if plan["attempts"] != offers or plan["source_sha"] != expected_source:
        raise ValueError("scanner_plan_changed")
    source = None
    failure = None
    cache_unavailable = []
    previous = signal.getsignal(signal.SIGALRM)

    def expire(_signum: int, _frame: Any) -> None:
        raise BudgetExceededError("scanner_controller_deadline")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, CONTROLLER_SECONDS)
    try:
        with lock.open("a+") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            source = identities(root, binary, expected_source)
            private_write(private, "source.json", source)
            private_write(
                private,
                "host.json",
                {
                    "image_os": os.environ.get("ImageOS"),  # noqa: SIM112 -- actual GitHub runner variable
                    "image_version": os.environ.get("ImageVersion"),  # noqa: SIM112 -- actual GitHub runner variable
                    "kernel": platform.release(),
                    "architecture": platform.machine(),
                    "logical_cpus": os.cpu_count(),
                },
            )
            target = private.parent / "fixture"
            dimensions = create_fixture(target, case)
            fixture = fixture_identity(target, case, dimensions)
            private_write(private, "fixture.json", fixture)
            expected = preflight(root, binary, target, case, dimensions, private)
            for state in STATES:
                try:
                    cache = prepare_cache(target, state)
                except (OSError, RuntimeError) as error:
                    cache_unavailable.append(state)
                    private_write(
                        private, f"cache-{state}.json", {"status": "unavailable", "reason": cache_failure_reason(error)}
                    )
                    continue
                private_write(private, f"cache-{state}.json", {"status": "prepared", "cache": cache})
                for attempt in (item for item in offers if item["state"] == state):
                    try:
                        prepare_cache(target, state)
                    except (OSError, RuntimeError) as error:
                        private_write(
                            private,
                            f"cache-{state}-interrupted.json",
                            {"status": "unavailable", "reason": cache_failure_reason(error)},
                        )
                        cache_unavailable.append(state)
                        break
                    native = binary if attempt["arm"] == "native_regex_pilot" else None
                    result, public = _record_call(
                        private,
                        attempt,
                        lambda native=native: full_cli(
                            root,
                            target,
                            case.workflow,
                            extra_args=("--fail-on-findings",),
                            expected_exit=3 if case.content != "safe" else 0,
                            native_pilot_binary=native,
                        ),
                    )
                    _check_public(public, dimensions, case)
                    if digest(canonical(public)) != expected:
                        raise ValueError("scanner_public_parity_failed")
                    if native and (
                        result["native_pilot_native_files"] < 1 or result["native_pilot_python_fallback_files"] != 0
                    ):
                        raise ValueError("scanner_native_boundary_missing")
                    private_write(
                        private, attempt["id"] + ".verified.json", {"verified": True, "result_sha256": expected}
                    )
            if identities(root, binary, expected_source) != source:
                raise ValueError("scanner_identity_changed")
            if fixture_identity(target, case, dimensions)["sha256"] != fixture["sha256"]:
                raise ValueError("scanner_fixture_changed")
    except BudgetExceededError:
        failure = "controller_deadline"
    except AttemptFailedError as error:
        failure = error.code
    except IdentityError as error:
        failure = str(error)
    except BaseException:
        failure = "collector_failed"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        private_write(
            private,
            "worker.json",
            {
                "finished": True,
                "failure": failure,
                "cache_unavailable": cache_unavailable,
                "identity_verified_after": failure is None and source is not None,
            },
        )
    return failure is None
