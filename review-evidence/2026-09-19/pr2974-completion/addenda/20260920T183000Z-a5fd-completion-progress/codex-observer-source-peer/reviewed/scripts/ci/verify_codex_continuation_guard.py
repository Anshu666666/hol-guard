"""Run one original current Codex approval attempt with a private line witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.codex_continuation_schema import pairs, validated_export
from scripts.ci.verify_installed_pi_sources import admit_installed
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_corpus import _attempt, _selected, installed_expectation
from scripts.native_slo_launcher_review import approved_review_case, payload_bound_review_case
from scripts.native_slo_priority_launchers import LauncherSession, install_priority_launchers
from scripts.native_slo_workloads import build_cases


@contextmanager
def child_forwarding(destination: Path):
    from scripts import native_slo_daemon_fixture as fixture

    original = fixture._spawn_hook_process
    expected = str(Path(fixture.__file__).resolve())
    child = str(Path(__file__).with_name("codex_continuation_child.py").resolve())
    calls = []

    def spawn(argv: Any, **kwargs: Any) -> Any:
        if (
            type(argv) is not tuple
            or len(argv) != 7
            or argv[:4] != (sys.executable, "-u", expected, "--serve")
            or argv[5:] != ("normal", "none")
            or calls
        ):
            raise ValueError("codex_observer_unexpected_fixture_spawn")
        calls.append(True)
        environment = dict(kwargs["environment"])
        if "RSP136_CODEX_OBSERVER_FILE" in environment:
            raise ValueError("codex_observer_existing_environment")
        environment["RSP136_CODEX_OBSERVER_FILE"] = str(destination)
        forwarded: dict[str, Any] = {**kwargs, "environment": environment}
        return original((*argv[:2], child, *argv[3:]), **forwarded)

    with patch.object(fixture, "_spawn_hook_process", spawn):
        yield calls


def _one_case(session: DaemonFixture, runtime: Path, ledger: Path, report: dict[str, object]) -> None:
    launchers = {
        (item.harness, item.event): item
        for item in install_priority_launchers(cast(LauncherSession, cast(object, session)))
    }
    selected = [
        case
        for case in build_cases(session.workspace, runtime=runtime)
        if case.setup == "normal"
        and case.harness == "codex"
        and _selected(case)
        and case.expected.reason_class == "review"
    ]
    if len(selected) != 1:
        raise ValueError("codex_observer_requires_one_original_case")
    case = installed_expectation(payload_bound_review_case(selected[0]))
    begun = session.control(
        "launcher_approval_begin",
        harness=case.harness,
        payload=dict(case.payload),
        resolution="allow",
        timeout_seconds=8,
    )
    operation = begun.get("operation_id")
    if begun.get("state") != "waiting" or not isinstance(operation, str):
        raise RuntimeError("qualification launcher approval could not start")
    with ledger.open("x", encoding="utf-8") as evidence:
        ledger.chmod(0o600)
        report["offered"] = 1
        _attempt(
            session,
            launchers[case.harness, case.event],
            approved_review_case(case),
            stage="browser_wait_completion",
            evidence=evidence,
            operation_id=operation,
        )
    report["original_passed"] = True


def run_attempt(runtime: Path, ledger: Path, observer_file: Path) -> dict[str, object]:
    report: dict[str, object] = {"offered": 0, "original_passed": False, "fixture_closed": False}
    session: DaemonFixture | None = None
    try:
        with child_forwarding(observer_file) as spawned:
            try:
                with DaemonFixture(runtime, setup="normal") as session:
                    try:
                        _one_case(session, runtime, ledger, report)
                    except Exception as error:
                        report["original_failure"] = failure_evidence(error)
            except Exception as error:
                report["cleanup_failure" if session is not None else "setup_failure"] = failure_evidence(error)
            report["fixture_spawns"] = len(spawned)
    finally:
        report["fixture_closed"] = (
            session is not None and session._closed and (session.process is None or session.process.poll() is not None)
        )
    return report


def verify(wheel: Path, source_sha: str, output: Path) -> dict[str, object]:
    report: dict[str, Any] = {
        "schema": "hol-guard.codex-guard-diagnostic.v1",
        "passed": False,
        "qualification_complete": False,
        "performance_qualified": False,
        "native_approval_consume_qualified": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    ledger = output.with_suffix(".jsonl")
    trace_file = output.with_suffix(".guards.json")
    try:
        identity, distribution, native = admit_installed(wheel, source_sha)
        report["identity"] = identity
        report["original"] = run_attempt(native.path, ledger, trace_file)
        assert_installed_import_origin(distribution)
        if installed_package_digest(distribution) != identity["installed_package_sha256"]:
            raise RuntimeError("installed_route_package_changed")
        with trace_file.open("rb") as stream:
            body = stream.read(256 * 1024 + 1)
        if len(body) > 256 * 1024:
            raise ValueError("codex_observer_export_bound")
        proof = validated_export(json.loads(body, object_pairs_hook=pairs))
        report["observer"] = proof
        report["observer_sha256"] = hashlib.sha256(body).hexdigest()
        report["passed"] = bool(
            proof.get("guards", {}).get("complete") is True
            and proof.get("native_returns", {}).get("complete") is True
            and report["original"]["fixture_closed"]
            and "cleanup_failure" not in report["original"]
            and report["original"]["offered"] == 1
            and report["original"]["fixture_spawns"] == 1
        )
    except Exception as error:
        report["diagnostic_failure"] = failure_evidence(error)
    finally:
        if ledger.exists():
            report["case_ledger_sha256"] = hashlib.sha256(ledger.read_bytes()).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.wheel.resolve(), args.source_sha, args.output.resolve())
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
