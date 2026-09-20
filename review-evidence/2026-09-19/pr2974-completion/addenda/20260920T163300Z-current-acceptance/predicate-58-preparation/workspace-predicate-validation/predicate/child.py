"""Owned fixture entrypoint; the original service/control flow is called once."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from predicate.bindings import Registry
from predicate.capture import Capture
from predicate.hooks import OwnedHooks

SCENARIOS = ("lost_metadata_hint", "key_rotation")
MAX_REPORT_BYTES = 1024 * 1024


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Write one bounded report in the already owned private driver directory."""
    parent = path.parent
    metadata = parent.lstat()
    if (
        parent.resolve(strict=True) != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or path.name not in {"00.json", "01.json"}
    ):
        raise ValueError("workspace_diagnostic_output_directory")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("workspace_diagnostic_output_bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def observe_dispatch(
    original: Any,
    fixture: Any,
    operation: str,
    request: Any,
    *,
    scenario: str,
    retain: Callable[[dict[str, Any]], None],
    registry: Registry,
) -> Any:
    """Forward the identical dispatch arguments; reporting cannot replace its result."""
    capture = None
    hooks = None
    result = None
    failure = None
    setup_failed = False
    try:
        session = fixture.session
        if (
            operation != "workspace_lifecycle"
            or type(request) is not dict
            or set(request) != {"op", "scenario", "receipt_profile"}
            or request.get("op") != operation
            or request.get("scenario") != scenario
            or request.get("receipt_profile") != "candidate"
            or scenario not in SCENARIOS
            or len(fixture.workspaces) != 100
        ):
            raise ValueError("workspace_diagnostic_dispatch_scope")
        capture = Capture(session)
        hooks = OwnedHooks(capture, registry)
        hooks.__enter__()
    except Exception:
        setup_failed = True
        if capture is not None:
            capture.fault()
    try:
        result = original(fixture, operation, request)
        return result
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if hooks is not None:
                hooks.close()
            observation = capture.freeze() if capture is not None else None
            result_flags = None
            if type(result) is dict:
                result_flags = {
                    "registered_workspaces": result.get("registered_workspaces") == 100,
                    "scenario_matches": result.get("scenario") == scenario,
                    "passed": result.get("passed") is True,
                    "status_completed": result.get("status") == "completed",
                    "publisher_contained": result.get("publisher_contained") is True,
                    "recovered_request_present": "requests" in result,
                    "failure_present": "failure" in result,
                }
            if failure is not None:
                original_return = "exception"
            elif type(result) is dict:
                original_return = "dict"
            else:
                original_return = "other"
            report = {
                "schema": "hol-guard.workspace-predicate-cell.v1",
                "scenario": scenario,
                "registered_workspaces": 100,
                "original_dispatch_calls": 1,
                "original_return": original_return,
                "original_result_flags": result_flags,
                "setup_failed": setup_failed,
                "hooks_restored": hooks is not None and hooks.restored,
                "observation": observation,
                "original_readiness_deadline_ms": 400,
                "original_result_or_exception_preserved": True,
                "additional_native_or_http_probes": 0,
                "headline_timing_eligible": False,
                "qualification_complete": False,
            }
            retain(report)
        except Exception:
            # A missing or partial diagnostic file makes collection incomplete;
            # the already obtained original operation outcome is preserved.
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("original_args", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    source = arguments.source_root.resolve(strict=True)
    original_args = arguments.original_args
    if original_args[:1] == ["--"]:
        original_args = original_args[1:]
    if len(original_args) != 5 or original_args[0] != "--serve" or original_args[2:] != ["none", "normal", "100"]:
        raise ValueError("workspace_diagnostic_fixture_arguments")
    sys.path.insert(0, str(source))
    from scripts import native_slo_daemon_fixture as fixture_module
    from scripts.native_slo_daemon_entrypoint import main as original_main
    from scripts.native_slo_workspace_server import WorkspaceScenarioFixture

    expected_fixture = source / "scripts" / "native_slo_daemon_fixture.py"
    if Path(fixture_module.__file__).resolve(strict=True) != expected_fixture:
        raise ValueError("workspace_diagnostic_fixture_identity")
    registry = Registry(source, Path(__file__).resolve().parents[1] / "source-bindings.json")
    original = WorkspaceScenarioFixture.dispatch
    calls = 0
    retained: list[dict[str, Any]] = []

    def dispatch(fixture: Any, operation: str, request: Any) -> Any:
        nonlocal calls
        if operation != "workspace_lifecycle":
            return original(fixture, operation, request)
        calls += 1
        if calls != 1:
            # No diagnostic re-entry; leave the original state machine in charge.
            return original(fixture, operation, request)
        return observe_dispatch(
            original,
            fixture,
            operation,
            request,
            scenario=arguments.scenario,
            retain=retained.append,
            registry=registry,
        )

    original_argv = sys.argv
    serve_result = None
    try:
        sys.argv = [str(expected_fixture), *original_args]
        with patch.object(WorkspaceScenarioFixture, "dispatch", dispatch):
            serve_result = original_main(fixture_module._serve, fixture_module._emit)
            return serve_result
    finally:
        sys.argv = original_argv
        try:
            if len(retained) == 1:
                report = retained[0]
                report["matching_dispatch_calls"] = calls
                report["original_serve_exit"] = (
                    serve_result if type(serve_result) is int and serve_result in {0, 1} else None
                )
                report["dispatch_patch_restored"] = WorkspaceScenarioFixture.dispatch is original
                write_report(arguments.output, report)
        except Exception:
            # Export is after the original serve result; missing output remains a diagnostic failure.
            pass


if __name__ == "__main__":
    raise SystemExit(main())
