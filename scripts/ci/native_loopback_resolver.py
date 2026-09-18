"""Run both qualification arms inside an optional exact-zone macOS DNS fixture.

Only the fixed loopback PTR resolver may be created. Both immutable wheels use
the same environment. Failed setup still runs the actual measurements and keeps
their outcome; no runtime patch, hosts rewrite, cache flush, or deadline change
is applied. Cleanup refuses to remove bytes that this run does not own.
"""

from __future__ import annotations

import argparse
import json
import secrets
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if __package__:
    from .native_loopback_dns import LoopbackPTRResponder
    from .native_loopback_observability import libc_query, retain_private_captures, scutil_diagnostics
    from .native_loopback_stack import observed_libc_probe
else:
    # Direct script execution puts this helper's directory on sys.path.
    from native_loopback_dns import LoopbackPTRResponder  # pyright: ignore[reportImplicitRelativeImport]
    from native_loopback_observability import (  # pyright: ignore[reportImplicitRelativeImport]
        libc_query,
        retain_private_captures,
        scutil_diagnostics,
    )
    from native_loopback_stack import observed_libc_probe  # pyright: ignore[reportImplicitRelativeImport]

_QUERIES = {
    "legacy_getfqdn": "socket.getfqdn('127.0.0.1')",
    "reverse_getnameinfo": "socket.getnameinfo(('127.0.0.1',0),socket.NI_NAMEREQD|socket.NI_NUMERICSERV)[0]",
    "numeric_getnameinfo": "socket.getnameinfo(('127.0.0.1',0),socket.NI_NUMERICHOST|socket.NI_NUMERICSERV)[0]",
    "libc_gethostbyaddr": "packed_ipv4_libsystem_call",
}
_STARTED = '{"phase":"call_started"}'


def _query(kind: str) -> str:
    if kind == "libc_gethostbyaddr":
        return libc_query(_STARTED)
    return (
        "import json,socket; print('" + _STARTED + "',flush=True); name=" + _QUERIES[kind] + "; "
        "print(json.dumps({'loopback_label':name in "
        "('127.0.0.1','localhost','hol-guard-qualification.localhost')}))"
    )


def _call_started(output: str | bytes | None) -> bool:
    if isinstance(output, bytes):
        return output.startswith(_STARTED.encode("ascii") + b"\n")
    return isinstance(output, str) and output.startswith(_STARTED + "\n")


def resolver_probe(
    kind: str = "legacy_getfqdn",
    *,
    deadline: float | None = None,
    native_capture: dict[str, object] | None = None,
) -> dict[str, object]:
    query = _query(kind)
    started = time.monotonic()
    result_field = "result_present" if kind == "libc_gethostbyaddr" else "loopback_label"
    result: dict[str, object] = {"status": "failed", result_field: False, "call_started": False}
    try:
        timeout = 5.0 if deadline is None else min(5.0, max(0.0, deadline - started))
        if timeout == 0:
            raise subprocess.TimeoutExpired("fixed_resolver_probe", timeout)
        if kind == "libc_gethostbyaddr" and native_capture is not None:
            status, stdout, code, observation, private = observed_libc_probe(
                query,
                _STARTED,
                deadline=started + timeout,
            )
            result["native_stack"] = observation
            native_capture.update(private)
            if status != "completed":
                result.update(status=status, call_started=_call_started(stdout))
                result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
                return result
            completed = subprocess.CompletedProcess(
                [],
                code if code is not None else -1,
                stdout.decode("utf-8", errors="strict"),
                "",
            )
        else:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", query], capture_output=True, text=True, timeout=timeout, check=False
            )
        result["call_started"] = _call_started(completed.stdout)
        lines = completed.stdout.splitlines() if len(completed.stdout) <= 128 else []
        if completed.returncode == 0 and len(lines) == 2 and lines[0] == _STARTED:
            value = json.loads(lines[1])
            if isinstance(value, dict) and set(value) == {result_field} and type(value[result_field]) is bool:
                result.update(status="completed", **{result_field: value[result_field]})
    except subprocess.TimeoutExpired as error:
        result["status"] = "deadline_exceeded"
        result["call_started"] = _call_started(error.output)
    except (OSError, ValueError):
        pass
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def resolver_diagnostics(
    *,
    deadline: float | None = None,
    native_capture: dict[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    """Run distinct fixed probes concurrently within one existing 5s wait.

    The numeric control requests no name lookup. These independent subprocesses
    never replace either installed arm's resolver or extend its startup deadline.
    """
    deadline = time.monotonic() + 5.0 if deadline is None else deadline

    def probe(kind: str) -> dict[str, object]:
        if kind == "libc_gethostbyaddr" and native_capture is not None:
            return resolver_probe(kind, deadline=deadline, native_capture=native_capture)
        return resolver_probe(kind, deadline=deadline)

    with ThreadPoolExecutor(max_workers=len(_QUERIES)) as executor:
        results = executor.map(probe, _QUERIES)
        return dict(zip(_QUERIES, results, strict=True))


def _run_helper(operation: str, port: int, owner: str) -> str:
    arguments = [
        "sudo",
        "-n",
        sys.executable,
        "-I",
        str(Path(__file__).with_name("native_loopback_dns.py").resolve()),
        "--operation",
        operation,
        "--port",
        str(port),
        "--owner",
        owner,
    ]
    try:
        completed = subprocess.run(arguments, capture_output=True, timeout=10, check=False)
        return {0: "completed", 2: "existing_configuration", 3: "refused_unowned"}.get(completed.returncode, "failed")
    except subprocess.TimeoutExpired:
        return "deadline_exceeded"
    except OSError:
        return "failed"


def _base_report() -> dict[str, object]:
    return {
        "schema": "hol-guard.native-loopback-resolver.v4",
        "environment_scope": "disposable_ci_runner_both_arms",
        "baseline_artifact_modified": False,
        "runtime_patched": False,
        "fixture_deadline_changed": False,
        "qualification_pass": False,
        "mechanism": "exact_loopback_ptr_resolver",
        "experiment_attempted": False,
        "probe_timeout_seconds": 5,
        "probe_execution": "independent_concurrent_subprocesses",
        "native_stack_scope": "before_phase_owned_libc_probe_only",
        "native_stack_max_attempts": 1,
        "native_stack_changes_measurement_deadline": False,
    }


def _diagnose_phase(
    report: dict[str, object],
    phase: str,
    captures: dict[str, dict[str, object]],
    *,
    port: int | None = None,
    responder: LoopbackPTRResponder | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + 5.0
    native_capture: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        probes_future = executor.submit(
            resolver_diagnostics,
            deadline=deadline,
            native_capture=native_capture if phase == "before" else None,
        )
        config_future = executor.submit(scutil_diagnostics, expected_port=port, deadline=deadline)
        selftest_future = executor.submit(responder.self_test, deadline=deadline) if responder is not None else None
        probes = probes_future.result()
        configuration, private = config_future.result()
        if selftest_future is not None:
            report["ptr_selftest"] = selftest_future.result()
    report[f"registration_{phase}"] = configuration
    captures[phase] = private
    if native_capture:
        captures["before_native_stack"] = native_capture
    report[f"probes_{phase}"] = probes
    report[phase] = probes["legacy_getfqdn"]
    native_stack = probes["libc_gethostbyaddr"].get("native_stack")
    if isinstance(native_stack, dict) and (
        native_stack.get("collector_cleanup_complete") is False or native_stack.get("probe_cleanup_complete") is False
    ):
        # Do not start either measured arm beside a collector that could remain
        # alive. This is a failed diagnostic, never a qualified observation.
        report["status"] = "diagnostic_cleanup_incomplete"
        raise RuntimeError("native_stack_cleanup_incomplete")
    return probes["legacy_getfqdn"]


def _write_report(output: Path, report: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _run_command(command: list[str]) -> int:
    return subprocess.run(command, check=False).returncode


def _terminate(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


def _run_wrapped(
    command: list[str], output: Path, report: dict[str, object], captures: dict[str, dict[str, object]]
) -> int:
    """Hold the exact DNS fixture around the entire paired build/measure command."""
    if sys.platform != "darwin":
        report["status"] = "not_macos"
        _write_report(output, report)
        return _run_command(command)
    before = _diagnose_phase(report, "before", captures)
    if before["status"] == "completed":
        report["status"] = "resolver_already_completed"
        _write_report(output, report)
        try:
            return _run_command(command)
        finally:
            _diagnose_phase(report, "after", captures)
            _write_report(output, report)
    report["experiment_attempted"] = True
    owner = secrets.token_hex(16)
    cleanup = "not_installed"
    returncode = 1
    try:
        responder = LoopbackPTRResponder()
    except OSError:
        report["status"] = "responder_unavailable"
        _write_report(output, report)
        return _run_command(command)
    with responder:
        # Removal is attempted even after helper timeout/failure: an interrupted
        # helper may have completed its exclusive create. Exact bytes guard it.
        try:
            report["configuration_install"] = _run_helper("install", responder.port, owner)
            _diagnose_phase(report, "after", captures, port=responder.port, responder=responder)
            report["status"] = "experiment_running"
            _write_report(output, report)
            returncode = _run_command(command)
            report["command_returncode"] = returncode
        finally:
            cleanup = (
                "not_owned"
                if report.get("configuration_install") == "existing_configuration"
                else _run_helper("remove", responder.port, owner)
            )
            report["configuration_cleanup"] = cleanup
            report["responder"] = responder.snapshot()
            report["status"] = "experiment_finished"
            _write_report(output, report)
    _diagnose_phase(report, "after_cleanup", captures, port=responder.port)
    _write_report(output, report)
    return returncode if cleanup in {"completed", "not_owned"} or returncode else 1


def _retain_captures(output: Path, report: dict[str, object], captures: dict[str, dict[str, object]]) -> None:
    if captures:
        parent = output.parent.parent if output.parent.name == "aggregate" else output.parent
        report["private_diagnostics_retained"] = retain_private_captures(parent / "private_samples", captures)
        _write_report(output, report)


def run_wrapped(command: list[str], output: Path) -> int:
    report = _base_report()
    captures: dict[str, dict[str, object]] = {}
    try:
        return _run_wrapped(command, output, report, captures)
    finally:
        # The paired driver requires an empty private sample directory on entry.
        # Bounded raw captures remain in memory until that command has exited.
        _retain_captures(output, report, captures)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if command:
        previous = signal.signal(signal.SIGTERM, _terminate)
        try:
            return run_wrapped(command, args.output)
        finally:
            signal.signal(signal.SIGTERM, previous)
    report = _base_report()
    captures: dict[str, dict[str, object]] = {}
    _diagnose_phase(report, "before", captures)
    report["status"] = "diagnostic_only"
    _retain_captures(args.output, report, captures)
    _write_report(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
