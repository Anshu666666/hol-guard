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
else:
    # Direct script execution puts this helper's directory on sys.path.
    from native_loopback_dns import LoopbackPTRResponder  # pyright: ignore[reportImplicitRelativeImport]

_QUERIES = {
    "legacy_getfqdn": "socket.getfqdn('127.0.0.1')",
    "reverse_getnameinfo": "socket.getnameinfo(('127.0.0.1',0),socket.NI_NAMEREQD|socket.NI_NUMERICSERV)[0]",
    "numeric_getnameinfo": "socket.getnameinfo(('127.0.0.1',0),socket.NI_NUMERICHOST|socket.NI_NUMERICSERV)[0]",
}
_STARTED = '{"phase":"call_started"}'


def _query(kind: str) -> str:
    return (
        "import json,socket; print('" + _STARTED + "',flush=True); name=" + _QUERIES[kind] + "; "
        "print(json.dumps({'loopback_label':name in "
        "('127.0.0.1','localhost','hol-guard-qualification.localhost')}))"
    )


def _call_started(output: str | bytes | None) -> bool:
    if isinstance(output, bytes):
        return output.startswith(_STARTED.encode("ascii") + b"\n")
    return isinstance(output, str) and output.startswith(_STARTED + "\n")


def resolver_probe(kind: str = "legacy_getfqdn", *, deadline: float | None = None) -> dict[str, object]:
    query = _query(kind)
    started = time.monotonic()
    result: dict[str, object] = {"status": "failed", "loopback_label": False, "call_started": False}
    try:
        timeout = 5.0 if deadline is None else min(5.0, max(0.0, deadline - started))
        if timeout == 0:
            raise subprocess.TimeoutExpired("fixed_resolver_probe", timeout)
        completed = subprocess.run(
            [sys.executable, "-I", "-c", query], capture_output=True, text=True, timeout=timeout, check=False
        )
        result["call_started"] = _call_started(completed.stdout)
        lines = completed.stdout.splitlines() if len(completed.stdout) <= 128 else []
        if completed.returncode == 0 and len(lines) == 2 and lines[0] == _STARTED:
            value = json.loads(lines[1])
            if isinstance(value, dict) and set(value) == {"loopback_label"} and type(value["loopback_label"]) is bool:
                result.update(status="completed", loopback_label=value["loopback_label"])
    except subprocess.TimeoutExpired as error:
        result["status"] = "deadline_exceeded"
        result["call_started"] = _call_started(error.output)
    except (OSError, ValueError):
        pass
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def resolver_diagnostics() -> dict[str, dict[str, object]]:
    """Run distinct fixed probes concurrently within one existing 5s wait.

    The numeric control requests no name lookup. These independent subprocesses
    never replace either installed arm's resolver or extend its startup deadline.
    """
    deadline = time.monotonic() + 5.0

    def probe(kind: str) -> dict[str, object]:
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
        "schema": "hol-guard.native-loopback-resolver.v2",
        "environment_scope": "disposable_ci_runner_both_arms",
        "baseline_artifact_modified": False,
        "runtime_patched": False,
        "fixture_deadline_changed": False,
        "qualification_pass": False,
        "mechanism": "exact_loopback_ptr_resolver",
        "experiment_attempted": False,
        "probe_timeout_seconds": 5,
        "probe_execution": "independent_concurrent_subprocesses",
    }


def _diagnose_phase(report: dict[str, object], phase: str) -> dict[str, object]:
    probes = resolver_diagnostics()
    report[f"probes_{phase}"] = probes
    report[phase] = probes["legacy_getfqdn"]
    return probes["legacy_getfqdn"]


def _write_report(output: Path, report: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _run_command(command: list[str]) -> int:
    return subprocess.run(command, check=False).returncode


def _terminate(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


def run_wrapped(command: list[str], output: Path) -> int:
    """Hold the exact DNS fixture around the entire paired build/measure command."""
    report = _base_report()
    if sys.platform != "darwin":
        report["status"] = "not_macos"
        _write_report(output, report)
        return _run_command(command)
    before = _diagnose_phase(report, "before")
    if before["status"] == "completed":
        report["status"] = "resolver_already_completed"
        _write_report(output, report)
        try:
            return _run_command(command)
        finally:
            _diagnose_phase(report, "after")
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
            _diagnose_phase(report, "after")
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
    _diagnose_phase(report, "after_cleanup")
    _write_report(output, report)
    return returncode if cleanup in {"completed", "not_owned"} or returncode else 1


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
    _diagnose_phase(report, "before")
    report["status"] = "diagnostic_only"
    _write_report(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
