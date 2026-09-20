"""One real first policy push through an explicitly diagnostic one-shot client."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _MAX_ACK_BYTES
from codex_plugin_scanner.guard.native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _ack_from_resident_output
from codex_plugin_scanner.guard.store import GuardStore

_MAX_STDOUT = _MAX_ACK_BYTES
_MAX_STDERR = 16_384 + 256
_PHASES = {"connect", "authenticate", "request_write_flush", "committed_response_read"}
_IO_KINDS = {
    "timed_out",
    "would_block",
    "interrupted",
    "unexpected_eof",
    "broken_pipe",
    "connection_reset",
    "connection_aborted",
    "connection_refused",
    "permission_denied",
    "invalid_input",
    "unsupported",
    "other",
}
_CODES = FINITE_FAILURE_CODES | {"unregistered_error"}


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


@dataclass
class ProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    timed_out: bool
    overflow: bool
    reaped: bool


def run_bounded(argv: list[str], payload: bytes, environment: dict[str, str], deadline: float) -> ProcessResult:
    """Drain both streams while the original absolute caller budget runs."""
    require(len(payload) <= 6 * 1024 * 1024, "input_bound")
    if time.monotonic() >= deadline:
        return ProcessResult(b"", b"", None, True, False, True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": _MAX_STDOUT, "stderr": _MAX_STDERR}
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=Path(argv[0]).parent,
        start_new_session=True,
    )
    timed_out = overflow = False
    position = 0
    try:
        with selectors.DefaultSelector() as selector:
            assert process.stdin is not None and process.stdout is not None and process.stderr is not None
            for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if payload:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    if key.data == "stdin":
                        try:
                            position += os.write(key.fd, payload[position : position + 4096])
                        except BrokenPipeError:
                            position = len(payload)
                        if position == len(payload):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                        continue
                    chunk = os.read(key.fd, min(65536, limits[key.data] - len(output[key.data]) + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        capacity = limits[key.data] - len(output[key.data])
                        output[key.data].extend(chunk[:capacity])
                        if len(chunk) > capacity:
                            overflow = True
                            break
                if overflow:
                    break
            if not timed_out and not overflow:
                try:
                    process.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
    finally:
        if process.poll() is None:
            with suppress(ProcessLookupError):
                process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=0.5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    return ProcessResult(
        bytes(output["stdout"]),
        bytes(output["stderr"]),
        process.returncode,
        timed_out,
        overflow,
        process.poll() is not None,
    )


def _integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def parse_diagnostic(stderr: bytes, payload: bytes) -> dict[str, Any]:
    """Reject unknown fields before retaining any native diagnostic record."""
    require(len(stderr) <= _MAX_STDERR, "stderr_bound")
    lines = stderr.splitlines()
    records = [line for line in lines if line.startswith(b"{")]
    require(len(records) == 1 and len(records[0]) < 16_384, "diagnostic_record_count")
    value = json.loads(records[0])
    expected = {
        "schema",
        "scope",
        "operation_succeeded",
        "operation_error",
        "operation_elapsed_us",
        "deadline_budget_ms",
        "payload_bytes",
        "payload_sha256",
        "events",
        "maximum_events",
        "dropped_events",
        "original_fatal_code",
        "detail_incomplete",
        "original_operation_result_preserved",
        "headline_timing_eligible",
        "qualification",
        "retries_added",
        "deadlines_changed",
    }
    require(type(value) is dict and set(value) == expected, "diagnostic_fields")
    value = cast(dict[str, Any], value)
    require(value["schema"] == "hol-guard.resident-startup-diagnostic.v1", "diagnostic_schema")
    require(value["scope"] == "single_explicit_managed_client_operation", "diagnostic_scope")
    require(value["deadline_budget_ms"] == 2000 and type(value["deadline_budget_ms"]) is int, "native_budget")
    require(value["payload_bytes"] == len(payload) and type(value["payload_bytes"]) is int, "payload_length")
    require(value["payload_sha256"] == hashlib.sha256(payload).hexdigest(), "payload_digest")
    require(value["maximum_events"] == 16 and type(value["maximum_events"]) is int, "event_bound")
    require(_integer(value["operation_elapsed_us"], 60_000_000), "elapsed_bound")
    require(_integer(value["dropped_events"], 2**64 - 1), "dropped_bound")
    for key in ("operation_error", "original_fatal_code"):
        require(value[key] is None or (isinstance(value[key], str) and value[key] in _CODES), "error_label")
    for key in ("operation_succeeded", "detail_incomplete"):
        require(type(value[key]) is bool, "boolean_field")
    for key in ("headline_timing_eligible", "qualification", "retries_added", "deadlines_changed"):
        require(value[key] is False, "diagnostic_claim")
    require(value["original_operation_result_preserved"] is True, "result_claim")
    events = value["events"]
    if not isinstance(events, list) or len(events) > 16:
        raise ValueError("events_bound")
    for event in events:
        require(
            type(event) is dict
            and set(event)
            == {
                "phase",
                "started_us",
                "duration_us",
                "succeeded",
                "error_code",
                "retryable_teardown",
                "io_failure",
            },
            "event_fields",
        )
        event = cast(dict[str, Any], event)
        require(isinstance(event["phase"], str) and event["phase"] in _PHASES, "phase_label")
        require(all(_integer(event[key], 60_000_000) for key in ("started_us", "duration_us")), "phase_time")
        require(all(type(event[key]) is bool for key in ("succeeded", "retryable_teardown")), "phase_boolean")
        require(
            event["error_code"] is None or (isinstance(event["error_code"], str) and event["error_code"] in _CODES),
            "phase_error",
        )
        failure = event["io_failure"]
        if failure is not None:
            require(type(failure) is dict and set(failure) == {"kind", "os_code"}, "io_fields")
            failure = cast(dict[str, Any], failure)
            require(isinstance(failure["kind"], str) and failure["kind"] in _IO_KINDS, "io_kind")
            require(
                failure["os_code"] is None
                or (type(failure["os_code"]) is int and -(2**31) <= failure["os_code"] < 2**31),
                "io_code",
            )
    return value


def first_payload(publisher: NativePolicySnapshotPublisher) -> tuple[bytes, dict[str, object]]:
    """Use original provisioning, verified context, generation and encoder helpers."""
    publisher._provision_verifier_key()
    context = publisher._publication_context()
    require(context is not None, "publisher_context_unavailable")
    assert context is not None
    identity, capabilities, master_key, config, extensions, _client = context
    try:
        snapshot = native_policy_snapshot_v3(
            config=config,
            guard_home=publisher.guard_home,
            runtime_identity=identity.sha256,
            rule_digest=capabilities.rule_digest,
            policy_integrity_key=master_key,
            issued_at_ms=int(publisher._wall_clock() * 1000),
            deadline_monotonic=publisher._monotonic_clock() + 2.0,
            renew_after_generation=None,
            command_extensions=extensions,
        )
        return _policy_snapshot_push_bytes_v3(snapshot), snapshot
    finally:
        master_key = context = None


def _process_summary(result: ProcessResult) -> dict[str, object]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_overflow": result.overflow,
        "direct_child_reaped": result.reaped,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
    }


def cleanup(executable: Path, home: Path, environment: dict[str, str]) -> dict[str, object]:
    result = run_bounded(
        [str(executable), "resident-stop", "--state-dir", str(home / "native-runtime")],
        b"",
        environment,
        time.monotonic() + 3.0,
    )
    state_absent = not any((home / "native-runtime").glob("resident-v3-*/generation-*.json"))
    authenticated_stop = result.returncode == 0 and not result.timed_out and not result.overflow and result.reaped
    return {
        **_process_summary(result),
        "authenticated_stop_succeeded": authenticated_stop,
        "resident_state_absent": state_absent,
        "contained": authenticated_stop and state_absent,
        "scope": "ordinary_authenticated_resident_stop_and_direct_child_reap",
    }


@contextmanager
def _temporary_home(report: dict[str, Any]) -> Iterator[str]:
    temporary = tempfile.TemporaryDirectory(prefix="hg-phase-", dir="/tmp")
    try:
        yield temporary.name
    finally:
        try:
            temporary.cleanup()
        except Exception:
            report["temporary_cleanup_failed"] = True


def run_probe(expected_sha: str) -> dict[str, Any]:
    require(sys.platform == "darwin" and bool(sys.flags.isolated), "isolated_macos_required")
    require(
        not any(name.startswith(("HOL_GUARD_", "GUARD_", "PYTEST_")) or name == "PYTHONPATH" for name in os.environ),
        "environment_override",
    )
    distribution = importlib.metadata.distribution("hol-guard")
    expected_module = Path(str(distribution.locate_file("codex_plugin_scanner/guard/native_runtime.py"))).resolve()
    require(
        Path(runtime.__file__).resolve() == expected_module and "site-packages" in expected_module.parts,
        "installed_import_required",
    )
    status = runtime.native_runtime_status()
    require(
        status.mode == "auto" and status.available and status.compatible and status.reason == "native_ready",
        "installed_identity_unavailable",
    )
    identity, capabilities = status.identity, status.capabilities
    require(identity is not None and capabilities is not None, "installed_identity_missing")
    assert identity is not None and capabilities is not None
    require(capabilities.build_sha == expected_sha, "diagnostic_build_mismatch")
    require(runtime._validate_binary(identity.path) == identity, "initial_binary_identity_changed")
    report: dict[str, Any] = {
        "schema": "hol-guard.native-startup-phase-driver.v1",
        "diagnostic_only": True,
        "qualification": False,
        "scope": "single_cold_real_policy_push_explicit_one_shot_client",
        "production_client": "persistent_framed_stream",
        "diagnostic_client": "resident-client-diagnostic",
        "native_budget_ms": 2000,
        "outer_budget_ms": 2000,
        "retries_added": False,
        "publication_requests": 0,
        "ack_validated": False,
        "observation_complete": False,
        "publisher_close_failed": False,
        "identity_revalidation_failed": False,
        "temporary_cleanup_failed": False,
        "identity": {
            "sha256": identity.sha256,
            "size": identity.size,
            "build_sha": capabilities.build_sha,
            "target": capabilities.target,
            "rule_digest": capabilities.rule_digest,
        },
    }
    environment = runtime._isolated_environment()
    with _temporary_home(report) as temporary:
        home = Path(temporary) / "guard-home"
        publisher = None
        try:
            publisher = NativePolicySnapshotPublisher(store=GuardStore(home))
            payload, snapshot = first_payload(publisher)
            require(not any((home / "native-runtime").glob("resident-v3-*/generation-*.json")), "cold_state_required")
            report["publication_requests"] = 1
            deadline = time.monotonic() + 2.0
            result = run_bounded(
                [str(identity.path), "resident-client-diagnostic", "--stdin", str(home / "native-runtime")],
                payload,
                environment,
                deadline,
            )
            report["process"] = _process_summary(result)
            report["native"] = parse_diagnostic(result.stderr, payload)
            if result.returncode == 0 and not result.timed_out and not result.overflow:
                ack = _ack_from_resident_output(result.stdout)
                report["ack_validated"] = bool(
                    ack
                    and ack["status"] == "accepted"
                    and ack["generation"] == snapshot["generation"]
                    and ack["policy_digest"] == snapshot["policy_digest"]
                )
            report["observation_complete"] = (
                not result.timed_out
                and not result.overflow
                and result.reaped
                and not report["native"]["detail_incomplete"]
            )
        except Exception as error:
            report["failure_category"] = type(error).__name__
        finally:
            if publisher is not None:
                try:
                    publisher.close()
                except Exception:
                    report["publisher_close_failed"] = True
            try:
                report["cleanup"] = cleanup(identity.path, home, environment)
            except Exception as error:
                report["cleanup"] = {"contained": False, "failure_category": type(error).__name__}
            try:
                report["binary_identity_unchanged"] = runtime._validate_binary(identity.path) == identity
            except Exception:
                report["binary_identity_unchanged"] = False
                report["identity_revalidation_failed"] = True
    report["observation_complete"] = bool(
        report["observation_complete"]
        and report["cleanup"]["contained"]
        and report["binary_identity_unchanged"]
        and not report["publisher_close_failed"]
        and not report["temporary_cleanup_failed"]
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_probe(args.expected_source_sha)
    except Exception as error:
        report = {
            "schema": "hol-guard.native-startup-phase-driver.v1",
            "qualification": False,
            "observation_complete": False,
            "failure_category": type(error).__name__,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report.get("observation_complete") else 2


if __name__ == "__main__":
    raise SystemExit(main())
