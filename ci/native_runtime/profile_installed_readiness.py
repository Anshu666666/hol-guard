"""Separate source-level diagnostics after an original installed readiness failure.

Three predeclared fresh-process trials retain the original readiness function and
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
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from types import CodeType
from typing import Any

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))
from ci.native_runtime.installed_readiness_profile import ReadinessProfile, _code, publisher_targets  # noqa: E402
from ci.native_runtime.installed_scoped_policy_fixture import SignedPolicyFixture  # noqa: E402
from ci.native_runtime.probe_installed_scoped_policy import (  # noqa: E402
    ProbeError,
    environment_is_clean,
    require,
    require_initial_readiness,
)
from scripts.native_slo_session import stop_native_resident  # noqa: E402

_REPORT_LIMIT = 32_768
_TRIALS = ("control", "start", "publication")
_PROCESS_LIMIT_SECONDS = 30

_CHECKPOINT_LIMIT = 2_048
_PHASES = frozenset(
    {
        "trial_entry",
        "identity_check",
        "fixture_setup",
        "publisher_setup",
        "target_resolution",
        "readiness_call",
        "publisher_cleanup",
        "resident_cleanup",
        "fixture_cleanup",
        "temporary_cleanup",
        "report_write",
    }
)

_STACK_SAMPLE_AFTER_SECONDS = 25.0
_STACK_FRAME_LIMIT = 32
_STACK_LABELS = frozenset(
    {
        "path_resolve",
        "fixture_init",
        "fixture_certificate",
        "fixture_close",
        "store_init",
        "store_initialize",
        "store_initialize_once",
        "store_schema",
        "store_connect",
        "store_advisory_lock",
        "credential_lock",
        "credential_set",
        "secret_fingerprint",
        "secret_persist",
        "secret_mirror",
        "encrypted_secret_set",
        "encrypted_secret_get",
        "encrypted_secret_write",
        "dpop_key",
        "rsa_key",
        "server_init",
        "server_bind",
        "socket_fqdn",
        "tls_wrap",
        "thread_start",
        "readiness_call",
        "resident_stop",
    }
)


def _stack_targets() -> dict[str, object]:
    """Resolve implementation identities only; never inspect authority values."""
    import socket
    import socketserver
    import ssl
    from http.server import HTTPServer

    from cryptography.hazmat.primitives.asymmetric import rsa

    from codex_plugin_scanner.guard import store_base
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.store_connection_schema import StoreConnectionSchemaMixin
    from codex_plugin_scanner.guard.store_oauth import StoreOAuthConnectMixin
    from codex_plugin_scanner.guard.store_secret_policy_integrity import StoreSecretPolicyIntegrityMixin

    return {
        "path_resolve": Path.resolve,
        "fixture_init": SignedPolicyFixture.__init__,
        "fixture_certificate": SignedPolicyFixture._certificate,
        "fixture_close": SignedPolicyFixture.close,
        "store_init": StoreSecretPolicyIntegrityMixin.__init__,
        "store_initialize": StoreConnectionSchemaMixin._initialize_serialized,
        "store_initialize_once": StoreConnectionSchemaMixin._initialize_serialized_once,
        "store_schema": StoreConnectionSchemaMixin._initialize_schema,
        "store_connect": StoreConnectionSchemaMixin._connect_once,
        "store_advisory_lock": StoreConnectionSchemaMixin._hold_advisory_file_lock,
        "credential_lock": StoreConnectionSchemaMixin.hold_oauth_credential_lock,
        "credential_set": StoreOAuthConnectMixin._set_oauth_local_credentials_unlocked,
        "secret_fingerprint": store_base._secret_fingerprint,
        "secret_persist": StoreSecretPolicyIntegrityMixin._assert_oauth_secret_persisted,
        "secret_mirror": StoreSecretPolicyIntegrityMixin._mirror_oauth_secret_to_fallback,
        "encrypted_secret_set": store_base.EncryptedFileSecretStore.set_secret,
        "encrypted_secret_get": store_base.EncryptedFileSecretStore.get_secret,
        "encrypted_secret_write": store_base.EncryptedFileSecretStore._atomic_write_bytes,
        "dpop_key": generate_dpop_key_pair,
        "rsa_key": rsa.generate_private_key,
        "server_init": socketserver.TCPServer.__init__,
        "server_bind": HTTPServer.server_bind,
        "socket_fqdn": socket.getfqdn,
        "tls_wrap": ssl.SSLContext.wrap_socket,
        "thread_start": threading.Thread.start,
        "readiness_call": require_initial_readiness,
        "resident_stop": stop_native_resident,
    }


class TrialStackSample:
    """One sample of the creating thread; no profiler, locals, names or paths."""

    def __init__(
        self,
        targets: Mapping[str, object],
        checkpoint: Path,
        mode: str,
        source: str,
        runtime: str,
    ) -> None:
        if (
            mode not in _TRIALS
            or re.fullmatch(r"[0-9a-f]{40}", source) is None
            or re.fullmatch(r"[0-9a-f]{64}", runtime) is None
        ):
            raise ValueError("trial_stack_identity_invalid")
        self._owner = threading.current_thread()
        self._codes: dict[int, tuple[CodeType, str]] = {}
        for label, function in targets.items():
            if label not in _STACK_LABELS:
                continue
            code = _code(function)
            if code is not None:
                self._codes[id(code)] = (code, label)
        self._path = checkpoint.with_suffix(".stack.json")
        self._identity = {
            "schema": "guard.installed-readiness-trial-stack.v1",
            "trial": mode,
            "source_sha": source,
            "runtime_sha256": runtime,
        }
        self._cancel = threading.Event()
        self._worker = threading.Thread(target=self._run, daemon=True)

    def _wait_for_sample(self) -> bool:
        return self._cancel.wait(_STACK_SAMPLE_AFTER_SECONDS)

    def _snapshot(self) -> dict[str, object]:
        unavailable: dict[str, object] = {"available": False, "labels": []}
        frame = None
        try:
            identity = self._owner.ident
            if identity is None or not self._owner.is_alive():
                return unavailable
            frame = sys._current_frames().get(identity)
            labels: list[str] = []
            for _ in range(_STACK_FRAME_LIMIT):
                if frame is None:
                    break
                code = frame.f_code
                admitted = self._codes.get(id(code))
                if admitted is not None and code is admitted[0] and admitted[1] not in labels:
                    labels.append(admitted[1])
                frame = frame.f_back
            if not self._owner.is_alive():
                return unavailable
            return {"available": bool(labels), "labels": labels}
        except BaseException:
            return unavailable
        finally:
            frame = None

    def _run(self) -> None:
        with suppress(BaseException):
            if self._wait_for_sample():
                return
            value = {**self._identity, **self._snapshot()}
            if not self._cancel.is_set():
                payload = json.dumps(value, sort_keys=True) + "\n"
                if len(payload.encode("utf-8")) <= _CHECKPOINT_LIMIT:
                    self._path.write_text(payload, encoding="utf-8")

    def start(self) -> None:
        with suppress(BaseException):
            self._worker.start()

    def close(self) -> bool:
        self._cancel.set()
        with suppress(BaseException):
            if self._worker.ident is not None:
                self._worker.join(timeout=0.1)
        return not self._worker.is_alive()


def read_trial_stack(checkpoint: Path, mode: str, source: str, runtime: str) -> dict[str, object]:
    """Project an exact bound sample; missing or unrecognized evidence stays unavailable."""
    result: dict[str, object] = {
        "trial": mode,
        "available": False,
        "labels": [],
        "observation": "one_trial_thread_stack_sample",
        "timing_claim": False,
    }
    with suppress(OSError, ValueError, UnicodeError):
        with checkpoint.with_suffix(".stack.json").open("rb") as handle:
            payload = handle.read(_CHECKPOINT_LIMIT + 1)
        if len(payload) > _CHECKPOINT_LIMIT:
            return result
        value = json.loads(payload)
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "trial",
            "source_sha",
            "runtime_sha256",
            "available",
            "labels",
        }:
            return result
        labels, available = value["labels"], value["available"]
        if (
            value["schema"] != "guard.installed-readiness-trial-stack.v1"
            or value["trial"] != mode
            or value["source_sha"] != source
            or value["runtime_sha256"] != runtime
            or type(available) is not bool
            or not isinstance(labels, list)
            or len(labels) > _STACK_FRAME_LIMIT
            or any(not isinstance(label, str) or label not in _STACK_LABELS for label in labels)
            or len(set(labels)) != len(labels)
            or bool(labels) is not available
        ):
            return result
        result.update(available=available, labels=labels)
    return result


def write_checkpoint(path: Path | None, mode: str, source: str, runtime: str, phase: str) -> None:
    """Retain only a fixed last-entered boundary, without timing or error text."""
    if (
        path is None
        or phase not in _PHASES
        or mode not in _TRIALS
        or not isinstance(source, str)
        or re.fullmatch(r"[0-9a-f]{40}", source) is None
        or not isinstance(runtime, str)
        or re.fullmatch(r"[0-9a-f]{64}", runtime) is None
    ):
        return
    record = {
        "schema": "guard.installed-readiness-trial-checkpoint.v1",
        "trial": mode,
        "source_sha": source,
        "runtime_sha256": runtime,
        "phase": phase,
    }
    with suppress(OSError):
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")


def read_checkpoint(path: Path, mode: str, source: str, runtime: str) -> str:
    try:
        with path.open("rb") as handle:
            payload = handle.read(_CHECKPOINT_LIMIT + 1)
        if len(payload) > _CHECKPOINT_LIMIT:
            return "unavailable"
        value = json.loads(payload)
        if not isinstance(value, dict):
            return "unavailable"
        phase = value.get("phase")
        if (
            value.get("schema") != "guard.installed-readiness-trial-checkpoint.v1"
            or value.get("trial") != mode
            or value.get("source_sha") != source
            or value.get("runtime_sha256") != runtime
            or not isinstance(phase, str)
            or phase not in _PHASES
        ):
            return "unavailable"
        return phase
    except (OSError, ValueError, UnicodeError):
        return "unavailable"


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


def trial(mode: str, source_sha: str, runtime_sha256: str, *, checkpoint: Path | None = None) -> dict[str, object]:
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
    write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "trial_entry")
    require(mode in _TRIALS, "trial_invalid")
    require("site-packages" in Path(codex_plugin_scanner.__file__).resolve().parts, "not_installed_package")
    require(environment_is_clean(os.environ) and native_mode() == "auto", "native_environment_override")
    require(os.environ.get("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT") == "1", "canonical_lane_disabled")
    write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "identity_check")
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
        stack_sample: TrialStackSample | None = None

        def cleanup_runtime() -> None:
            nonlocal runtime_cleanup_attempted
            if runtime_cleanup_attempted:
                return
            runtime_cleanup_attempted = True
            failed = False
            if publisher is not None:
                write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "publisher_cleanup")
                try:
                    publisher.close()
                except BaseException:
                    failed = True
            if fixture is not None:
                write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "resident_cleanup")
                try:
                    stopped = stop_native_resident(identity.path, fixture.store.guard_home, write_diagnostic=False)
                    failed = failed or not stopped.contained
                except BaseException:
                    failed = True
                report["cleanup"] = "failed" if failed else "contained"

        try:
            if checkpoint is not None:
                with suppress(BaseException):
                    stack_sample = TrialStackSample(_stack_targets(), checkpoint, mode, source_sha, runtime_sha256)
                    stack_sample.start()
            write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "fixture_setup")
            fixture = SignedPolicyFixture(Path(temporary).resolve())
            os.environ["SSL_CERT_FILE"] = str(fixture.ca_file)
            write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "publisher_setup")
            publisher = get_native_policy_snapshot_publisher(fixture.store)
            write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "target_resolution")
            observation = ReadinessProfile(
                publisher_targets(publisher),
                enabled=mode != "control",
                window="start" if mode == "start" else "publication",
            )
            with observation.attach(publisher):
                try:
                    write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "readiness_call")
                    started = time.monotonic()
                    try:
                        require_initial_readiness(publisher, fixture.workspace)
                        report["outcome"] = "ready_observed"
                    except ProbeError as error:
                        report["outcome"] = (
                            "readiness_deadline" if str(error) == "readiness_deadline" else "probe_refused"
                        )
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
                write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "fixture_cleanup")
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
            if stack_sample is not None:
                sample_contained = stack_sample.close()
                if not sample_contained and report["cleanup"] == "contained":
                    report["cleanup"] = "unverified"
            write_checkpoint(checkpoint, mode, source_sha, runtime_sha256, "temporary_cleanup")
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
        "trial_stack_samples": [],
    }
    if runtime is None:
        report["disposition"] = "original_readiness_failure_not_admitted"
        return report
    report["runtime_sha256"] = runtime
    results: list[dict[str, Any]] = []
    stack_samples: list[dict[str, object]] = []

    def unavailable(mode: str, checkpoint: Path, reason: str) -> dict[str, object]:
        return {
            "trial": mode,
            "outcome": "trial_unavailable",
            "cleanup": "unverified",
            "unavailable_reason": reason,
            "last_entered_phase": read_checkpoint(checkpoint, mode, expected_source, runtime),
            "phase_semantics": "last_entered_boundary_without_duration",
        }

    with tempfile.TemporaryDirectory(prefix="hg-readiness-reports-") as temporary:
        for mode in _TRIALS:
            output = Path(temporary) / (mode + ".json")
            checkpoint = Path(temporary) / (mode + ".checkpoint.json")
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
                        "--checkpoint",
                        str(checkpoint),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=_PROCESS_LIMIT_SECONDS,
                )
                if completed.returncode != 0:
                    results.append(unavailable(mode, checkpoint, "process_exit_failed"))
                    break
                result = read_report(output)
                if result is None:
                    results.append(unavailable(mode, checkpoint, "trial_report_unavailable"))
                    break
                if (
                    result.get("schema") != "guard.installed-readiness-profile-trial.v1"
                    or result.get("source_sha") != expected_source
                    or result.get("runtime_sha256") != runtime
                    or result.get("trial") != mode
                    or result.get("acceptance_claim") is not False
                ):
                    results.append(unavailable(mode, checkpoint, "trial_report_rejected"))
                    break
                results.append(result)
                if result.get("cleanup") != "contained":
                    break
            except subprocess.TimeoutExpired:
                results.append(unavailable(mode, checkpoint, "process_timeout"))
                break
            except OSError:
                results.append(unavailable(mode, checkpoint, "process_launch_failed"))
                break
            finally:
                stack_samples.append(read_trial_stack(checkpoint, mode, expected_source, runtime))
    report["trials"] = results
    report["trial_stack_samples"] = stack_samples
    report["disposition"] = "diagnostic_only"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--original-report", type=Path)
    parser.add_argument("--trial", choices=_TRIALS)
    parser.add_argument("--expected-runtime-sha256")
    parser.add_argument("--checkpoint", type=Path)
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
            result = trial(
                args.trial, args.expected_source_sha, args.expected_runtime_sha256, checkpoint=args.checkpoint
            )
        else:
            result = run_trials(
                read_report(args.original_report) if args.original_report else None, args.expected_source_sha
            )
        payload = json.dumps(result, sort_keys=True, allow_nan=False) + "\n"
        if len(payload.encode("utf-8")) > _REPORT_LIMIT:
            raise ValueError("profile_report_limit")
    except BaseException:
        payload = '{"schema":"guard.installed-readiness-profile-error.v1","acceptance_claim":false}\n'
    if args.trial:
        write_checkpoint(
            args.checkpoint, args.trial, args.expected_source_sha, args.expected_runtime_sha256, "report_write"
        )
    args.json.write_text(payload, encoding="utf-8")
    if not args.trial:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
