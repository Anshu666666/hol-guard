"""Finite installed-wheel resident registration and scoped-shutdown witness.

Run with the verified wheel interpreter and -I. This is evidence tooling, not
production code. It sends real authenticated health requests through the public
Python client API and uses the public scoped close APIs without replacing any
transport, stop operation, registry, or native implementation. A second Python
process holds idle real streams so local-client closure is observed beyond the
native one-second lease expiry. Private internals are inspected, never modified.

Only two freshly created private homes are used. The receipt never contains
resident tokens, MACs, environment values, or endpoint paths. A failure remains
a failure even if subsequent scoped cleanup succeeds. PIDFD exit is reported
separately from reaping: an orphaned supervisor may remain a zombie under PID 1.
This witness covers lifecycle transport, not hook/policy semantic qualification.
The production key-provisioning API creates the native runtime directory before
first request. This corrected fixture proves first resident registration, not
registration while the native runtime directory is absent. The earlier failed
unprovisioned attempt is a separate immutable artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import importlib.metadata
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

SOURCE_SHA = "8156ba5ec1e69908290d481bad421ba5f9bd93b2"
SOURCE_TREE = "1c551084cffda3f73ec410b432f0455579502754"
BUILD_SHA = "c331bb1ac5d9ee2082ea379713490b5b6d41e782"
WHEEL_SHA = "7b82fa210d88b2e4be3f21791101a9a0d378cd7df29205ee13fe024388c97bc8"
RUNTIME_SHA = "679da56f12eca504da0e3bc65b9abb99b1109e4caab2deb6961283865db9b2ba"
MANIFEST_SHA = "fa20cf9b73c6d7b695ab6f4c8888153f83f3451a6f0190c03fa5175a12c78b12"
ARTIFACT_SHA = "857e3701e64130d078b4483a7d5b3dc8267a6ae9e348ef1322c28f6810f8f14c"
HEALTH = b'{"operation":"health","request":{}}'
MODULES = (
    "native_runtime",
    "native_runtime_identity",
    "native_resident_client",
    "native_resident_stream",
    "native_resident_transport",
    "codex_hook_launch_runtime",
    "native_policy_snapshot",
    "native_policy_snapshot_codec",
    "native_policy_snapshot_constants",
    "native_policy_snapshot_windows_key",
    "native_policy_snapshot_windows_support",
)
SAFE_HEALTH_ERROR_CODES = frozenset(
    {
        "native_resident_start_timeout",
        "native_resident_start_in_progress",
        "native_resident_live_request_failed",
        "native_resident_restart_circuit_open",
        "native_client_deadline_exceeded",
        "native_request_invalid_json",
        "native_response_encode_failed",
        "native_resident_spawn_containment_failed",
    }
)
STATE_FIELDS = (
    "schema",
    "generation",
    "process_id",
    "process_start_marker",
    "owner_process_id",
    "owner_process_start_marker",
    "runtime_sha256",
    "transport",
    "endpoint",
    "token_hex",
    "created_ms",
)


class Failure(RuntimeError):
    """Only fixed, privacy-safe reason strings may be supplied."""


class HealthFailure(Failure):
    def __init__(self, reason: str, diagnostic: dict[str, Any]):
        super().__init__(reason)
        self.diagnostic = diagnostic


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Failure(reason)


def safe_error(error: BaseException) -> str:
    return str(error) if isinstance(error, Failure) else type(error).__name__


def bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        content = handle.read(maximum + 1)
    require(0 < len(content) <= maximum, "bounded_file_size")
    return content


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(content: bytes) -> Any:
    return json.loads(content, object_pairs_hook=no_duplicate_keys)


def ready(response: bytes | None) -> None:
    require(
        isinstance(response, bytes) and 0 < len(response) <= 1024,
        "health_response_size",
    )
    value = decode(response)
    require(
        type(value) is dict and set(value) == {"status", "protocol_version"},
        "health_response_shape",
    )
    require(
        value["status"] == "ready"
        and type(value["protocol_version"]) is int
        and value["protocol_version"] == 2,
        "health_response_value",
    )


def installed(wheel: Path) -> tuple[Any, Any, Path, dict[str, str], dict[str, Any]]:
    require(
        sys.platform == "linux" and hasattr(os, "pidfd_open"), "linux_pidfd_required"
    )
    require(bool(sys.flags.isolated), "isolated_interpreter_required")
    forbidden = (
        "HOL_GUARD_",
        "GUARD_NATIVE",
        "GUARD_TEST_",
        "GUARD_ORACLE",
        "GUARD_DIAGNOSTIC",
        "GUARD_BINARY",
        "GUARD_FAST_PATH",
        "GUARD_HOOK_BINARY",
        "GUARD_HOOK_FAST_PATH",
        "GUARD_HOOK_SOURCE_REF",
        "GUARD_PYTHON_ORACLE",
        "GUARD_PYTEST_",
        "PYTEST_",
    )
    require(
        not any(
            name.startswith(forbidden) or name == "PYTHONPATH" for name in os.environ
        ),
        "environment_override",
    )
    require(digest(bounded(wheel, 64 * 1024 * 1024)) == WHEEL_SHA, "wheel_digest")
    distribution = importlib.metadata.distribution("hol-guard")
    direct_url = distribution.read_text("direct_url.json")
    if direct_url is not None:
        require(
            not json.loads(direct_url).get("dir_info", {}).get("editable", False),
            "editable_install",
        )
    hashes: dict[str, str] = {}
    loaded: dict[str, Any] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in MODULES:
            member = "codex_plugin_scanner/guard/" + name + ".py"
            module = importlib.import_module("codex_plugin_scanner.guard." + name)
            module_path = Path(module.__file__).resolve()
            require(
                module_path == Path(str(distribution.locate_file(member))).resolve(),
                "wheel_import_location",
            )
            require(
                "site-packages" in module_path.parts, "wheel_site_packages_required"
            )
            content = bounded(module_path, 1024 * 1024)
            require(content == archive.read(member), "wheel_module_bytes")
            hashes[member] = digest(content)
            loaded[name] = module
    runtime, client = loaded["native_runtime"], loaded["native_resident_client"]
    status = runtime.native_runtime_status()
    require(
        status.mode == "auto" and status.available and status.compatible,
        "bundled_auto_admission",
    )
    require(
        status.identity is not None and status.capabilities is not None,
        "native_identity_missing",
    )
    executable = status.identity.path
    require(
        executable == runtime._bundled_runtime_candidate().resolve(),
        "bundled_executable_required",
    )
    require(
        status.identity.sha256 == RUNTIME_SHA
        and digest(bounded(executable, 64 * 1024 * 1024)) == RUNTIME_SHA,
        "runtime_digest",
    )
    manifest_bytes = bounded(executable.with_name("runtime-manifest.json"), 16384)
    require(digest(manifest_bytes) == MANIFEST_SHA, "manifest_digest")
    manifest = decode(manifest_bytes)
    require(
        manifest["source_sha"] == BUILD_SHA
        and status.capabilities.build_sha == BUILD_SHA,
        "build_identity",
    )
    require(
        manifest["runtime_sha256"] == RUNTIME_SHA
        and manifest["runtime_size"] == 12400288,
        "manifest_runtime_identity",
    )
    require(status.capabilities.protocol_version == 1, "native_protocol_identity")
    features = {
        "resident-protocol-v2",
        "native-resident-client-v1",
        "native-resident-lifecycle-v1",
        "authenticated-unix-resident-v1",
    }
    require(features <= set(status.capabilities.features), "resident_capabilities")
    provenance = {
        "published_source_sha": SOURCE_SHA,
        "source_tree": SOURCE_TREE,
        "build_sha": BUILD_SHA,
        "artifact_id": 10573761511,
        "artifact_zip_sha256": ARTIFACT_SHA,
        "wheel_sha256": WHEEL_SHA,
        "runtime_sha256": RUNTIME_SHA,
        "manifest_sha256": MANIFEST_SHA,
        "python_modules_sha256": hashes,
        "python_version": sys.version.split()[0],
        "package_version": distribution.version,
        "native_protocol_version": 1,
        "resident_protocol_version": 2,
        "mode": status.mode,
    }
    return runtime, client, executable, runtime._isolated_environment(), provenance


def private_directory(path: Path) -> None:
    metadata = path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_mode & 0o077 == 0,
        "private_directory_identity",
    )


def compact_directory(home: Path) -> Path:
    scope = home / "native-runtime" / ("resident-v3-" + RUNTIME_SHA[:16])
    return Path("/tmp") / (
        "hgr-" + RUNTIME_SHA[:8] + "-" + digest(os.fsencode(scope))[:8]
    )


def generation_files(home: Path) -> list[Path]:
    private_directory(home)
    base = home / "native-runtime"
    if not os.path.lexists(base):
        return []
    private_directory(base)
    found: list[Path] = []
    with os.scandir(base) as entries:
        scopes = list(entries)
    require(len(scopes) <= 32, "state_scope_count")
    for entry in scopes:
        if not entry.name.startswith("resident-v3-"):
            continue
        require(
            re.fullmatch(r"resident-v3-[0-9a-f]{16}", entry.name) is not None,
            "state_scope_name",
        )
        scope = Path(entry.path)
        private_directory(scope)
        with os.scandir(scope) as entries:
            candidates = list(entries)
        require(len(candidates) <= 64, "state_file_count")
        for candidate in candidates:
            if candidate.name.startswith("generation-") and candidate.name.endswith(
                ".json"
            ):
                require(
                    re.fullmatch(r"generation-[0-9]{20}\.json", candidate.name)
                    is not None,
                    "generation_file_name",
                )
                found.append(Path(candidate.path))
    return found


def read_state(home: Path) -> tuple[Path, dict[str, Any]]:
    paths = generation_files(home)
    require(len(paths) == 1, "one_native_generation_required")
    path = paths[0]
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and metadata.st_mode & 0o077 == 0
            and metadata.st_nlink == 1,
            "private_state_identity",
        )
        content = os.read(descriptor, 16385)
    finally:
        os.close(descriptor)
    require(0 < len(content) <= 16384, "native_state_size")
    value = decode(content)
    require(
        type(value) is dict and set(value) == set(STATE_FIELDS) | {"state_mac"},
        "native_state_shape",
    )
    require(
        value["schema"] == "hol-guard-resident-state.v3"
        and value["runtime_sha256"] == RUNTIME_SHA,
        "native_state_identity",
    )
    for key in ("generation", "process_id", "owner_process_id", "created_ms"):
        require(
            type(value[key]) is int and value[key] > 0, "native_state_numeric_identity"
        )
    require(
        path.name == f"generation-{value['generation']:020d}.json",
        "native_generation_filename",
    )
    require(
        path.parent.name == "resident-v3-" + RUNTIME_SHA[:16], "native_scope_runtime"
    )
    require(
        value["transport"] == "unix"
        and type(value["endpoint"]) is str
        and len(value["endpoint"]) <= 2048,
        "native_unix_transport",
    )
    endpoint = Path(value["endpoint"])
    compact = Path("/tmp") / (
        "hgr-" + RUNTIME_SHA[:8] + "-" + digest(os.fsencode(path.parent))[:8]
    )
    require(
        endpoint.is_absolute()
        and (
            endpoint.parent == path.parent
            or (
                endpoint.parent == compact
                and endpoint.name.startswith("h3-" + RUNTIME_SHA[:8] + "-")
            )
        ),
        "native_endpoint_scope",
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", value["token_hex"]) is not None
        and re.fullmatch(r"[0-9a-f]{64}", value["state_mac"]) is not None,
        "native_auth_encoding",
    )
    message = "\0".join(str(value[field]) for field in STATE_FIELDS).encode()
    expected = hmac.new(
        bytes.fromhex(value["token_hex"]),
        b"hol-guard-resident-state-v3\0" + message,
        hashlib.sha256,
    ).hexdigest()
    require(hmac.compare_digest(expected, value["state_mac"]), "native_state_mac")
    return path, value


def proc_stat(pid: int) -> dict[str, Any] | None:
    try:
        raw = bounded(Path(f"/proc/{pid}/stat"), 4096).decode()
    except FileNotFoundError:
        return None
    require(raw.startswith(str(pid) + " ("), "proc_pid_identity")
    fields = raw[raw.rfind(")") + 2 :].split()
    require(len(fields) >= 20 and fields[19].isdigit(), "proc_start_identity")
    return {
        "pid": pid,
        "start_marker": "linux:" + fields[19],
        "state": fields[0],
        "parent_pid": int(fields[1]),
        "process_group": int(fields[2]),
    }


@dataclass
class Process:
    pid: int
    marker: str
    fd: int
    role: str
    initial: dict[str, Any]

    @classmethod
    def capture(
        cls, pid: int, marker: str | None, role: str, executable: Path
    ) -> Process:
        require(type(pid) is int and pid > 0, "capture_pid")
        initial = proc_stat(pid)
        require(
            initial is not None and initial["state"] not in {"Z", "X", "x"},
            "capture_live_process",
        )
        require(
            marker is None or initial["start_marker"] == marker, "capture_start_marker"
        )
        descriptor = os.pidfd_open(pid, 0)
        try:
            image = Path(f"/proc/{pid}/exe")
            require(
                Path(f"/proc/{pid}").stat().st_uid == os.getuid(),
                "capture_process_owner",
            )
            require(image.resolve(strict=True) == executable, "capture_executable_path")
            require(image.stat().st_uid == os.getuid(), "capture_executable_owner")
            require(
                digest(bounded(image, 64 * 1024 * 1024)) == RUNTIME_SHA,
                "capture_executable_bytes",
            )
            command = bounded(Path(f"/proc/{pid}/cmdline"), 8192).split(b"\0")
            require(
                len(command) >= 2 and command[1] == role.encode(), "capture_native_role"
            )
            current = proc_stat(pid)
            require(
                current is not None
                and current["start_marker"] == initial["start_marker"]
                and current["state"] not in {"Z", "X", "x"},
                "capture_identity_changed",
            )
            return cls(pid, initial["start_marker"], descriptor, role, initial)
        except BaseException:
            os.close(descriptor)
            raise

    def events(self) -> int:
        poller = select.poll()
        poller.register(self.fd, select.POLLIN | select.POLLHUP)
        events = poller.poll(0)
        mask = events[0][1] if events else 0
        require(mask & (select.POLLERR | select.POLLNVAL) == 0, "pidfd_poll_error")
        return mask

    def exited(self) -> bool:
        return bool(self.events() & select.POLLIN)

    def alive(self) -> None:
        current = proc_stat(self.pid)
        require(
            not self.exited()
            and current is not None
            and current["start_marker"] == self.marker
            and current["state"] not in {"Z", "X", "x"},
            "original_process_not_alive",
        )

    def retirement(self, timeout: float = 5.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while not self.exited() and time.monotonic() < deadline:
            select.select(
                [self.fd], [], [], min(0.05, max(0, deadline - time.monotonic()))
            )
        current = proc_stat(self.pid)
        same = current is not None and current["start_marker"] == self.marker
        mask = self.events()
        result = {
            "pidfd_exit": bool(mask & select.POLLIN),
            "pidfd_reaped": bool(mask & select.POLLHUP),
            "pidfd_poll_mask": mask,
            "proc_original_absent": not same,
            "terminal_state": current["state"] if same else "absent_or_pid_reused",
            "observed_parent_pid": current["parent_pid"] if same else None,
        }
        require(result["pidfd_exit"], "original_process_not_retired")
        return result

    def record(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "start_marker": self.marker,
            "role": self.role,
            "initial_parent_pid": self.initial["parent_pid"],
            "initial_process_group": self.initial["process_group"],
            "executable_sha256": RUNTIME_SHA,
        }


@dataclass
class Resident:
    home: Path
    generation: int
    path: Path
    endpoint: Path
    serving: Process
    supervisor: Process

    @classmethod
    def capture(
        cls, home: Path, executable: Path, processes: list[Process]
    ) -> Resident:
        path, state = read_state(home)
        serving = Process.capture(
            state["process_id"],
            state["process_start_marker"],
            "serve-managed",
            executable,
        )
        processes.append(serving)
        supervisor = Process.capture(
            state["owner_process_id"],
            state["owner_process_start_marker"],
            "supervise-managed",
            executable,
        )
        processes.append(supervisor)
        require(
            serving.pid != supervisor.pid
            and serving.initial["parent_pid"] == supervisor.pid,
            "resident_supervisor_relationship",
        )
        return cls(
            home,
            state["generation"],
            path,
            Path(state["endpoint"]),
            serving,
            supervisor,
        )

    def identity(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "serving": self.serving.record(),
            "supervisor": self.supervisor.record(),
        }

    def alive(self) -> None:
        path, state = read_state(self.home)
        require(
            path == self.path
            and state["generation"] == self.generation
            and state["process_id"] == self.serving.pid
            and state["process_start_marker"] == self.serving.marker
            and state["owner_process_id"] == self.supervisor.pid
            and state["owner_process_start_marker"] == self.supervisor.marker,
            "resident_generation_changed",
        )
        self.serving.alive()
        self.supervisor.alive()

    def retired(self) -> dict[str, Any]:
        require(generation_files(self.home) == [], "native_generation_remains")
        require(not os.path.lexists(self.endpoint), "native_endpoint_remains")
        return {
            "generation_absent": True,
            "endpoint_absent": True,
            "serving": self.serving.retirement(),
            "supervisor": self.supervisor.retirement(),
        }


def registry(client: Any, executable: Path, homes: dict[str, Path]) -> dict[str, Any]:
    known = {
        (executable, (home / "native-runtime").resolve()): label
        for label, home in homes.items()
    }
    with client._RESIDENTS_LOCK:
        keys = tuple(client._RESIDENTS)
    require(all(key in known for key in keys), "unexpected_resident_registration")
    pool_keys = {(str(exe), str(path)): label for (exe, path), label in known.items()}
    with client._CLIENTS_LOCK:
        pools = tuple(client._CLIENT_POOLS)
    require(all(key in pool_keys for key in pools), "unexpected_client_pool")
    return {
        "registered_homes": sorted(known[key] for key in keys),
        "pooled_homes": sorted(pool_keys[key] for key in pools),
    }


def client_process(
    client: Any, executable: Path, home: Path, processes: list[Process]
) -> tuple[Any, Process]:
    with client._CLIENTS_LOCK:
        pool = client._CLIENT_POOLS[
            (str(executable), str((home / "native-runtime").resolve()))
        ]
    with pool._condition:
        require(
            len(pool._clients) == 1 and len(pool._idle) == 1, "one_idle_client_required"
        )
        transport = next(iter(pool._clients))
        child = transport._process
    require(child is not None and child.returncode is None, "client_process_live")
    captured = Process.capture(child.pid, None, "resident-client-stream", executable)
    processes.append(captured)
    return child, captured


def health(
    client: Any, executable: Path, environment: dict[str, str], home: Path
) -> None:
    response = client.native_resident_client_request(
        executable=executable,
        guard_home=home,
        environment=environment,
        payload=HEALTH,
        timeout_seconds=8.0,
    )
    try:
        ready(response)
    except (Failure, ValueError, UnicodeError) as error:
        raise HealthFailure(safe_error(error), response_diagnostic(response)) from None
    require(
        client.native_resident_client_failure_code() is None, "health_client_failure"
    )


def response_diagnostic(response: bytes | None) -> dict[str, Any]:
    if not isinstance(response, bytes):
        return {"response_present": False}
    result: dict[str, Any] = {
        "response_present": True,
        "response_bytes": len(response),
        "response_sha256": digest(response),
    }
    if not 0 < len(response) <= 1024:
        return result
    try:
        value = decode(response)
    except (Failure, ValueError, UnicodeError):
        return result
    if type(value) is dict and set(value) == {"error", "retryable"}:
        code = value["error"]
        if type(code) is str and code in SAFE_HEALTH_ERROR_CODES:
            result["native_error_code"] = code
        else:
            result["native_error_code"] = "unregistered_native_error"
        if type(value["retryable"]) is bool:
            result["retryable"] = value["retryable"]
    return result


def provision_fresh_home(home: Path) -> dict[str, Any]:
    require(
        not os.path.lexists(home / "native-runtime"),
        "bootstrap_runtime_directory_exists",
    )
    api = importlib.import_module("codex_plugin_scanner.guard.native_policy_snapshot")
    master = os.urandom(32)
    try:
        key_path = api.provision_native_policy_verifier_key(home, master)
    finally:
        master = None
    require(
        key_path == home / "native-runtime" / "policy-verifier.key",
        "provisioned_key_path",
    )
    metadata = key_path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_mode & 0o077 == 0
        and metadata.st_size == 32,
        "provisioned_key_private_shape",
    )
    require(not generation_files(home), "resident_started_during_key_provision")
    return {
        "production_api": "native_policy_snapshot.provision_native_policy_verifier_key",
        "state_directory_absent_before_bootstrap": True,
        "state_directory_present_before_request": True,
        "private_verifier_key_provisioned": True,
        "generation_absent_before_request": True,
    }


class Channel:
    def __init__(self, descriptor: int):
        self.descriptor, self.buffer = descriptor, bytearray()

    def read(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            require(
                remaining > 0
                and bool(select.select([self.descriptor], [], [], remaining)[0]),
                "helper_channel_timeout",
            )
            content = os.read(self.descriptor, 4096)
            require(bool(content), "helper_channel_closed")
            self.buffer.extend(content)
            require(len(self.buffer) <= 16384, "helper_channel_size")
        line, _, remainder = self.buffer.partition(b"\n")
        self.buffer = bytearray(remainder)
        value = decode(bytes(line))
        require(type(value) is dict, "helper_channel_shape")
        return value


def send(descriptor: int, value: dict[str, Any]) -> None:
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(len(content) <= 4096, "helper_send_size")
    require(os.write(descriptor, content) == len(content), "helper_send_short")


def pure_controls() -> list[str]:
    ready(b'{"status":"ready","protocol_version":2}')
    rejected = []
    for name, value in (
        ("safe_native_error", b'{"error":{"code":"native_unavailable"}}'),
        (
            "actual_native_error_shape",
            b'{"error":"native_resident_start_timeout","retryable":false}',
        ),
        (
            "native_protocol_instead_of_resident",
            b'{"status":"ready","protocol_version":1}',
        ),
        (
            "duplicate_response_key",
            b'{"status":"ready","status":"ready","protocol_version":2}',
        ),
    ):
        try:
            ready(value)
        except Failure:
            rejected.append(name)
        else:
            raise Failure("validator_negative_control_accepted")
    known = response_diagnostic(
        b'{"error":"native_resident_start_timeout","retryable":false}'
    )
    require(
        known.get("native_error_code") == "native_resident_start_timeout",
        "diagnostic_known_error",
    )
    unknown = response_diagnostic(
        b'{"error":"private-unregistered-detail","retryable":false}'
    )
    require(
        unknown.get("native_error_code") == "unregistered_native_error"
        and "private-unregistered-detail" not in json.dumps(unknown),
        "diagnostic_unknown_error_redaction",
    )
    rejected.append("unregistered_error_detail_redacted")
    return rejected


def identity_controls(resident: Resident) -> list[str]:
    rejected = []
    for name, operation, expected_reason in (
        (
            "wrong_process_start_marker",
            replace(resident.serving, marker="linux:0").alive,
            "original_process_not_alive",
        ),
        (
            "wrong_resident_generation",
            replace(resident, generation=resident.generation + 1).alive,
            "resident_generation_changed",
        ),
    ):
        try:
            operation()
        except Failure as error:
            require(
                str(error) == expected_reason,
                "identity_negative_control_unexpected_error",
            )
            rejected.append(name)
        else:
            raise Failure("identity_negative_control_accepted")
    resident.alive()
    return rejected


def contain_owned_helper(helper: Any, marker: str | None) -> dict[str, Any]:
    """Contain only this Popen-owned Python helper; never signal a native PID."""
    if helper.poll() is not None:
        return {"already_exited": True, "returncode": helper.returncode}
    current = proc_stat(helper.pid)
    require(
        marker is not None
        and current is not None
        and current["start_marker"] == marker,
        "helper_cleanup_identity_unproven",
    )
    require(
        Path(f"/proc/{helper.pid}/exe").resolve(strict=True)
        == Path(sys.executable).resolve(),
        "helper_cleanup_executable_changed",
    )
    signals = ["terminate_owned_python_helper"]
    helper.terminate()
    try:
        helper.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        current = proc_stat(helper.pid)
        require(
            current is not None and current["start_marker"] == marker,
            "helper_kill_identity_changed",
        )
        signals.append("kill_owned_python_helper")
        helper.kill()
        helper.wait(timeout=2.0)
    return {"signals": signals, "returncode": helper.returncode, "reaped": True}


def holder(args: argparse.Namespace) -> int:
    processes: list[Process] = []
    children: dict[str, tuple[Any, Process]] = {}
    homes = {"A": Path(args.home_a).resolve(), "B": Path(args.home_b).resolve()}
    failures: list[str] = []
    cleanup: dict[str, Any] = {}
    client = None
    try:
        _, client, executable, environment, _ = installed(args.wheel)
        require(
            registry(client, executable, homes)
            == {"registered_homes": [], "pooled_homes": []},
            "helper_initial_registry",
        )
        residents = {}
        for label, home in homes.items():
            health(client, executable, environment, home)
            residents[label] = Resident.capture(home, executable, processes)
            children[label] = client_process(client, executable, home, processes)
        send(
            1,
            {
                "event": "joined",
                "residents": {k: v.identity() for k, v in residents.items()},
                "client_streams": {k: p.record() for k, (_, p) in children.items()},
                "registry": registry(client, executable, homes),
            },
        )
        channel = Channel(0)
        while True:
            command = channel.read(45.0)
            if command == {"operation": "finish"}:
                break
            labels = command.get("homes")
            require(
                command.get("operation") == "health" and labels in (["A", "B"], ["B"]),
                "helper_command",
            )
            for label in labels:
                residents[label].alive()
                health(client, executable, environment, homes[label])
                residents[label].alive()
            send(
                1,
                {
                    "event": "health_ready",
                    "homes": labels,
                    "residents": {
                        label: residents[label].identity() for label in labels
                    },
                },
            )
    except BaseException as error:
        failures.append(safe_error(error))
        if isinstance(error, HealthFailure):
            cleanup["failed_native_response"] = error.diagnostic
    finally:
        if client is not None:
            for label, home in homes.items():
                try:
                    closed = client.close_native_residents(home)
                    require(closed is True, "helper_scoped_cleanup_false")
                    require(
                        not generation_files(home), "helper_cleanup_generation_remains"
                    )
                    if label in children:
                        child, captured = children[label]
                        require(
                            child.returncode is not None,
                            "helper_client_not_reaped_by_close",
                        )
                        cleanup[label] = {
                            "registered_close": True,
                            "client": captured.retirement(),
                            "client_returncode": child.returncode,
                        }
                    else:
                        cleanup[label] = {"registered_close": True}
                except BaseException as error:
                    failures.append(safe_error(error))
                    cleanup[label] = {"failure": safe_error(error)}
        for process in processes:
            try:
                os.close(process.fd)
            except BaseException as error:
                failures.append(safe_error(error))
        try:
            send(1, {"event": "finished", "failures": failures, "cleanup": cleanup})
        except BaseException as error:
            failures.append(safe_error(error))
    return int(bool(failures))


def run(args: argparse.Namespace) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema": "hol-guard-installed-registration-witness.v2",
        "scope": "finite Linux installed bundled-auto authenticated health and owned resident lifecycle",
        "excluded_claims": [
            "hook_policy_semantics",
            "concurrent_same_home_registration",
            "full_release_qualification",
            "successful_startup_with_absent_native_runtime_directory",
        ],
        "prior_unprovisioned_failure_receipt_sha256": "9b03fb5765618023d04f01fbe38c5207ab5a45e4aade62fc5862c3b770294b77",
        "harness_sha256": digest(bounded(Path(__file__), 1024 * 1024)),
        "phases": [],
        "failures": [],
        "cleanup": {},
    }
    processes: list[Process] = []
    residents: dict[str, Resident] = {}
    children: dict[str, tuple[Any, Process]] = {}
    homes: dict[str, Path] = {}
    attempted_homes: set[str] = set()
    compact_directories: dict[str, Path] = {}
    helper = None
    helper_channel = None
    helper_finished = False
    helper_marker = None
    client = None
    temporary = None
    started = time.monotonic()
    try:
        receipt["negative_response_controls"] = pure_controls()
        _, client, executable, environment, receipt["provenance"] = installed(
            args.wheel
        )
        temporary = Path(
            tempfile.mkdtemp(prefix="private-run-", dir=args.private_parent)
        ).resolve()
        os.chmod(temporary, 0o700)
        for label in ("A", "B"):
            homes[label] = temporary / label
            homes[label].mkdir(mode=0o700)
            compact = compact_directory(homes[label])
            require(not os.path.lexists(compact), "preexisting_compact_directory")
            compact_directories[label] = compact
        require(
            registry(client, executable, homes)
            == {"registered_homes": [], "pooled_homes": []},
            "main_initial_registry",
        )
        for label, home in homes.items():
            bootstrap = provision_fresh_home(home)
            require(
                label not in registry(client, executable, homes)["registered_homes"]
                and label not in registry(client, executable, homes)["pooled_homes"],
                "registration_before_first_native_request",
            )
            attempted_homes.add(label)
            health(client, executable, environment, home)
            residents[label] = Resident.capture(home, executable, processes)
            children[label] = client_process(client, executable, home, processes)
            require(
                label in registry(client, executable, homes)["registered_homes"],
                "first_use_unregistered",
            )
            receipt["phases"].append(
                {
                    "phase": "first_use_registered",
                    "home": label,
                    "bootstrap": bootstrap,
                    "registration_absent_before_request": True,
                    "validated_health": True,
                    "resident": residents[label].identity(),
                    "client_stream": children[label][1].record(),
                    "registry": registry(client, executable, homes),
                }
            )
        require(
            residents["A"].serving.pid != residents["B"].serving.pid
            and residents["A"].supervisor.pid != residents["B"].supervisor.pid,
            "distinct_home_processes",
        )
        receipt["negative_identity_controls"] = identity_controls(residents["A"])
        # Wrong selector returns true without stopping a registered home. This
        # establishes why all measured closes need independent identity proof.
        require(
            client.close_native_residents(temporary) is True,
            "parent_home_negative_close",
        )
        require(
            registry(client, executable, homes)
            == {"registered_homes": ["A", "B"], "pooled_homes": ["A", "B"]},
            "parent_home_changed_registry",
        )
        for resident in residents.values():
            resident.alive()
        receipt["phases"].append(
            {"phase": "parent_home_selector_negative_control", "unchanged": True}
        )
        helper = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--holder",
                "--wheel",
                str(args.wheel),
                "--home-a",
                str(homes["A"]),
                "--home-b",
                str(homes["B"]),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(os.environ),
            cwd=temporary,
            start_new_session=True,
        )
        require(helper.stdin is not None and helper.stdout is not None, "helper_pipes")
        helper_identity = proc_stat(helper.pid)
        require(helper_identity is not None, "helper_process_identity")
        helper_marker = helper_identity["start_marker"]
        receipt["helper_process"] = {
            "pid": helper.pid,
            "start_marker": helper_marker,
            "executable_sha256": digest(
                bounded(Path(f"/proc/{helper.pid}/exe"), 64 * 1024 * 1024)
            ),
        }
        helper_channel = Channel(helper.stdout.fileno())
        joined = helper_channel.read(30.0)
        if joined.get("event") == "finished":
            receipt["helper_unexpected_terminal_event"] = joined
        require(joined.get("event") == "joined", "helper_join_failed")
        require(
            joined.get("registry")
            == {"registered_homes": ["A", "B"], "pooled_homes": ["A", "B"]},
            "helper_join_registration",
        )
        for label, resident in residents.items():
            # Initial parent PIDs remain stable until the creating streams close.
            require(
                joined["residents"][label] == resident.identity(),
                "helper_joined_replacement",
            )
            record = joined["client_streams"][label]
            captured = Process.capture(
                record["pid"],
                record["start_marker"],
                "resident-client-stream",
                executable,
            )
            processes.append(captured)
            require(
                captured.initial["parent_pid"] == helper.pid, "helper_client_parent"
            )
        receipt["phases"].append(
            {
                "phase": "independent_idle_clients_joined",
                "helper_pid": helper.pid,
                "clients": joined["client_streams"],
            }
        )
        local_close = {}
        for label, home in homes.items():
            client.close_native_resident_clients(home)
            child, captured = children[label]
            require(child.returncode is not None, "main_client_not_reaped_by_close")
            local_close[label] = {
                "client": captured.retirement(),
                "client_returncode": child.returncode,
            }
        require(
            registry(client, executable, homes)
            == {"registered_homes": ["A", "B"], "pooled_homes": []},
            "local_close_lost_registration",
        )
        observation = time.monotonic()
        while time.monotonic() - observation < 1.5:
            for resident in residents.values():
                resident.alive()
            time.sleep(0.05)
        require(helper.poll() is None, "helper_not_live_after_local_close")
        send(helper.stdin.fileno(), {"operation": "health", "homes": ["A", "B"]})
        response = helper_channel.read(20.0)
        require(
            response.get("event") == "health_ready"
            and response.get("homes") == ["A", "B"],
            "shared_resident_health_after_local_close",
        )
        for label, resident in residents.items():
            resident.alive()
            require(
                response["residents"][label] == resident.identity(),
                "shared_health_replacement",
            )
        receipt["phases"].append(
            {
                "phase": "local_clients_closed_shared_residents_survived",
                "observation_seconds": round(time.monotonic() - observation, 6),
                "lease_expiry_seconds": 1.0,
                "local_clients": local_close,
                "same_generation_health": True,
                "registry": registry(client, executable, homes),
            }
        )
        # The helper is idle from this point for A, including while close runs.
        for label in ("A", "B"):
            residents[label].alive()
            require(
                label in registry(client, executable, homes)["registered_homes"],
                "measured_close_unregistered",
            )
            began = time.monotonic()
            closed = client.close_native_residents(homes[label])
            require(closed is True, "measured_registered_close_false")
            retirement = residents[label].retired()
            expected_remaining = ["B"] if label == "A" else []
            require(
                registry(client, executable, homes)
                == {"registered_homes": expected_remaining, "pooled_homes": []},
                "measured_close_registry",
            )
            receipt["phases"].append(
                {
                    "phase": "registered_scoped_shutdown",
                    "home": label,
                    "return_value": closed,
                    "duration_seconds": round(time.monotonic() - began, 6),
                    "retirement": retirement,
                    "registry": registry(client, executable, homes),
                }
            )
            if label == "A":
                residents["B"].alive()
                send(helper.stdin.fileno(), {"operation": "health", "homes": ["B"]})
                response = helper_channel.read(15.0)
                require(
                    response.get("event") == "health_ready"
                    and response.get("homes") == ["B"],
                    "unrelated_home_health_failed",
                )
                require(
                    response["residents"]["B"] == residents["B"].identity(),
                    "unrelated_home_replaced",
                )
                residents["B"].alive()
                receipt["phases"].append(
                    {
                        "phase": "unrelated_home_survived_selected_shutdown",
                        "same_generation_health": True,
                    }
                )
        send(helper.stdin.fileno(), {"operation": "finish"})
        final = helper_channel.read(20.0)
        require(final.get("event") == "finished", "helper_final_event")
        helper_finished = True
        receipt["cleanup"]["helper"] = final
        require(final.get("failures") == [], "helper_cleanup_failure")
        require(helper.wait(timeout=5.0) == 0, "helper_exit_failure")
        receipt["cleanup"]["helper_reaped"] = True
    except BaseException as error:
        receipt["failures"].append(safe_error(error))
        if isinstance(error, HealthFailure):
            receipt["failed_native_response"] = error.diagnostic
    finally:
        # Shutdown is quiescent. No other home, process group, or resident is
        # targeted. Recovery never turns a failed measured phase into a pass.
        if helper is not None and helper.stdin is not None:
            try:
                if not helper.stdin.closed:
                    if not helper_finished and helper.poll() is None:
                        send(helper.stdin.fileno(), {"operation": "finish"})
                    helper.stdin.close()
                if not helper_finished and helper_channel is not None:
                    final = helper_channel.read(20.0)
                    require(
                        final.get("event") == "finished", "helper_cleanup_final_event"
                    )
                    receipt["cleanup"]["helper"] = final
                    require(final.get("failures") == [], "helper_cleanup_failure")
                require(helper.wait(timeout=5.0) == 0, "helper_cleanup_exit_failure")
                receipt["cleanup"]["helper_reaped"] = True
            except BaseException as error:
                receipt["failures"].append(safe_error(error))
                receipt["cleanup"]["helper_reaped"] = helper.poll() is not None
                if helper.poll() is None:
                    try:
                        receipt["cleanup"]["helper_containment_fallback"] = (
                            contain_owned_helper(helper, helper_marker)
                        )
                        receipt["cleanup"]["helper_reaped"] = True
                    except BaseException as containment_error:
                        receipt["failures"].append(safe_error(containment_error))
            if helper.stdout is not None:
                try:
                    helper.stdout.close()
                except BaseException as error:
                    receipt["failures"].append(safe_error(error))
        clean = True
        if client is not None:
            for label, home in homes.items():
                try:
                    require(
                        client.close_native_residents(home) is True,
                        "final_scoped_cleanup_false",
                    )
                    require(not generation_files(home), "final_generation_remains")
                    require(
                        label not in attempted_homes or label in residents,
                        "uncaptured_first_use_retirement_unproven",
                    )
                    retired = (
                        residents[label].retired()
                        if label in residents
                        else {"native_request_not_attempted": True}
                    )
                    if label in children:
                        require(
                            children[label][0].returncode is not None,
                            "final_local_client_unreaped",
                        )
                    receipt["cleanup"][label] = {
                        "registered_close": True,
                        "retirement": retired,
                    }
                except BaseException as error:
                    clean = False
                    receipt["failures"].append(safe_error(error))
                    receipt["cleanup"][label] = {"failure": safe_error(error)}
        if helper is not None and helper.poll() is None:
            clean = False
        remaining_processes = []
        for process in processes:
            try:
                retirement = process.retirement(timeout=1.0)
                remaining_processes.append(
                    {"identity": process.record(), "retirement": retirement}
                )
            except BaseException as error:
                clean = False
                receipt["failures"].append(safe_error(error))
                remaining_processes.append(
                    {"identity": process.record(), "failure": safe_error(error)}
                )
        receipt["cleanup"]["all_captured_native_processes"] = remaining_processes
        for process in processes:
            try:
                os.close(process.fd)
            except BaseException as error:
                clean = False
                receipt["failures"].append(safe_error(error))
        if clean:
            for label, directory in compact_directories.items():
                try:
                    if os.path.lexists(directory):
                        private_directory(directory)
                        # rmdir is deliberately nonrecursive: any unexpected
                        # entry prevents deletion and remains failure-visible.
                        directory.rmdir()
                    receipt["cleanup"].setdefault(label, {})[
                        "compact_socket_directory_absent"
                    ] = True
                except BaseException as error:
                    clean = False
                    receipt["failures"].append(safe_error(error))
        if temporary is not None and clean:
            try:
                shutil.rmtree(temporary)
            except BaseException as error:
                clean = False
                receipt["failures"].append(safe_error(error))
        receipt["cleanup"]["private_homes_removed"] = (
            temporary is None or not temporary.exists()
        )
        receipt["duration_seconds"] = round(time.monotonic() - started, 6)
        receipt["result"] = "passed" if not receipt["failures"] and clean else "failed"
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--private-parent", type=Path)
    parser.add_argument("--holder", action="store_true")
    parser.add_argument("--home-a")
    parser.add_argument("--home-b")
    args = parser.parse_args()
    args.wheel = args.wheel.resolve()
    if args.holder:
        require(
            args.home_a is not None and args.home_b is not None, "helper_homes_missing"
        )
        return holder(args)
    require(
        args.output is not None and args.private_parent is not None,
        "main_output_missing",
    )
    private_directory(args.private_parent.resolve())
    require(not args.output.exists(), "receipt_already_exists")
    receipt = run(args)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        json.dumps(
            {
                "result": receipt["result"],
                "failures": receipt["failures"],
                "phases": len(receipt["phases"]),
                "receipt_sha256": digest(args.output.read_bytes()),
            }
        )
    )
    return int(receipt["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
