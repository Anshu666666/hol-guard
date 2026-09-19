"""Source-only bootstrap boundary; no configured actual execution authority.

Finite injected doubles can exercise forwarding and refusal. Production main
always refuses until an independently reviewed live controller verifier exists.
JSON shape, echoed hashes and local observations cannot authorize a workload.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import runpy
import select
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType
from typing import Any, Protocol, cast

PROTOCOL = "hol_sqlite_child_bootstrap_v1"
MAX_FRAME = 4096
MAX_SECONDS = 120.0
SOURCE_COMMIT = "1cd7842c1da4f327b568065dd159c67e7bd0c92b"
SOURCE_PINS = {
    "scripts/native_slo_daemon_fixture.py": "03a53becf8e93ee2a317a502bca3dab7a1b6f9c393330aaff78e61a33061c581",
    "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py": (
        "aaf93c593704f40f159f0ccb05fb52d064b501e1643f024a833ef8ea4c63505f"
    ),
}
SQLITE_FIELDS = frozenset(("sqlite_version", "sqlite_source_id", "sqlite_image_sha256", "python_extension_sha256"))
FRAME_KEYS = frozenset(
    (
        "schema",
        "kind",
        "session_id",
        "profile_sha256",
        "child_pid",
        "nonce",
        "controller_receipt_sha256",
        "child_evidence_sha256",
        "verification_receipt_sha256",
    )
)
# Quarantines intentionally retain owned references for process lifetime. They
# are never a reusable pool and a nonempty quarantine refuses a subsequent arm.
_OBSERVER_QUARANTINE: list[object] = []
_PROCESS_QUARANTINE: list[object] = []


class BootstrapUnavailableError(RuntimeError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise BootstrapUnavailableError(code)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def hex_value(value: object, length: int) -> bool:
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def deadline_remaining(deadline: float, clock: Any = time.monotonic) -> float:
    need(type(deadline) in (float, int) and math.isfinite(deadline), "deadline_shape")
    remaining = deadline - clock()
    need(0 < remaining <= MAX_SECONDS, "deadline_expired_or_unbounded")
    return remaining


@dataclass(frozen=True)
class Identity:
    session_id: str
    profile_sha256: str
    nonce: str
    controller_receipt_sha256: str

    def validate(self) -> None:
        need(hex_value(self.session_id, 32) and hex_value(self.nonce, 32), "session_shape")
        need(hex_value(self.profile_sha256, 64) and hex_value(self.controller_receipt_sha256, 64), "identity_digest")

    def frame(
        self,
        kind: str,
        child_pid: int,
        *,
        child_evidence_sha256: str | None = None,
        verification_receipt_sha256: str | None = None,
    ) -> dict[str, Any]:
        self.validate()
        value = {
            "schema": PROTOCOL,
            "kind": kind,
            "session_id": self.session_id,
            "profile_sha256": self.profile_sha256,
            "child_pid": child_pid,
            "nonce": self.nonce,
            "controller_receipt_sha256": self.controller_receipt_sha256,
            "child_evidence_sha256": child_evidence_sha256,
            "verification_receipt_sha256": verification_receipt_sha256,
        }
        validate_frame(value, self, kind, child_pid)
        return value


def validate_frame(value: Any, identity: Identity, kind: str, child_pid: int) -> None:
    need(type(value) is dict and set(value) == FRAME_KEYS, "frame_fields")
    value = cast(dict[str, Any], value)
    need(value["schema"] == PROTOCOL and value["kind"] == kind and kind in ("ready", "release"), "frame_protocol")
    need(
        type(value["child_pid"]) is int and 0 < value["child_pid"] <= 2**31 - 1 and value["child_pid"] == child_pid,
        "child_identity",
    )
    need(
        all(
            value[key] == getattr(identity, key)
            for key in ("session_id", "profile_sha256", "nonce", "controller_receipt_sha256")
        ),
        "stale_frame",
    )
    if kind == "ready":
        need(
            value["child_evidence_sha256"] is None and value["verification_receipt_sha256"] is None,
            "ready_cannot_claim_future_capture",
        )
    else:
        need(
            hex_value(value["child_evidence_sha256"], 64) and hex_value(value["verification_receipt_sha256"], 64),
            "release_evidence_missing",
        )


def decode_frame(raw: bytes, identity: Identity, kind: str, child_pid: int) -> dict[str, Any]:
    need(
        type(raw) is bytes and 0 < len(raw) <= MAX_FRAME and raw.endswith(b"\n") and raw.count(b"\n") == 1,
        "frame_bound",
    )

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            need(key not in result, "duplicate_frame_field")
            result[key] = value
        return result

    try:
        value = json.loads(raw[:-1].decode("ascii"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise BootstrapUnavailableError("frame_encoding") from None
    validate_frame(value, identity, kind, child_pid)
    return value


class FifoOperations:
    """Concrete bounded FIFO I/O; finite tests replace this entire dependency."""

    clock = staticmethod(time.monotonic)
    read = staticmethod(os.read)
    write = staticmethod(os.write)
    close = staticmethod(os.close)

    @staticmethod
    def admit(read_fd: int, write_fd: int) -> None:
        import fcntl

        need(
            type(read_fd) is int and type(write_fd) is int and min(read_fd, write_fd) >= 3 and read_fd != write_fd,
            "private_descriptors",
        )
        values = [os.fstat(fd) for fd in (read_fd, write_fd)]
        need(all(stat.S_ISFIFO(item.st_mode) for item in values), "control_not_fifo")
        keys = {(item.st_dev, item.st_ino) for item in values}
        need(len(keys) == 2, "control_fifo_alias")
        for standard in (0, 1, 2):
            try:
                item = os.fstat(standard)
            except OSError:
                continue
            need((item.st_dev, item.st_ino) not in keys, "control_aliases_standard_io")
        need(fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, "control_read_mode")
        need(fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY, "control_write_mode")
        for fd in (read_fd, write_fd):
            os.set_inheritable(fd, False)
            os.set_blocking(fd, False)
            need(not os.get_inheritable(fd), "control_still_inheritable")

    @staticmethod
    def wait(fd: int, write: bool, timeout: float) -> None:
        readable, writable, _ = select.select([] if write else [fd], [fd] if write else [], [], timeout)
        need(bool(writable if write else readable), "control_deadline")


class FifoChannel:
    def __init__(self, read_fd: int, write_fd: int, deadline: float, operations: Any):
        deadline_remaining(deadline, operations.clock)
        operations.admit(read_fd, write_fd)
        self.read_fd, self.write_fd, self.deadline, self.operations = read_fd, write_fd, deadline, operations
        self.received: set[str] = set()
        self.sent: set[str] = set()
        self.closed = False

    def receive(self, identity: Identity, kind: str, child_pid: int) -> dict[str, Any]:
        need(kind not in self.received and not self.closed, "duplicate_or_closed_receive")
        self.received.add(kind)
        raw = bytearray()
        while not raw.endswith(b"\n"):
            remaining = deadline_remaining(self.deadline, self.operations.clock)
            self.operations.wait(self.read_fd, False, remaining)
            deadline_remaining(self.deadline, self.operations.clock)
            try:
                chunk = self.operations.read(self.read_fd, MAX_FRAME + 1 - len(raw))
            except (BlockingIOError, InterruptedError):
                continue
            need(type(chunk) is bytes and bool(chunk), "control_eof")
            raw.extend(chunk)
            need(len(raw) <= MAX_FRAME, "frame_bound")
        deadline_remaining(self.deadline, self.operations.clock)
        return decode_frame(bytes(raw), identity, kind, child_pid)

    def send(self, value: dict[str, Any]) -> None:
        kind = value.get("kind")
        need(kind in ("ready", "release") and kind not in self.sent and not self.closed, "duplicate_or_closed_send")
        raw = canonical(value) + b"\n"
        need(len(raw) <= MAX_FRAME, "frame_bound")
        self.sent.add(cast(str, kind))
        offset = 0
        while offset < len(raw):
            remaining = deadline_remaining(self.deadline, self.operations.clock)
            self.operations.wait(self.write_fd, True, remaining)
            deadline_remaining(self.deadline, self.operations.clock)
            try:
                count = self.operations.write(self.write_fd, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            need(type(count) is int and 0 < count <= len(raw) - offset, "control_write")
            offset += count
        deadline_remaining(self.deadline, self.operations.clock)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            error = None
            for fd in (self.read_fd, self.write_fd):
                try:
                    self.operations.close(fd)
                except BaseException as caught:
                    error = caught
            if error is not None:
                raise BootstrapUnavailableError("control_close_failed") from None


@dataclass(frozen=True)
class OwnedTreeCleanup:
    parent_reaped: bool
    descendants_exhausted: bool
    controller_receipt_sha256: str


class ControllerVerifier(Protocol):
    """Trusted code dependency, never a receipt parser or arbitrary ready flag.

    The future real implementation must hold live program/map/link FDs and an
    externally pinned review. before_spawn proves mandatory links and gate=1 for
    this session. verify_child_release establishes a watermark after ready,
    drains/reconciles records and verifies actual parent birth/dup_fd/exec epochs
    and current ownership/loss/gate/link state. cleanup_owned_tree must retire
    and reap only the birth-bound owned tree, retaining live capabilities until
    exhaustion is proved. None of that actual authority exists locally yet.
    """

    scope: str

    def before_spawn(self, identity: Identity, profile: dict[str, Any], deadline: float) -> object: ...
    def verify_child_release(self, ticket: object, ready: dict[str, Any], deadline: float) -> dict[str, Any]: ...
    def admit_child_profile(self, profile: dict[str, Any], observed: dict[str, Any], deadline: float) -> None: ...
    def verify_release(self, ready: dict[str, Any], release: dict[str, Any], deadline: float) -> None: ...
    def cleanup_owned_tree(self, ticket: object, process: object, deadline: float) -> OwnedTreeCleanup: ...


class UnconfiguredVerifier:
    scope = "unconfigured"

    def before_spawn(self, *_args: object) -> object:
        raise BootstrapUnavailableError("authoritative_controller_unavailable")

    def verify_child_release(self, *_args: object) -> dict[str, Any]:
        raise BootstrapUnavailableError("authoritative_controller_unavailable")

    def admit_child_profile(self, *_args: object) -> None:
        raise BootstrapUnavailableError("authoritative_controller_unavailable")

    def verify_release(self, *_args: object) -> None:
        raise BootstrapUnavailableError("authoritative_controller_unavailable")

    def cleanup_owned_tree(self, *_args: object) -> OwnedTreeCleanup:
        raise BootstrapUnavailableError("authoritative_controller_unavailable")


def admit_verifier(verifier: ControllerVerifier, finite_control: bool) -> None:
    # There is no reviewed live-controller implementation to admit yet. A scope
    # string, fake receipt or caller-supplied shape cannot substitute for one.
    need(finite_control is True and verifier.scope == "finite_injected_control", "authoritative_controller_unavailable")


def admit_profile(identity: Identity, profile: dict[str, Any]) -> None:
    identity.validate()
    need(type(profile) is dict and digest(canonical(profile)) == identity.profile_sha256, "profile_digest")
    need(
        set(profile)
        == {
            "kind",
            "review_sha256",
            "python_sha256",
            "kernel_profile_sha256",
            "source_sha256",
            "artifact_sha256",
            "installed_package_sha256",
            "native_runtime_sha256",
            "shim_sha256",
            "sqlite",
        },
        "profile_fields",
    )
    need(profile["kind"] == "independently_reviewed_hosted_target", "profile_not_independent")
    need(all(hex_value(profile[key], 64) for key in profile if key not in ("kind", "sqlite")), "profile_pins_missing")
    need(
        type(profile["sqlite"]) is dict
        and set(profile["sqlite"]) == SQLITE_FIELDS
        and all(type(v) is str and bool(v) for v in profile["sqlite"].values()),
        "sqlite_profile",
    )
    need(
        all(hex_value(profile["sqlite"][key], 64) for key in ("sqlite_image_sha256", "python_extension_sha256")),
        "sqlite_image_profile",
    )


def guard_not_imported() -> None:
    need(
        not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules),
        "guard_import_before_release",
    )


def checked_snapshot(value: Any) -> dict[str, Any]:
    need(type(value) is dict and set(value) == {"version", "incomplete", "active_files", "markers"}, "snapshot_shape")
    value = cast(dict[str, Any], value)
    need(type(value["version"]) is int and value["version"] == 1, "snapshot_version")
    for key in ("incomplete", "active_files"):
        need(type(value[key]) is int and 0 <= value[key] < 2**64, "snapshot_counter")
    markers = value["markers"]
    need(
        type(markers) is list
        and len(markers) == 21
        and all(
            type(row) is list and len(row) == 5 and all(type(n) is int and 0 <= n < 2**64 for n in row)
            for row in markers
        ),
        "snapshot_markers",
    )
    return value


class ObserverLease:
    def __init__(self):
        self.observer: Any = None
        self.quarantined = False
        self.released = False
        self.snapshot: dict[str, Any] | None = None

    def prepare(self, observer_type: Any, shim_path: Path, profile: dict[str, Any]) -> None:
        need(not _OBSERVER_QUARANTINE and self.observer is None, "observer_quarantine_or_reuse")
        # Retain the object before explicit init: __init__/install can raise
        # after acquiring a DSO handle or registering the C VFS.
        self.observer = observer_type.__new__(observer_type)
        try:
            observer_type.__init__(self.observer, shim_path, profile["shim_sha256"])
            self.observer.install(dict(profile["sqlite"]))
            self.observer.validate_loaded_binding()
        except BaseException:
            self.finish(cleanup_completed=True)
            raise

    def finish(self, *, cleanup_completed: bool) -> bool:
        if self.observer is None:
            return self.released
        if self.quarantined:
            return False
        try:
            need(cleanup_completed, "fixture_cleanup_unproved")
            self.snapshot = checked_snapshot(self.observer.snapshot())
            need(
                self.snapshot["active_files"] == 0 and self.snapshot["incomplete"] == 0,
                "observer_still_active_or_incomplete",
            )
            self.observer.validate_loaded_binding()
            self.observer.uninstall()
            self.observer.validate_loaded_binding()
        except BaseException:
            self.quarantined = True
            _OBSERVER_QUARANTINE.append(self.observer)
            return False
        self.observer = None
        self.released = True
        return True


@dataclass
class ChildState:
    workload_started: bool = False
    workload_completed: bool = False
    observer_released: bool = False
    observer_quarantined: bool = False
    control_closed: bool = False
    diagnostic_complete: bool = False


def run_child(
    *,
    identity: Identity,
    profile: dict[str, Any],
    observed_profile: dict[str, Any],
    verifier: ControllerVerifier,
    channel: FifoChannel,
    child_pid: int,
    original_argv: list[str],
    observer_type: Any,
    shim_path: Path,
    state: ChildState,
    run_path: Any = runpy.run_path,
    finite_control: bool = False,
) -> Any:
    lease = ObserverLease()
    previous_argv = sys.argv
    try:
        admit_verifier(verifier, finite_control)
        admit_profile(identity, profile)
        guard_not_imported()
        deadline_remaining(channel.deadline, channel.operations.clock)
        # This mandatory callback admits independently pinned actual identities;
        # the local shape/hash check above is never that proof.
        verifier.admit_child_profile(profile, observed_profile, channel.deadline)
        admit_profile(identity, profile)
        guard_not_imported()
        need(
            type(original_argv) is list and bool(original_argv) and all(type(v) is str for v in original_argv),
            "original_argv",
        )
        lease.prepare(observer_type, shim_path, profile)
        guard_not_imported()
        ready = identity.frame("ready", child_pid)
        channel.send(ready)
        release = channel.receive(identity, "release", child_pid)
        verifier.verify_release(ready, release, channel.deadline)
        deadline_remaining(channel.deadline, channel.operations.clock)
        guard_not_imported()
        sys.argv = list(original_argv)
        state.workload_started = True
        try:
            result = run_path(original_argv[0], run_name="__main__")
        except SystemExit as completed:
            # The pinned original __main__ raises SystemExit(_serve(...)). The
            # original cleanup has completed only for its normal exit statuses.
            state.workload_completed = completed.code is None or (type(completed.code) is int and completed.code == 0)
            raise
        state.workload_completed = True
        return result
    finally:
        sys.argv = previous_argv
        state.observer_released = lease.finish(cleanup_completed=not state.workload_started or state.workload_completed)
        state.observer_quarantined = lease.quarantined
        try:
            channel.close()
            state.control_closed = True
        except BaseException:
            state.control_closed = False
        state.diagnostic_complete = state.workload_completed and state.observer_released and state.control_closed
        # Diagnostic status is separate from the exact original return value or
        # exception. A future driver must require diagnostic_complete, and must
        # retain quarantine on failure. main currently refuses every workload.


def clone_function(function: FunctionType, replaced: str, value: object) -> FunctionType:
    need(type(function) is FunctionType and replaced in function.__globals__, "original_function_binding")
    globals_ = dict(function.__globals__)
    globals_[replaced] = value
    cloned = FunctionType(function.__code__, globals_, function.__name__, function.__defaults__, function.__closure__)
    cloned.__kwdefaults__ = function.__kwdefaults__
    cloned.__annotations__ = dict(function.__annotations__)
    return cloned


def bind_original(function: FunctionType, source: bytes, relative: str, qualname: str) -> None:
    need(digest(source) == SOURCE_PINS[relative], "original_source_pin")
    compiled = compile(source, function.__code__.co_filename, "exec", dont_inherit=True)

    def find(code: Any) -> Any:
        for item in code.co_consts:
            if type(item) is type(compiled):
                if getattr(item, "co_qualname", None) == qualname:
                    return item
                result = find(item)
                if result is not None:
                    return result
        return None

    need(find(compiled) == function.__code__, "original_code_changed")


class SpawnTransport(Protocol):
    child_fds: tuple[int, int]
    channel: FifoChannel

    def parent_after_spawn(self) -> None: ...
    def close(self) -> None: ...


class FixtureBootstrap:
    """One owned Popen attempt; only isolated copied function globals change."""

    def __init__(
        self,
        *,
        fixture_enter: FunctionType,
        spawner: FunctionType,
        fixture_source: bytes,
        spawner_source: bytes,
        bootstrap_path: Path,
        identity: Identity,
        profile: dict[str, Any],
        verifier: ControllerVerifier,
        transport: SpawnTransport,
        deadline: float,
        clock: Any = time.monotonic,
        finite_control: bool = False,
    ):
        admit_verifier(verifier, finite_control)
        admit_profile(identity, profile)
        need(not _PROCESS_QUARANTINE, "process_quarantine")
        bind_original(fixture_enter, fixture_source, "scripts/native_slo_daemon_fixture.py", "DaemonFixture.__enter__")
        bind_original(
            spawner,
            spawner_source,
            "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
            "_spawn_hook_process",
        )
        need(fixture_enter.__globals__["_spawn_hook_process"] is spawner, "fixture_spawner_alias")
        self.identity, self.profile, self.verifier = identity, profile, verifier
        need(transport.channel.deadline == deadline, "control_deadline_disagrees")
        self.transport, self.deadline, self.clock = transport, deadline, clock
        self.bootstrap_path = bootstrap_path
        self.process: Any = None
        self.ticket: object | None = None
        self.attempts = 0
        self.cleanup_failed = False
        self.parent_reaped = False
        self.descendants_exhausted = False
        self.cleanup_receipt_sha256: str | None = None
        self._cleanup_attempted = False
        self._spawner_original = spawner
        original_subprocess = spawner.__globals__["subprocess"]
        owner = self

        class Proxy:
            PIPE = original_subprocess.PIPE

            def __getattr__(self, name: str) -> Any:
                return self._popen if name == "Popen" else getattr(original_subprocess, name)

            def _popen(self, *args: Any, **kwargs: Any) -> Any:
                need(owner.attempts == 0 and kwargs.get("pass_fds") == (), "spawn_reuse_or_existing_pass_fds")
                need(
                    kwargs.get("start_new_session") is True
                    and all(kwargs.get(k) is self.PIPE for k in ("stdin", "stdout", "stderr")),
                    "original_spawn_io",
                )
                fds = owner.transport.child_fds
                need(
                    type(fds) is tuple
                    and len(fds) == 2
                    and all(type(fd) is int and fd >= 3 for fd in fds)
                    and fds[0] != fds[1],
                    "child_control_fds",
                )
                deadline_remaining(owner.deadline, owner.clock)
                owner.attempts += 1
                forwarded = dict(kwargs)
                forwarded["pass_fds"] = (*kwargs["pass_fds"], *fds)
                owner.process = original_subprocess.Popen(*args, **forwarded)
                return owner.process

        self._spawner = clone_function(spawner, "subprocess", Proxy())
        self._enter = clone_function(fixture_enter, "_spawn_hook_process", self._spawn)

    def _spawn(self, command: Any, **kwargs: Any) -> Any:
        need(
            kwargs.get("parent_liveness") is False
            and kwargs.get("allow_windows_breakaway") is False
            and kwargs.get("windows_kill_on_job_close") is True,
            "fixture_spawn_flags",
        )
        need(
            type(command) is tuple and len(command) >= 4 and command[1] == "-u" and command[3] == "--serve",
            "fixture_argv_shape",
        )
        deadline_remaining(self.deadline, self.clock)
        # The capability object is retained through this fixture. An actual
        # implementation must prove gate/link/session state here, before Popen.
        self.ticket = self.verifier.before_spawn(self.identity, self.profile, self.deadline)
        admit_profile(self.identity, self.profile)
        need(self.ticket is not None and type(self.ticket) is not bool, "controller_capability_missing")
        read_fd, write_fd = self.transport.child_fds
        bootstrap_command = (
            command[0],
            command[1],
            str(self.bootstrap_path),
            "--control-read",
            str(read_fd),
            "--control-write",
            str(write_fd),
            "--",
            *command[2:],
        )
        try:
            result = self._spawner(bootstrap_command, **kwargs)
            process = self.process
            if process is None or result[0] is not process:
                raise BootstrapUnavailableError("spawn_result_identity")
            self.transport.parent_after_spawn()
            ready = self.transport.channel.receive(self.identity, "ready", process.pid)
            release = self.verifier.verify_child_release(self.ticket, ready, self.deadline)
            validate_frame(release, self.identity, "release", process.pid)
            self.transport.channel.send(release)
            return result
        except BaseException:
            self._cleanup_owned()
            raise

    def enter(self, fixture: Any) -> Any:
        try:
            return self._enter(fixture)
        except BaseException:
            # Covers Popen success followed by spawner return/fixture attribute
            # assignment or reader setup failure before original try/cleanup.
            self._cleanup_owned()
            raise

    def _cleanup_owned(self) -> None:
        if self._cleanup_attempted:
            return
        self._cleanup_attempted = True
        if self.process is not None:
            try:
                need(self.ticket is not None, "cleanup_capability_missing")
                # Only the future authoritative controller can bind this exact
                # Popen object's birth/session to the owned descendant tree.
                # Direct parent retirement is never descendant exhaustion.
                proof = self.verifier.cleanup_owned_tree(self.ticket, self.process, self.deadline)
                need(type(proof) is OwnedTreeCleanup, "owned_tree_cleanup_proof")
                need(
                    type(proof.parent_reaped) is bool and type(proof.descendants_exhausted) is bool,
                    "owned_tree_cleanup_status",
                )
                self.parent_reaped = proof.parent_reaped and self.process.poll() is not None
                self.descendants_exhausted = proof.descendants_exhausted
                need(hex_value(proof.controller_receipt_sha256, 64), "owned_tree_cleanup_receipt")
                self.cleanup_receipt_sha256 = proof.controller_receipt_sha256
                need(self.parent_reaped and self.descendants_exhausted, "owned_tree_cleanup_incomplete")
            except BaseException:
                self.cleanup_failed = True
                # Hold the process AND controller/transport capability. Dropping
                # the owner here could detach the only remaining capture links.
                if not any(owner is self for owner in _PROCESS_QUARANTINE):
                    _PROCESS_QUARANTINE.append(self)
        try:
            self.transport.close()
        except BaseException:
            self.cleanup_failed = True


def main() -> int:
    # No actual hosted profile or live controller implementation is configured.
    # This entry must refuse even if command-line JSON/FDs look plausible.
    raise BootstrapUnavailableError("authoritative_controller_unavailable")


if __name__ == "__main__":
    raise SystemExit(main())
