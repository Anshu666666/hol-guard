"""Failure-only, bounded observations for the native test publication barrier."""

from __future__ import annotations

import inspect
import io
import json
import threading
from collections.abc import Callable
from pathlib import Path
from types import CodeType, SimpleNamespace

import pytest

import codex_plugin_scanner.guard.native_policy_authority_managed as authority_managed
import codex_plugin_scanner.guard.native_policy_authority_read as authority_read
import codex_plugin_scanner.guard.native_policy_snapshot_publisher_context as context
import codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs as inputs
import codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport as transport
import codex_plugin_scanner.guard.native_policy_snapshot_source_requirement as source_requirement
import codex_plugin_scanner.guard.native_policy_test_support as support
import codex_plugin_scanner.guard.store_base as store_base
import codex_plugin_scanner.guard.store_connection_schema as connection_schema
import codex_plugin_scanner.guard.store_policy_integrity_backend as integrity_backend
import codex_plugin_scanner.guard.store_review_event_outbox_schema as outbox
import codex_plugin_scanner.guard.store_secret_policy_integrity as secret_integrity
import codex_plugin_scanner.guard.store_storage_lock as storage_lock


class PublisherDouble:
    def __init__(self, *, ready: bool, snapshot: object = None) -> None:
        self.ready = ready
        self.snapshot = snapshot
        self.last_error = None
        self.calls: list[object] = []
        self._started = False
        self._closed = False

    def start(self) -> None:
        self.calls.append("start")
        self._started = True

    def wait_until_ready(self, deadline: float) -> bool:
        self.calls.append(("wait", deadline))
        return self.ready

    def current_snapshot(self) -> object:
        self.calls.append("snapshot")
        return self.snapshot

    def close(self) -> None:
        self.calls.append("close")
        self._closed = True


def install_publisher(monkeypatch: pytest.MonkeyPatch, publisher: PublisherDouble) -> None:
    store = object()
    monkeypatch.setattr(support, "GuardStore", lambda _home: store)

    def get_publisher(actual_store: object) -> PublisherDouble:
        assert actual_store is store
        return publisher

    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", get_publisher)
    monkeypatch.setattr(support, "time", SimpleNamespace(monotonic=lambda: 100.0))


@pytest.mark.parametrize(("platform", "deadline"), [("linux", 103.0), ("win32", 125.0)])
def test_failed_wait_observes_once_and_preserves_deadline_failure_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    deadline: float,
) -> None:
    publisher = PublisherDouble(ready=False)
    install_publisher(monkeypatch, publisher)
    monkeypatch.setattr(support, "sys", SimpleNamespace(platform=platform))
    observations: list[object] = []

    def observe(actual: object) -> None:
        assert actual is publisher
        assert publisher.calls == ["start", ("wait", deadline)]
        observations.append(actual)

    monkeypatch.setattr(support, "_emit_publication_failure_observation", observe)
    with (
        pytest.raises(AssertionError, match=r"^native policy publisher was not ready: None$"),
        support.native_policy_snapshot(Path("synthetic-guard-home")),
    ):
        pytest.fail("An unready publisher must not yield authority.")
    assert observations == [publisher]
    assert publisher.calls == ["start", ("wait", deadline), "close"]


def test_success_yields_original_snapshot_without_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = {"generation": 1}
    publisher = PublisherDouble(ready=True, snapshot=snapshot)
    install_publisher(monkeypatch, publisher)
    monkeypatch.setattr(support, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        support,
        "_emit_publication_failure_observation",
        lambda _publisher: pytest.fail("Successful publication must not be observed."),
    )
    with support.native_policy_snapshot(Path("synthetic-guard-home")) as actual:
        assert actual is snapshot
        assert publisher.calls == ["start", ("wait", 103.0), "snapshot"]
    assert publisher.calls == ["start", ("wait", 103.0), "snapshot", "close"]


def test_empty_acked_snapshot_keeps_existing_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = PublisherDouble(ready=True)
    install_publisher(monkeypatch, publisher)
    monkeypatch.setattr(support, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        support,
        "_emit_publication_failure_observation",
        lambda _publisher: pytest.fail("Only the failed readiness wait is observed."),
    )
    with (
        pytest.raises(AssertionError, match=r"^native policy publisher returned no ACKed snapshot$"),
        support.native_policy_snapshot(Path("synthetic-guard-home")),
    ):
        pytest.fail("An absent snapshot must not yield authority.")
    assert publisher.calls == ["start", ("wait", 103.0), "snapshot", "close"]


class FrameProbe:
    def __init__(self, module: str, code: object, parent: object = None) -> None:
        self.f_globals = {"__name__": module, "policy": "private-frame-canary"}
        self.f_code = code
        self.parent = parent
        self.parent_reads = 0

    @property
    def f_back(self) -> object:
        self.parent_reads += 1
        return self.parent

    @property
    def f_locals(self) -> object:
        pytest.fail("Frame locals must never be read.")

    @property
    def f_lineno(self) -> object:
        pytest.fail("Raw stack locations must never be read.")


class ForbiddenOtherThreadFrame:
    @property
    def f_globals(self) -> object:
        pytest.fail("Unrelated threads must not be inspected.")


def read_observation(output: io.StringIO) -> dict[str, object]:
    lines = output.getvalue().splitlines()
    assert len(lines) == 1
    assert len(lines[0]) < 512
    prefix = "native_policy_readiness_observation="
    assert lines[0].startswith(prefix)
    result = json.loads(lines[0][len(prefix) :])
    assert set(result) == {
        "phase",
        "started",
        "closed",
        "acked",
        "snapshot_present",
        "error_present",
        "worker_present",
        "worker_alive",
        "worker_frame_present",
        "frame_limit_reached",
        "observation_failed",
    }
    assert all(type(value) is bool for key, value in result.items() if key != "phase")
    return result


def test_observation_uses_one_worker_and_emits_only_finite_phase_and_booleans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = threading.current_thread()
    worker_ident = worker.ident
    assert worker_ident is not None
    known = FrameProbe(transport.__name__, transport._publish_snapshot_v3.__code__)
    unknown = FrameProbe(
        "private-module-canary",
        SimpleNamespace(co_name="private-function-canary"),
        known,
    )
    calls: list[str] = []

    def current_frames() -> dict[int, object]:
        calls.append("capture")
        return {worker_ident: unknown, worker_ident + 1: ForbiddenOtherThreadFrame()}

    output = io.StringIO()
    monkeypatch.setattr(support, "sys", SimpleNamespace(_current_frames=current_frames, stderr=output))
    publisher = SimpleNamespace(
        _thread=worker,
        _started=True,
        _closed=False,
        _acked=False,
        _snapshot={"policy": "private-policy-canary"},
        _last_error="private-error-canary",
        identity="private-identity-canary",
        path="private-path-canary",
    )
    support._emit_publication_failure_observation(publisher)
    result = read_observation(output)
    assert result == {
        "phase": "v3_transport",
        "started": True,
        "closed": False,
        "acked": False,
        "snapshot_present": True,
        "error_present": True,
        "worker_present": True,
        "worker_alive": True,
        "worker_frame_present": True,
        "frame_limit_reached": False,
        "observation_failed": False,
    }
    assert calls == ["capture"]
    assert unknown.parent_reads == 1
    assert known.parent_reads == 0
    assert "private-" not in output.getvalue()
    assert str(worker_ident) not in output.getvalue()


def test_unknown_stack_names_are_not_reported_as_a_known_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = threading.current_thread()
    frame = FrameProbe("private-module-canary", transport._publish_snapshot_v3.__code__)
    output = io.StringIO()
    monkeypatch.setattr(
        support,
        "sys",
        SimpleNamespace(_current_frames=lambda: {worker.ident: frame}, stderr=output),
    )
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == "unknown"
    assert result["frame_limit_reached"] is False
    assert result["observation_failed"] is False
    assert "private-" not in output.getvalue()


def test_frame_traversal_is_bounded_without_reading_locals(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = threading.current_thread()
    frame = FrameProbe("private-module-canary", SimpleNamespace(co_name="private-function-canary"))
    frame.parent = frame
    output = io.StringIO()
    monkeypatch.setattr(
        support,
        "sys",
        SimpleNamespace(_current_frames=lambda: {worker.ident: frame}, stderr=output),
    )
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == "unknown"
    assert result["frame_limit_reached"] is True
    assert result["observation_failed"] is False
    assert frame.parent_reads == 32
    assert "private-" not in output.getvalue()


def test_capture_error_is_a_boolean_without_exception_contents(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_capture() -> object:
        raise RuntimeError("private-exception-canary")

    output = io.StringIO()
    monkeypatch.setattr(
        support,
        "sys",
        SimpleNamespace(_current_frames=refuse_capture, stderr=output),
    )
    support._emit_publication_failure_observation(SimpleNamespace(_thread=threading.current_thread()))
    result = read_observation(output)
    assert result["phase"] == "unknown"
    assert result["observation_failed"] is True
    assert "private-" not in output.getvalue()


def test_diagnostic_output_failure_cannot_mask_original_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class RefusingOutput:
        def write(self, _text: str) -> None:
            raise OSError("private-output-canary")

    publisher = PublisherDouble(ready=False)
    install_publisher(monkeypatch, publisher)
    monkeypatch.setattr(support, "sys", SimpleNamespace(platform="linux", stderr=RefusingOutput()))
    with (
        pytest.raises(AssertionError, match=r"^native policy publisher was not ready: None$"),
        support.native_policy_snapshot(Path("synthetic-guard-home")),
    ):
        pytest.fail("An unready publisher must not yield authority.")
    assert publisher.calls == ["start", ("wait", 103.0), "close"]


@pytest.mark.parametrize(
    ("module", "code", "phase"),
    [
        (
            context.__name__,
            context.compiled_v3_compatible_policy.__code__,
            "v3_input_capture",
        ),
        (
            inputs.__name__,
            inputs.NativePolicySnapshotPublisherInputs._resident_directory_fingerprint.__code__,
            "resident_directory",
        ),
        (
            inputs.__name__,
            inputs.NativePolicySnapshotPublisherInputs._confirm_resident_fingerprint.__code__,
            "resident_confirmation",
        ),
    ],
)
def test_publication_subphases_remain_finite_and_stop_at_the_known_frame(
    monkeypatch: pytest.MonkeyPatch, module: str, code: CodeType, phase: str
) -> None:
    worker = threading.current_thread()
    worker_ident = worker.ident
    assert worker_ident is not None
    frame = FrameProbe(module, code, ForbiddenOtherThreadFrame())
    captures: list[str] = []

    def current_frames() -> dict[int, object]:
        captures.append("capture")
        return {worker_ident: frame}

    output = io.StringIO()
    monkeypatch.setattr(support, "sys", SimpleNamespace(_current_frames=current_frames, stderr=output))
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == phase
    assert result["worker_frame_present"] is True
    assert result["frame_limit_reached"] is False
    assert result["observation_failed"] is False
    assert captures == ["capture"]
    assert frame.parent_reads == 0
    assert "private-" not in output.getvalue()
    assert str(worker_ident) not in output.getvalue()


@pytest.mark.parametrize(
    ("module", "code", "phase"),
    [
        (
            source_requirement.__name__,
            source_requirement.refresh_source_requirement.__code__,
            "source_presence",
        ),
        (
            secret_integrity.__name__,
            secret_integrity.StoreSecretPolicyIntegrityMixin._policy_integrity_secret_material.__code__,
            "integrity_key",
        ),
        (
            authority_read.__name__,
            authority_read.read_native_policy_authority_inputs.__code__,
            "authority_capture",
        ),
        (
            context.__name__,
            context._v3_inputs_from_capture.__code__,
            "v3_projection",
        ),
    ],
)
def test_v3_recapture_calls_remain_finite_and_stop_at_the_known_frame(
    monkeypatch: pytest.MonkeyPatch, module: str, code: CodeType, phase: str
) -> None:
    worker = threading.current_thread()
    worker_ident = worker.ident
    assert worker_ident is not None
    frame = FrameProbe(module, code, ForbiddenOtherThreadFrame())
    captures: list[str] = []

    def current_frames() -> dict[int, object]:
        captures.append("capture")
        return {worker_ident: frame}

    output = io.StringIO()
    monkeypatch.setattr(support, "sys", SimpleNamespace(_current_frames=current_frames, stderr=output))
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == phase
    assert result["worker_frame_present"] is True
    assert result["frame_limit_reached"] is False
    assert result["observation_failed"] is False
    assert captures == ["capture"]
    assert frame.parent_reads == 0
    assert "private-" not in output.getvalue()
    assert str(worker_ident) not in output.getvalue()


_Connection = connection_schema.StoreConnectionSchemaMixin
_Integrity = secret_integrity.StoreSecretPolicyIntegrityMixin
_Vault = store_base.EncryptedFileSecretStore
_Keyring = store_base.SystemKeyringSecretStore
_capture = authority_read._capture_native_policy_authority_inputs


class SourceSiteFrame(FrameProbe):
    def __init__(self, module: str, code: CodeType, line: int) -> None:
        super().__init__(module, code, ForbiddenOtherThreadFrame())
        self.line = line

    @property
    def f_lineno(self) -> int:
        return self.line


def assert_nested_observation(monkeypatch: pytest.MonkeyPatch, frame: FrameProbe, phase: str) -> None:
    worker = threading.current_thread()
    worker_ident = worker.ident
    assert worker_ident is not None
    output = io.StringIO()
    captures: list[str] = []

    def current_frames() -> dict[int, object]:
        captures.append("capture")
        return {worker_ident: frame, worker_ident + 1: ForbiddenOtherThreadFrame()}

    monkeypatch.setattr(support, "sys", SimpleNamespace(_current_frames=current_frames, stderr=output))
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == phase
    assert result["worker_frame_present"] is True
    assert result["frame_limit_reached"] is False
    assert result["observation_failed"] is False
    assert captures == ["capture"]
    assert frame.parent_reads == 0
    assert "private-" not in output.getvalue()
    assert str(worker_ident) not in output.getvalue()


@pytest.mark.parametrize(
    ("function", "phase"),
    [
        (_Connection._connect, "connection_admission"),
        (_Connection._connect_once, "connection_transaction"),
        (_Connection._hold_storage_gate, "storage_gate"),
        (_Connection._hold_advisory_file_lock, "advisory_gate"),
        (_Connection.hold_oauth_credential_lock, "credential_gate"),
        (storage_lock.hold_storage_file_lock, "storage_file_gate"),
        (storage_lock._WindowsStorageLock.acquire, "storage_lock_acquire"),
        (storage_lock._WindowsStorageLock.release, "storage_lock_release"),
        (_Integrity._policy_integrity_cache_marker, "integrity_marker"),
        (_Integrity._load_policy_integrity_state_cache_marker, "integrity_marker_sql"),
        (_Integrity._get_policy_integrity_secret_from_store, "integrity_backend_read"),
        (_Integrity._load_policy_integrity_control_state, "integrity_control"),
        (_Integrity._repair_store_permissions, "store_permissions"),
        (store_base._acquire_advisory_file_lock, "advisory_lock_acquire"),
        (store_base._release_advisory_file_lock, "advisory_lock_release"),
        (_Vault._ensure_ready, "vault_initialization"),
        (_Vault.get_secret, "vault_read"),
        (_Vault.set_secret, "vault_write"),
        (_Vault._load_fernet_key, "vault_key_read"),
        (_Vault._atomic_write_bytes, "vault_atomic_write"),
        (_Vault._decrypt_fernet, "vault_decrypt"),
        (_Keyring._backend_is_available, "keyring_selection"),
        (_Keyring._load_keyring_module_or_none, "keyring_module"),
        (_Keyring.get_secret, "keyring_read"),
        (_Keyring.get_secret_with_timeout, "keyring_bounded_read"),
        (_Keyring._get_macos_secret_in_isolated_process, "keyring_process_read"),
        (integrity_backend.build_policy_integrity_secret_store, "integrity_backend_selection"),
        (authority_read._capture_native_policy_authority_inputs, "authority_snapshot"),
        (authority_managed.read_frozen_native_managed_authority, "managed_authority_read"),
        (authority_managed.FrozenNativeManagedAuthority.require_current_secrets, "managed_secret_fence"),
        (outbox.finalize_review_event_payload_hashes, "transaction_hashes"),
        (outbox.commit_review_event_transaction, "transaction_commit"),
        (outbox.notify_review_event_wake, "transaction_notification"),
    ],
)
def test_nested_call_categories_bind_real_code_and_keep_finite_output(
    monkeypatch: pytest.MonkeyPatch, function: Callable[..., object], phase: str
) -> None:
    code = inspect.unwrap(function).__code__
    frame = SourceSiteFrame(function.__module__, code, -1)
    assert_nested_observation(monkeypatch, frame, phase)


@pytest.mark.parametrize(
    ("function", "first", "start", "end", "needle", "phase"),
    [
        (_Connection._connect_once, 364, 370, 370, "connection = sqlite3.connect(", "sqlite_open"),
        (_Connection._connect_once, 364, 382, 390, 'connection.execute(f"pragma busy_timeout=', "sqlite_setup"),
        (_Connection._connect_once, 364, 410, 410, "connection.close()", "sqlite_close"),
        (_Connection._hold_advisory_file_lock, 475, 493, 493, "time.sleep(poll_seconds)", "advisory_gate_wait"),
        (_Vault._ensure_ready, 900, 908, 910, "with _ENCRYPTED_SECRET_INIT_LOCKS_GUARD:", "vault_thread_gate"),
        (_Vault._ensure_ready, 900, 924, 924, "time.sleep(0.01)", "vault_file_gate_wait"),
        (_capture, 130, 152, 152, 'connection.execute("begin")', "authority_transaction_begin"),
        (_capture, 130, 154, 157, "state_rows = connection.execute(", "authority_state_sql"),
        (_capture, 130, 166, 169, "controls = connection.execute(", "authority_controls_sql"),
        (_capture, 130, 177, 179, "device_row = connection.execute(", "authority_device_sql"),
        (_capture, 130, 187, 190, "for row in connection.execute(", "authority_source_sql"),
        (_capture, 130, 201, 205, "local_rows = connection.execute(", "authority_rows_sql"),
        (outbox.commit_review_event_transaction, 80, 88, 88, "connection.commit()", "sqlite_commit"),
    ],
)
def test_nested_source_sites_bind_real_statements_without_exposing_locations(
    monkeypatch: pytest.MonkeyPatch,
    function: Callable[..., object],
    first: int,
    start: int,
    end: int,
    needle: str,
    phase: str,
) -> None:
    code = inspect.unwrap(function).__code__
    lines, source_start = inspect.getsourcelines(function)
    assert code.co_firstlineno == first
    assert needle in lines[start - source_start]
    executable_lines = sorted({line for _, _, line in code.co_lines() if line is not None and start <= line <= end})
    assert executable_lines
    for line in (executable_lines[0], executable_lines[-1]):
        frame = SourceSiteFrame(function.__module__, code, line)
        assert_nested_observation(monkeypatch, frame, phase)


def test_unmapped_qualified_call_does_not_read_source_position(monkeypatch: pytest.MonkeyPatch) -> None:
    code = SimpleNamespace(co_name="private-function-canary", co_qualname="private-qualified-canary")
    frame = FrameProbe(store_base.__name__, code)
    output = io.StringIO()
    worker = threading.current_thread()
    monkeypatch.setattr(support, "sys", SimpleNamespace(_current_frames=lambda: {worker.ident: frame}, stderr=output))
    support._emit_publication_failure_observation(SimpleNamespace(_thread=worker))
    result = read_observation(output)
    assert result["phase"] == "unknown"
    assert result["observation_failed"] is False
    assert "private-" not in output.getvalue()


def test_unpinned_function_entry_never_uses_source_position(monkeypatch: pytest.MonkeyPatch) -> None:
    original = inspect.unwrap(_Connection._connect_once).__code__
    code = original.replace(co_firstlineno=original.co_firstlineno + 1)
    frame = FrameProbe(connection_schema.__name__, code, ForbiddenOtherThreadFrame())
    assert_nested_observation(monkeypatch, frame, "connection_transaction")
