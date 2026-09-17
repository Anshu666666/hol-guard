"""Periodic reads coexist with native readers; semantic writes still exclude them."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    hold_command_control_authority_lock,
    require_command_control_mutation_lease,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime

from .test_guard_extension_control_authority import MemorySecretStore, _store

_READER = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
try:
    with hold_command_control_authority_lock(Path(sys.argv[1]), shared=True, timeout_seconds=0):
        pass
except TimeoutError:
    sys.exit(3)
"""


def _foreign_reader(home: Path) -> bool:
    result = subprocess.run([sys.executable, "-c", _READER, str(home)], capture_output=True, timeout=10, check=False)
    assert result.returncode in {0, 3}, result.stderr.decode("utf-8", errors="replace")
    return result.returncode == 0


@pytest.mark.parametrize("enrolled", [False, True])
def test_unchanged_periodic_refresh_keeps_foreign_shared_reader_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enrolled: bool
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path, MemorySecretStore(), enroll=enrolled)
    initial = store.read_extension_control_authority_for_registry(REGISTRY)
    server = SimpleNamespace(store=store, extension_control_runtime=ExtensionControlRuntime(initial))
    original = store._read_extension_control_authority_locked
    available: list[bool] = []

    def checked_read(*args: object, **kwargs: object) -> ExtensionControlAuthorityView:
        available.append(_foreign_reader(tmp_path))
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", checked_read)
    # Freeze the actual old path as a control: a read-only workload still took EX.
    assert store.read_extension_control_authority_for_registry(REGISTRY) == initial
    assert available == [False]
    available.clear()
    result = _GuardDaemonHTTPServer.refresh_extension_control_runtime(server)
    assert available == [True]
    assert result == server.extension_control_runtime.current()
    assert result.revision == initial.revision
    assert result.health is initial.health


def test_mutation_required_releases_shared_lease_before_fresh_exclusive_read(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    initial = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, REGISTRY.catalog_digest, ())
    updated = replace(initial, revision=2)
    events: list[tuple[str, bool]] = []

    class Store:
        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False
        ) -> ExtensionControlAuthorityView:
            assert registry is REGISTRY
            # Entering EX would raise the real reentrancy sentinel if the old
            # shared lease remained held. Both calls reacquire the OS lock.
            with hold_command_control_authority_lock(tmp_path, shared=read_only):
                events.append(("read", read_only))
                assert _foreign_reader(tmp_path) is read_only
                require_command_control_mutation_lease(tmp_path)
                events.append(("write", read_only))
                return updated

    server = SimpleNamespace(store=Store(), extension_control_runtime=ExtensionControlRuntime(initial))
    result = _GuardDaemonHTTPServer.refresh_extension_control_runtime(server)
    assert events == [("read", True), ("read", False), ("write", False)]
    assert result.revision == 2
    assert _foreign_reader(tmp_path)


def test_missing_authenticated_manifest_is_written_only_after_exclusive_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path, MemorySecretStore())
    initial = store.read_extension_control_authority_for_registry(REGISTRY)
    with store._connect() as connection:
        connection.execute("delete from extension_control_catalog_manifest")
    original = store._invalidate_native_extension_control_policy
    attempted: list[bool] = []
    completed: list[bool] = []

    def checked_invalidation(**kwargs: object) -> None:
        available = _foreign_reader(tmp_path)
        attempted.append(available)
        original(**kwargs)
        completed.append(available)

    monkeypatch.setattr(store, "_invalidate_native_extension_control_policy", checked_invalidation)
    runtime = ExtensionControlRuntime(initial)
    result = _GuardDaemonHTTPServer.refresh_extension_control_runtime(
        SimpleNamespace(store=store, extension_control_runtime=runtime)
    )
    assert attempted == [True, False] and completed == [False]
    assert result.health is AuthorityHealth.PROTECTED
    assert result.revision == initial.revision
    # The replacement is authenticated by the existing real reader/secret store.
    assert store.read_extension_control_authority_for_registry(REGISTRY, read_only=True) == initial
    assert attempted == [True, False]


def test_other_read_error_is_not_retried_as_a_mutation() -> None:
    initial = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, REGISTRY.catalog_digest, ())
    failure = RuntimeError("injected read failure")
    calls: list[bool] = []

    class Store:
        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False
        ) -> ExtensionControlAuthorityView:
            assert registry is REGISTRY
            calls.append(read_only)
            raise failure

    runtime = ExtensionControlRuntime(initial)
    before = runtime.current()
    with pytest.raises(RuntimeError) as caught:
        _GuardDaemonHTTPServer.refresh_extension_control_runtime(
            SimpleNamespace(store=Store(), extension_control_runtime=runtime)
        )
    assert caught.value is failure
    assert calls == [True]
    assert runtime.current() is before


@pytest.mark.parametrize(
    "health", [AuthorityHealth.TAMPERED, AuthorityHealth.DEGRADED_UNACKNOWLEDGED, AuthorityHealth.DEGRADED_ACKNOWLEDGED]
)
def test_nonprotected_authority_view_keeps_existing_runtime_semantics(health: AuthorityHealth) -> None:
    initial = ExtensionControlAuthorityView(AuthorityHealth.UNENROLLED, 0, REGISTRY.catalog_digest, ())
    view = replace(initial, health=health)
    calls: list[bool] = []

    class Store:
        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False
        ) -> ExtensionControlAuthorityView:
            assert registry is REGISTRY
            calls.append(read_only)
            return view

    runtime = ExtensionControlRuntime(initial)
    expected = ExtensionControlRuntime(initial).refresh(view)
    result = _GuardDaemonHTTPServer.refresh_extension_control_runtime(
        SimpleNamespace(store=Store(), extension_control_runtime=runtime)
    )
    assert result == expected
    assert calls == [True]
