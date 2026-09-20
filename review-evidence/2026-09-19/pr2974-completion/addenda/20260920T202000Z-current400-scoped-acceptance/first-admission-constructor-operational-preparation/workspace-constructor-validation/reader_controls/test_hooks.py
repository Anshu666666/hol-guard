"""Exact registry, alias restoration and real cold-worker forwarding controls."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from codex_plugin_scanner.guard.daemon import hook_worker, server, server_http, server_service
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_workspace_lifecycle as lifecycle
from scripts import native_slo_workspace_startup as startup
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from tests.native_policy_snapshot_test_fixtures import _ack, _status

from constructor.bindings import Registry
from constructor.capture import Capture
from constructor.hooks import CALLERS, OwnedHooks
from constructor.reader import admit_phases


def registry() -> Registry:
    return Registry(
        Path(lifecycle.__file__).resolve().parents[1], Path(__file__).resolve().parents[1] / "source-bindings.json"
    )


def test_original_class_aliases_and_all_eight_bindings_restore() -> None:
    value, sites = Capture(object()), registry()
    cls, http = server.GuardDaemonServer, server._GuardDaemonHttpServer
    methods = (cls.__init__, http.__init__, http._initialize_request_services, hook_worker.HookWorker.__init__)
    with OwnedHooks(value, sites) as hooks:
        assert server.GuardDaemonServer is cls is server_service.GuardDaemonServer
        assert server._GuardDaemonHttpServer is http is server_http._GuardDaemonHTTPServer
        assert len(hooks.bindings) == 8
    assert hooks.restored
    assert methods == (cls.__init__, http.__init__, http._initialize_request_services, hook_worker.HookWorker.__init__)
    assert value.freeze()["replacement_calls"] == 0


def test_registry_rejects_changed_provider_before_any_patch(tmp_path: Path) -> None:
    root = Path(lifecycle.__file__).resolve().parents[1]
    manifest = json.loads((Path(__file__).resolve().parents[1] / "source-bindings.json").read_text())
    manifest[0]["sha256"] = "0" * 64
    path = tmp_path / "bindings.json"
    path.write_text(json.dumps(manifest))
    original = server.GuardDaemonServer.__init__
    with pytest.raises(RuntimeError, match="source_identity"):
        Registry(root, path)
    assert server.GuardDaemonServer.__init__ is original


def test_same_filename_and_name_do_not_admit_mutated_live_code(monkeypatch: pytest.MonkeyPatch) -> None:
    original = lifecycle.run_lifecycle_cell.__code__
    values = list(original.co_consts)
    index = next(index for index, item in enumerate(values) if type(item) is str)
    values[index] = "PRIVATE_CHANGED_CODE_CONSTANT"
    changed = original.replace(co_consts=tuple(values))
    assert changed.co_filename == original.co_filename and changed.co_qualname == original.co_qualname
    monkeypatch.setattr(lifecycle.run_lifecycle_cell, "__code__", changed)
    with pytest.raises(RuntimeError, match="live_code_mismatch"):
        registry()


def test_original_setup_failure_restores_every_already_applied_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    sites, original = registry(), server.GuardDaemonServer.__init__
    hooks = OwnedHooks(Capture(object()), sites)
    bind = hooks.bind
    count = 0

    def fail_third(*args: Any) -> None:
        nonlocal count
        count += 1
        if count == 3:
            raise RuntimeError("fixture")
        bind(*args)

    monkeypatch.setattr(hooks, "bind", fail_third)
    with pytest.raises(RuntimeError, match="fixture"):
        hooks.__enter__()
    assert hooks.restored and server.GuardDaemonServer.__init__ is original


def test_unknown_replacement_caller_forwards_once_without_activating(monkeypatch: pytest.MonkeyPatch) -> None:
    session, result, calls = object(), object(), []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return result

    value = Capture(session)
    sites = registry()
    monkeypatch.setattr(lifecycle, "replace_service", original)
    with OwnedHooks(value, sites) as hooks:
        assert lifecycle.replace_service(session, (), prepare=None) is result
    assert calls == [((session, ()), {"prepare": None})]
    assert hooks.restored and value.lost and value.replacements == 0 and not value.rows


def test_actual_hook_worker_and_cold_factory_use_one_original_start_wait_and_modeled_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    prepare_empty_command_authority(store)
    counts = {"factory": 0, "start": 0, "wait": 0, "transport": 0}

    def transport(**kwargs: Any) -> bytes:
        counts["transport"] += 1
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=transport)
    original_start, original_wait = NativePolicySnapshotPublisher.start, NativePolicySnapshotPublisher.wait_until_ready

    def start(instance: Any) -> Any:
        counts["start"] += 1
        return original_start(instance)

    def wait(instance: Any, *args: Any, **kwargs: Any) -> Any:
        counts["wait"] += 1
        return original_wait(instance, *args, **kwargs)

    def factory(candidate: Any, **_kwargs: Any) -> Any:
        assert candidate is store
        counts["factory"] += 1
        return publisher

    sites, value = registry(), Capture(object())
    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    monkeypatch.setattr(NativePolicySnapshotPublisher, "start", start)
    monkeypatch.setattr(NativePolicySnapshotPublisher, "wait_until_ready", wait)
    value.store = store
    original_site = sites.site
    created = []

    def create_worker() -> None:
        # Only the outer three constructors are modeled. This is the actual
        # production HookWorker and startup factory, with modeled ACK bytes.
        with startup.prepare_owned_publisher(store, lambda _publisher: value.acceptance(time.monotonic())):
            created.append(hook_worker.HookWorker(store=store))

    def control_site(frame: Any) -> str:
        if frame.f_code is create_worker.__code__:
            return CALLERS["hook_worker_constructor"] + ":199"
        return original_site(frame)

    monkeypatch.setattr(sites, "site", control_site)

    def enter(index: int) -> None:
        stage = list(CALLERS)[index]
        call = create_worker if index == 2 else lambda: enter(index + 1)
        value.call(stage, CALLERS[stage], call, (), {})

    try:
        with OwnedHooks(value, sites) as hooks:
            value.replacement(enter, (0,), {})
        assert hooks.restored and created[0].policy_snapshot_publisher is publisher
        assert counts["factory"] == counts["start"] == counts["wait"] == 1
        assert counts["transport"] >= 1
        assert admit_phases(value.freeze())["all_five_returned"] is True
    finally:
        publisher.close()
        assert publisher.closed and (publisher._thread is None or not publisher._thread.is_alive())
