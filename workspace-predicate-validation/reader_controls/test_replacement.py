"""Actual cold fixture forwarding with modeled ACK bytes, no native workload."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from codex_plugin_scanner.guard.daemon import hook_worker
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_workspace_lifecycle as lifecycle
from scripts import native_slo_workspace_startup as startup
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_workspace_lifecycle_faults import FirstAdmissionReplyFault
from tests.native_policy_snapshot_test_fixtures import _ack, _status

from predicate.bindings import Registry
from predicate.capture import Capture
from predicate.hooks import OwnedHooks
from read_result import admit_observation
from reader_controls.test_reader import good


def old_capture() -> Capture:
    publisher = SimpleNamespace(_condition=threading.Condition(), _acked=True, _closed=True, _epoch=1, _snapshot=None)
    worker = SimpleNamespace(policy_snapshot_publisher=publisher)
    session = SimpleNamespace(store=object(), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    return Capture(session)


def registry() -> Registry:
    return Registry(
        Path(lifecycle.__file__).resolve().parents[1], Path(__file__).resolve().parents[1] / "source-bindings.json"
    )


def test_actual_cold_factory_fault_retry_and_stored_worker_handoff(tmp_path: Path, monkeypatch: Any) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    prepare_empty_command_authority(store)
    calls, factories, faults = [], [], []

    def transport(**kwargs: Any) -> bytes:
        calls.append(kwargs)
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=transport)

    def factory(candidate: Any, **kwargs: Any) -> Any:
        factories.append((candidate, kwargs))
        return publisher

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    capture, sites = old_capture(), registry()

    def prepare(cold: Any) -> None:
        assert capture.publisher is cold and capture.store is store
        fault = FirstAdmissionReplyFault(cold)
        fault.__enter__()
        faults.append(fault)

    def replacement() -> Any:
        with startup.prepare_owned_publisher(store, prepare) as captured:
            current = hook_worker.get_native_policy_snapshot_publisher(cast(Any, store))
            assert current is publisher and captured == [publisher]
            current._publish_once()
            assert current.current_snapshot_binding() is None
            current._publish_once()
            assert current.current_snapshot_binding() is not None
            worker = SimpleNamespace(store=store, policy_snapshot_publisher=current)
            assert hooks.owned("worker", (worker,))
            assert capture.worker is worker
            return worker

    sites.add(replacement.__code__, "control")
    sites.add(sys._getframe().f_code, "control")
    original_transport = publisher._client_request
    try:
        with OwnedHooks(capture, sites) as hooks:
            result = capture.call("service_replacement", "control:replacement", replacement, (), {})
            publisher.close()
            faults[0].__exit__()
        assert result is capture.worker and hooks.restored
        assert publisher._client_request is original_transport
        assert hook_worker.get_native_policy_snapshot_publisher is factory
        assert factories == [(store, {})] and len(calls) == 2
        proof = faults[0].report()
        assert proof["real_client_calls"] == 2
        assert all(
            proof[name] is True
            for name in (
                "real_accepted_reply_discarded",
                "production_ack_error_observed",
                "first_error_withheld_ack",
                "subsequent_transport_forwarded",
            )
        )
        report = capture.freeze()
        assert report["observation_complete"] is True, report
        assert report["factory_handoffs"] == report["worker_handoffs"] == 1
        factory_row = next(row for row in report["rows"] if row["stage"] == "publisher_factory")
        assert factory_row["before"]["publisher_instance"] == 0 and factory_row["after"]["publisher_instance"] == 1
        assert any(
            row["stage"] == "record_error" and row["site"].startswith("scripts.native_slo_workspace_lifecycle_faults:")
            for row in report["rows"]
        )
        assert all(row["site"] != "unknown" for row in report["rows"])
    finally:
        for fault in faults:
            fault.__exit__()
        publisher.close()


def test_actual_factory_exception_identity_and_no_handoff(monkeypatch: Any) -> None:
    error = OSError("PRIVATE_SENTINEL")
    calls = []

    def factory(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        raise error

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    capture, sites = old_capture(), registry()
    store = object()

    def replacement() -> None:
        with startup.prepare_owned_publisher(store, lambda _: None):
            hook_worker.get_native_policy_snapshot_publisher(cast(Any, store))

    with OwnedHooks(capture, sites) as hooks, pytest.raises(OSError) as caught:
        capture.call("service_replacement", "control:replacement", replacement, (), {})
    assert caught.value is error and calls == [((store,), {})] and hooks.restored
    report = capture.freeze()
    assert report["observation_complete"] is True and report["factory_handoffs"] == 0
    assert "PRIVATE_SENTINEL" not in json.dumps(report)


def test_handoff_observation_failure_preserves_factory_result(monkeypatch: Any) -> None:
    capture, sites = old_capture(), registry()
    store = object()
    publisher = SimpleNamespace(_thread=None, _started=False, current_snapshot_binding=lambda: None)
    calls = []

    def factory(candidate: Any) -> Any:
        calls.append(candidate)
        return publisher

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)

    def replacement() -> Any:
        with startup.prepare_owned_publisher(store, lambda _: None):
            return hook_worker.get_native_policy_snapshot_publisher(cast(Any, store))

    with OwnedHooks(capture, sites) as hooks:
        result = capture.call("service_replacement", "control:replacement", replacement, (), {})
    assert result is publisher and calls == [store] and hooks.restored
    assert capture.freeze()["lost"] is True


def test_unowned_factory_call_is_untouched(monkeypatch: Any) -> None:
    value, store, calls = object(), object(), []

    def factory(candidate: Any) -> Any:
        calls.append(candidate)
        return value

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    capture = old_capture()
    with OwnedHooks(capture, registry()) as hooks:
        assert hook_worker.get_native_policy_snapshot_publisher(cast(Any, store)) is value
    assert calls == [store] and hooks.restored and capture.rows == []


@pytest.mark.parametrize("failure", ["repeated", "same_store", "wrong_store", "same_publisher"])
def test_handoff_identity_ambiguity_is_refused(failure: str) -> None:
    capture = old_capture()
    store = object()
    publisher = SimpleNamespace(store=store)
    if failure == "repeated":
        capture.adopt_publisher(publisher, store)
        store = object()
        publisher = SimpleNamespace(store=store)
    elif failure == "same_store":
        store = capture.store
        publisher = SimpleNamespace(store=store)
    elif failure == "wrong_store":
        publisher.store = object()
    else:
        publisher = capture.publisher
    with pytest.raises(ValueError, match="replacement_publisher_identity"):
        capture.adopt_publisher(publisher, store)


def test_worker_identity_is_bound_without_getters() -> None:
    capture = old_capture()
    previous = capture.worker
    store = object()
    publisher = SimpleNamespace(store=store)
    capture.adopt_publisher(publisher, store)
    assert not capture.owns_worker(previous)
    assert not capture.owns_worker(SimpleNamespace(store=store, policy_snapshot_publisher=object()))
    worker = SimpleNamespace(store=store, policy_snapshot_publisher=publisher)
    assert capture.owns_worker(worker) and capture.owns_worker(worker)
    assert not capture.owns_worker(SimpleNamespace(store=store, policy_snapshot_publisher=publisher))
    assert capture.worker_handoffs == 1


def test_preinjection_refusal_does_not_claim_fault_offered() -> None:
    report, cell = good()
    result = admit_observation(report, "first_admission_fault", cell)
    assert not result["original_cell_passed"]
    assert report["observation"]["factory_handoffs"] == 0
    assert "fault" not in cell and "requests" not in cell


@pytest.mark.parametrize(
    "field,value", [("factory_handoffs", 2), ("worker_handoffs", True), ("publisher_instances", 2)]
)
def test_invalid_ownership_census_refused(field: str, value: Any) -> None:
    report, cell = good()
    report["observation"][field] = value
    with pytest.raises(ValueError):
        admit_observation(report, "first_admission_fault", cell)


@pytest.mark.parametrize("bound", [False, True])
def test_original_contextmanager_generator_and_cold_check_have_exact_registry_coverage(
    bound: bool, tmp_path: Path, monkeypatch: Any
) -> None:
    rows = json.loads((Path(__file__).resolve().parents[1] / "source-bindings.json").read_text())
    if not bound:
        rows = [row for row in rows if row["path"] != "scripts/native_slo_workspace_startup.py"]
    manifest = tmp_path / "registry.json"
    manifest.write_text(json.dumps(rows))
    sites = Registry(Path(lifecycle.__file__).resolve().parents[1], manifest)
    observed = []

    def current_binding() -> None:
        try:
            observed.append(sites.site(sys._getframe(1)))
        except RuntimeError:
            observed.append("refused")

    publisher = SimpleNamespace(_thread=None, _started=False, current_snapshot_binding=current_binding)
    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", lambda _: publisher)
    store = object()
    prepared = []
    with startup.prepare_owned_publisher(store, prepared.append):
        assert hook_worker.get_native_policy_snapshot_publisher(cast(Any, store)) is publisher
    assert prepared == [publisher] and len(observed) == 1
    if bound:
        assert observed[0].startswith("scripts.native_slo_workspace_startup:prepare_owned_publisher.<locals>.observed:")
    else:
        assert observed == ["refused"]


@pytest.mark.parametrize("failure", ["shape", "depth"])
def test_decorated_registry_refuses_unreviewable_wrapper_chain(failure: str) -> None:
    sites = Registry.__new__(Registry)
    sites.codes, sites.sites = {}, {}

    def operation() -> None:
        pass

    vars(operation)["__wrapped__"] = object() if failure == "shape" else operation
    with pytest.raises(RuntimeError, match="predicate_wrap"):
        sites.add_function(operation, operation.__module__)


def recovered_report() -> tuple[dict[str, Any], dict[str, Any]]:
    report, cell = good()
    rows = report["observation"]["rows"]
    for index, stage, parent, await_id, start, end, before, after in (
        (1, "service_replacement", None, None, 0.3, 0.6, 0, 1),
        (2, "publisher_factory", 1, None, 0.4, 0.5, 0, 1),
        (3, "await_ack", None, 2, 0.7, 0.8, 1, 1),
    ):
        rows.append(
            {
                "id": index,
                "stage": stage,
                "parent": parent,
                "await": await_id,
                "site": "fixed_source:42",
                "entry_seconds": start,
                "exit_seconds": end,
                "before": {"publisher_instance": before},
                "after": {"publisher_instance": after},
                "outcome": "return",
                "returned": {"kind": "other"},
            }
        )
    report["observation"].update(await_calls=2, factory_handoffs=1, worker_handoffs=1, publisher_instances=2)
    return report, cell


def test_recovered_owner_join_preserves_original_failure() -> None:
    report, cell = recovered_report()
    result = admit_observation(report, "first_admission_fault", cell)
    assert result["diagnostic_complete"] and result["original_cell_passed"] is False


@pytest.mark.parametrize(
    "fault", ["parent", "old_owner", "new_owner", "await_owner", "factory_interval", "await_interval"]
)
def test_counts_alone_cannot_admit_replacement_ownership(fault: str) -> None:
    report, cell = recovered_report()
    rows = report["observation"]["rows"]
    if fault == "parent":
        rows[2]["parent"] = None
    elif fault == "old_owner":
        rows[2]["before"]["publisher_instance"] = 1
    elif fault == "new_owner":
        rows[2]["after"]["publisher_instance"] = 0
    elif fault == "await_owner":
        rows[3]["before"]["publisher_instance"] = 0
    elif fault == "factory_interval":
        rows[2]["exit_seconds"] = 0.65
    else:
        rows[3]["entry_seconds"] = 0.55
    with pytest.raises(ValueError):
        admit_observation(report, "first_admission_fault", cell)
