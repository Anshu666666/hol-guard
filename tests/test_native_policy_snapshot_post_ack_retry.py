"""Keep a rejected V3 ACK closed while one bounded fresh publication recovers."""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import closing, contextmanager
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher as publisher_module
import codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport as transport_module
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import CapturedV3PublicationInputs
from codex_plugin_scanner.guard.oauth_connection_authority import read_connection_authority
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_capture_retry import _write_startup_status
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher

_CALLER_READY_SECONDS = 0.4
_STAMP = "2026-09-19T00:00:00Z"


@pytest.fixture
def publication(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text("")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as bootstrap:
        bootstrap._publish_once()
        assert bootstrap.is_ready(), bootstrap.last_error
    calls.clear()
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        assert not publisher.is_ready()
        assert publisher._snapshot is None
        assert publisher._published_cloud_inputs.source_identity is None
        yield store, publisher, calls


@contextmanager
def _one_worker_with_caller_deadline(publisher):
    errors = []

    def publish():
        try:
            publisher._publish_once()
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=publish, daemon=True)
    deadline = time.monotonic() + _CALLER_READY_SECONDS
    worker.start()
    try:
        ready = publisher.wait_until_ready(deadline_monotonic=deadline)
        if errors:
            raise errors[0]
        yield ready, deadline
    finally:
        publisher.close()
        worker.join(timeout=_PUBLISH_TIMEOUT_SECONDS)
        assert not worker.is_alive()
        if errors:
            raise errors[0]


def _credential_mutation(store, *, restore):
    key = store._oauth_local_credentials_state_key
    now = time.time()
    previous = store.get_sync_payload(key)
    with store._connect() as observer:
        before = read_native_policy_authority_inputs(store, now=now)
        before_authority = read_connection_authority(observer, key)
        version = observer.execute("pragma data_version").fetchone()[0]
        store.set_sync_payload(key, {"workspace_id": "synthetic-changed-workspace"}, _STAMP)
        if restore:
            if previous is None:
                store.delete_sync_payload(key)
            else:
                store.set_sync_payload(key, previous, _STAMP)
        assert observer.execute("pragma data_version").fetchone()[0] != version
        assert read_connection_authority(observer, key) != before_authority
        after = read_native_policy_authority_inputs(store, now=now)
    assert (before.input_digest == after.input_digest) is restore
    if restore:
        assert store.get_sync_payload(key) == previous


def _config_mutation(store, publisher, *, restore):
    before_config = publisher._compiled_effective_policy()
    before_policy = publisher_module._policy_fingerprint(before_config)
    action = "allow" if before_config.get("default_action") == "block" else "block"
    path = store.guard_home / "config.toml"
    before = path.stat()
    content = path.read_text()
    path.write_text(f'default_action = "{action}"\n')
    if restore:
        restored = path.with_name("config-restored.toml")
        restored.write_text(content)
        os.utime(restored, ns=(before.st_atime_ns, before.st_mtime_ns))
        restored.replace(path)
        assert path.read_text() == content
        assert path.stat().st_mtime_ns == before.st_mtime_ns
        assert path.stat().st_ino != before.st_ino
    else:
        assert path.read_text() != content
    after_policy = publisher_module._policy_fingerprint(publisher._compiled_effective_policy())
    assert (before_policy == after_policy) is restore


def _observe(publication, monkeypatch, *, phase, mutation="summary-once"):
    store, publisher, calls = publication
    state = SimpleNamespace(
        captures=[],
        reserved_inputs=[],
        validations=[],
        confirmations=[],
        writes=[],
        mutations=0,
        errors=[],
        accepted_at=[],
        transport_deadlines=[],
    )
    capture = publisher._publication_context
    reserve = transport_module.native_policy_snapshot_v3
    compile_policy = publisher_module.compiled_v3_compatible_policy
    confirm = publisher._confirm_resident_fingerprint
    client = publisher._client_request
    record_error = publisher._record_error
    schedule = publisher._schedule_renewal_locked
    assert client is not None

    def mutate():
        if mutation == "none" or (state.mutations and mutation != "summary-repeated"):
            return
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher._snapshot is None
        state.mutations += 1
        if mutation in {"summary-once", "summary-repeated", "deadline"}:
            state.writes.append(_write_startup_status(store, state.mutations, now=publisher._wall_clock()))
        elif mutation in {"credential-change", "credential-aba"}:
            _credential_mutation(store, restore=mutation == "credential-aba")
        elif mutation in {"config-change", "config-aba"}:
            _config_mutation(store, publisher, restore=mutation == "config-aba")
        elif mutation == "source-required":
            store.set_sync_payload("policy_bundle", {"invalid": True}, _STAMP)
            assert store.get_sync_payload("policy_bundle") == {"invalid": True}
        elif mutation == "request":
            publisher.request_publish()
        elif mutation == "close":
            publisher.close()
        else:
            raise AssertionError(mutation)

    def capture_context(*, publish_epoch=None):
        context = capture(publish_epoch=publish_epoch)
        assert context is not None
        inputs = context[5]
        assert isinstance(inputs, CapturedV3PublicationInputs)
        assert inputs.defaults is None and inputs.source_identity is None
        state.captures.append(inputs)
        return context

    def reserve_snapshot(**kwargs):
        snapshot = reserve(**kwargs)
        assert state.captures
        state.reserved_inputs.append(state.captures[-1])
        return snapshot

    def request(**kwargs):
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher._snapshot is None
        state.transport_deadlines.append(kwargs["deadline_monotonic"])
        output = client(**kwargs)
        if mutation == "bad-ack":
            reply = json.loads(output)
            reply["policy_digest"] = "0" * 64
            return json.dumps(reply).encode()
        if mutation == "deadline":
            time.sleep(max(0.0, kwargs["deadline_monotonic"] - time.monotonic()) + 0.005)
            assert time.monotonic() >= kwargs["deadline_monotonic"]
        return output

    def compile_current(*args, **kwargs):
        config, inputs = compile_policy(*args, **kwargs)
        state.validations.append(inputs)
        if len(state.validations) == 1:
            assert isinstance(inputs, CapturedV3PublicationInputs)
            assert inputs.input_digest == state.reserved_inputs[-1].input_digest
            assert publisher_module._policy_fingerprint(config) == (calls[-1]["config_digest"], calls[-1]["mode"])
        if phase == "during-post-ack-read":
            mutate()
        return config, inputs

    def confirm_current(*args, **kwargs):
        result = confirm(*args, **kwargs)
        assert result is not None
        state.confirmations.append(True)
        if phase == "after-resident-confirmation":
            mutate()
        return result

    def record_current_error(error):
        state.errors.append(error)
        record_error(error)

    def schedule_current(snapshot):
        schedule(snapshot)
        state.accepted_at.append(time.monotonic())

    monkeypatch.setattr(publisher, "_publication_context", capture_context)
    monkeypatch.setattr(transport_module, "native_policy_snapshot_v3", reserve_snapshot)
    monkeypatch.setattr(publisher, "_client_request", request)
    monkeypatch.setattr(publisher_module, "compiled_v3_compatible_policy", compile_current)
    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", confirm_current)
    monkeypatch.setattr(publisher, "_record_error", record_current_error)
    monkeypatch.setattr(publisher, "_schedule_renewal_locked", schedule_current)
    return state


@pytest.mark.parametrize(
    "phase",
    ["none", "during-post-ack-read", "after-resident-confirmation"],
    ids=["unchanged-control", "during-compile", "after-confirmation"],
)
def test_one_startup_commit_recovers_within_the_original_caller_deadline(publication, monkeypatch, phase):
    _, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase=phase, mutation="none" if phase == "none" else "summary-once")
    initial_epoch = publisher._epoch
    with _one_worker_with_caller_deadline(publisher) as (ready, deadline):
        assert state.mutations == int(phase != "none")
        assert len(state.writes) == state.mutations
        assert all(before != after for before, after in state.writes)
        assert publisher._epoch == initial_epoch
        assert ready, publisher.last_error
        assert 1 <= len(calls) <= 2
        assert len(state.reserved_inputs) == len(calls)
        if phase != "none":
            assert len(calls) == 2
            assert state.reserved_inputs[-1] is not state.reserved_inputs[0]
        assert len(state.validations) >= len(calls)
        assert len(state.confirmations) >= (2 if phase == "after-resident-confirmation" else 1)
        assert publisher.current_snapshot() == calls[-1]
        assert publisher._published_cloud_inputs is state.reserved_inputs[-1]
        assert len(state.accepted_at) == 1 and state.accepted_at[0] <= deadline
        assert state.errors == []
        assert publisher.last_error is None
        assert publisher._failure_count == 0
        assert publisher._retry_not_before_monotonic is None


@pytest.mark.parametrize(
    "phase,mutation",
    [
        ("during-post-ack-read", "summary-repeated"),
        ("after-resident-confirmation", "summary-repeated"),
        ("during-post-ack-read", "credential-change"),
        ("during-post-ack-read", "credential-aba"),
        ("during-post-ack-read", "config-change"),
        ("after-resident-confirmation", "config-aba"),
        ("during-post-ack-read", "source-required"),
        ("during-post-ack-read", "request"),
        ("after-resident-confirmation", "close"),
        ("during-post-ack-read", "bad-ack"),
        ("during-post-ack-read", "deadline"),
    ],
    ids=[
        "repeated-during-compile",
        "repeated-after-confirmation",
        "credential-change",
        "credential-aba",
        "config-change",
        "config-aba",
        "required-source",
        "request",
        "close",
        "ack-mismatch",
        "transport-deadline",
    ],
)
def test_post_ack_recovery_retains_authority_and_budget_refusals(publication, monkeypatch, phase, mutation):
    _, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase=phase, mutation=mutation)
    initial_epoch = publisher._epoch
    publisher._publish_once()
    assert not publisher.is_ready()
    assert publisher.current_snapshot_binding() is None
    assert publisher._snapshot is None
    assert state.accepted_at == []
    assert 1 <= len(calls) <= 2
    assert len(state.reserved_inputs) == len(calls)
    assert publisher._epoch == initial_epoch + int(mutation == "request")
    assert publisher.closed is (mutation == "close")
    if mutation in {"request", "close"}:
        assert state.mutations == 1
        assert state.errors == []
        assert publisher.last_error is None
        assert publisher._failure_count == 0
        assert publisher._retry_not_before_monotonic is None
    else:
        assert len(state.errors) == 1
        assert publisher._failure_count == 1
        assert publisher._retry_not_before_monotonic is not None
        if mutation == "bad-ack":
            assert len(calls) == 1 and state.mutations == 0
            assert state.validations == [] and state.confirmations == []
            assert publisher.last_error == "native_policy_snapshot_ack_mismatch"
        elif mutation == "deadline":
            assert len(calls) == 1 and state.mutations <= 1
            assert time.monotonic() >= state.transport_deadlines[0]
            assert publisher.last_error in {
                "native_policy_authority_changed_during_publish",
                "native_policy_snapshot_deadline_exceeded",
            }
        else:
            assert state.mutations >= 1
            if mutation != "summary-repeated":
                assert len(calls) == 1 and state.mutations == 1
            assert publisher.last_error == "native_policy_authority_changed_during_publish"
