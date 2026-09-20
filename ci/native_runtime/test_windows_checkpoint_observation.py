"""Finite forwarding, ownership, privacy and restoration controls for the observer."""

from __future__ import annotations

import errno
import json
import queue
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from ci.native_runtime.windows_checkpoint_observation import CheckpointObservation


class Writer:
    def __init__(self, path: object, thread: threading.Thread) -> None:
        self._journal_path = path
        self._thread = thread


@pytest.fixture
def rig():
    commands = queue.Queue()
    answers = queue.Queue()
    calls = []
    bind_calls = []
    state = SimpleNamespace(callback=lambda *args, **kwargs: state.result, result=object())

    def checkpoint(*args, **kwargs):
        calls.append((args, kwargs))
        return state.callback(*args, **kwargs)

    def unused(*args, **kwargs):
        del args, kwargs

    @contextmanager
    def lock(_path):
        yield

    journal = SimpleNamespace(
        checkpoint_journal=checkpoint,
        _read_journal_records_locked=unused,
        _open_journal=unused,
        _write_all=unused,
        _rewrite_preview_sidecar=unused,
        _read_preview_sidecar=unused,
        _apply_private_file_mode=unused,
        _journal_lock=lock,
    )
    module = SimpleNamespace(checkpoint_journal=checkpoint, RuntimeHookEvidenceWriter=Writer)

    def original_bind(daemon):
        bind_calls.append(daemon)
        return state.result

    probe = SimpleNamespace(bind_corpus=original_bind)

    def worker():
        while True:
            command = commands.get()
            if command is None:
                return
            args, kwargs = command
            try:
                answers.put(("result", module.checkpoint_journal(*args, **kwargs)))
            except BaseException as error:
                answers.put(("error", error))

    thread = threading.Thread(target=worker)
    thread.start()
    path = object()
    writer = Writer(path, thread)
    daemon = SimpleNamespace(_server=SimpleNamespace(runtime_hook_evidence_writer=writer))

    def invoke(*args, **kwargs):
        commands.put((args, kwargs))
        return answers.get(timeout=3)

    value = SimpleNamespace(
        module=module,
        journal=journal,
        probe=probe,
        state=state,
        path=path,
        writer=writer,
        daemon=daemon,
        thread=thread,
        invoke=invoke,
        calls=calls,
        bind_calls=bind_calls,
        original_bind=original_bind,
        original_checkpoint=checkpoint,
    )
    try:
        yield value
    finally:
        commands.put(None)
        thread.join(timeout=3)
        assert not thread.is_alive()


def observe(rig):
    return CheckpointObservation(rig.probe, rig.module, rig.journal)


def test_exact_forwarding_success_and_restoration(rig):
    removed = frozenset({"not exported"})
    with observe(rig) as observation:
        assert rig.probe.bind_corpus(rig.daemon) is rig.state.result
        kind, result = rig.invoke(rig.path, remove_record_ids=removed, max_bytes=123)
        assert kind == "result" and result is rig.state.result
        assert rig.calls == [((rig.path,), {"remove_record_ids": removed, "max_bytes": 123})]
    assert rig.probe.bind_corpus is rig.original_bind
    assert rig.module.checkpoint_journal is rig.original_checkpoint
    report = observation.report()
    assert report["original_checkpoint_calls"] == report["original_checkpoint_successes"] == 1
    assert report["original_checkpoint_failures"] == 0
    assert report["exact_seams_restored"] is True
    assert report["records"] == [] and report["missing_is_zero"] is False


@pytest.mark.parametrize("winerror", [5, 32, 33])
def test_original_exception_identity_and_closed_metadata(rig, winerror):
    error = PermissionError(errno.EACCES, "private-message", "/private/filename")
    error.winerror = winerror

    def fail(*args, **kwargs):
        raise error

    rig.state.callback = fail
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        kind, caught = rig.invoke(rig.path, remove_record_ids={"private-id"}, max_bytes=123)
        assert kind == "error" and caught is error
    report = observation.report()
    assert len(rig.calls) == report["original_checkpoint_failures"] == 1
    record = report["records"][0]
    assert record["category"] == "PermissionError"
    assert record["errno"] == errno.EACCES and record["winerror"] == winerror
    assert record["shipped_frames"]
    assert record["implicit_context_inspected"] is False
    assert not any(secret in json.dumps(report) for secret in ("private-message", "/private/filename", "private-id"))


def test_unbound_other_path_and_other_thread_are_not_attributed(rig):
    with observe(rig) as observation:
        rig.invoke(rig.path)
        rig.probe.bind_corpus(rig.daemon)
        rig.invoke(object())
        assert rig.module.checkpoint_journal(rig.path) is rig.state.result
    assert len(rig.calls) == 3
    assert observation.report()["original_checkpoint_calls"] == 0


@pytest.mark.parametrize("field", ["_thread", "_journal_path"])
def test_changed_generation_refuses_attribution_but_preserves_call(rig, field):
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        setattr(rig.writer, field, object())
        kind, result = rig.invoke(rig.path)
        assert kind == "result" and result is rig.state.result
    assert len(rig.calls) == 1
    report = observation.report()
    assert report["observer_invalid"] is True and report["original_checkpoint_calls"] == 0


def test_duplicate_binding_revokes_generation(rig):
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        rig.probe.bind_corpus(rig.daemon)
        rig.invoke(rig.path)
    assert len(rig.bind_calls) == 2 and len(rig.calls) == 1
    assert observation.report()["observer_invalid"] is True


def test_observer_failure_never_replaces_original_exception(rig):
    error = PermissionError(errno.EACCES, "private")

    def fail(*args, **kwargs):
        raise error

    def broken_record(_error):
        raise RuntimeError("observer failure")

    rig.state.callback = fail
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        observation._record = broken_record
        kind, caught = rig.invoke(rig.path)
        assert kind == "error" and caught is error
    assert observation.report()["additional_observation_lost"] is True
    assert rig.module.checkpoint_journal is rig.original_checkpoint


def test_custom_exception_subclass_attributes_are_not_read(rig):
    class Hostile(PermissionError):
        def __getattribute__(self, name):
            raise AssertionError("must not inspect custom exception")

    error = Hostile()

    def fail(*args, **kwargs):
        raise error

    rig.state.callback = fail
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        assert rig.invoke(rig.path)[1] is error
    assert observation.report()["records"] == [{"category": "unclassified", "metadata_available": False}]


def test_record_bound_explicitly_marks_loss(rig):
    error = PermissionError(errno.EACCES, "private")

    def fail(*args, **kwargs):
        raise error

    rig.state.callback = fail
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        for _ in range(17):
            assert rig.invoke(rig.path)[1] is error
    report = observation.report()
    assert report["original_checkpoint_failures"] == 17
    assert len(report["records"]) == 16 and report["additional_observation_lost"] is True


def test_original_probe_failure_restores_both_seams(rig):
    error = RuntimeError("original probe failure")
    observation = observe(rig)
    with pytest.raises(RuntimeError) as caught:
        with observation:
            rig.probe.bind_corpus(rig.daemon)
            raise error
    assert caught.value is error
    assert rig.probe.bind_corpus is rig.original_bind
    assert rig.module.checkpoint_journal is rig.original_checkpoint
    assert observation.report()["exact_seams_restored"] is True


def test_observer_cannot_be_reentered_or_nested(rig):
    observation = observe(rig)
    with observation:
        with pytest.raises(RuntimeError, match="checkpoint_original_alias_mismatch"):
            observe(rig)
    with pytest.raises(RuntimeError, match="checkpoint_observer_generation_invalid"):
        observation.__enter__()


def test_bind_failure_preserves_original_exception_and_call_count(rig):
    error = RuntimeError("bind failure")

    def failed_bind(daemon):
        rig.bind_calls.append(daemon)
        raise error

    rig.probe.bind_corpus = failed_bind
    observation = observe(rig)
    with observation:
        with pytest.raises(RuntimeError) as caught:
            rig.probe.bind_corpus(rig.daemon)
        assert caught.value is error
    assert rig.bind_calls == [rig.daemon]
    assert observation.report()["observer_bound"] is False
    assert rig.probe.bind_corpus is failed_bind


def test_partial_enter_failure_restores_checkpoint_alias(rig):
    class Probe:
        def __init__(self, original):
            object.__setattr__(self, "bind_corpus", original)
            object.__setattr__(self, "refuse_once", True)

        def __setattr__(self, name, value):
            if name == "bind_corpus" and self.refuse_once:
                object.__setattr__(self, "refuse_once", False)
                raise RuntimeError("injected seam installation failure")
            object.__setattr__(self, name, value)

    probe = Probe(rig.original_bind)
    observation = CheckpointObservation(probe, rig.module, rig.journal)
    with pytest.raises(RuntimeError, match="injected seam installation failure"):
        observation.__enter__()
    assert probe.bind_corpus is rig.original_bind
    assert rig.module.checkpoint_journal is rig.original_checkpoint
    assert observation.report()["exact_seams_restored"] is True


def test_changed_external_seam_is_not_overwritten_or_claimed_restored(rig):
    def replacement(*args, **kwargs):
        return object()

    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        rig.probe.bind_corpus = replacement
        assert rig.invoke(rig.path)[0] == "result"
    report = observation.report()
    assert report["observer_invalid"] is True
    assert report["exact_seams_restored"] is False
    assert rig.probe.bind_corpus is replacement
    assert rig.module.checkpoint_journal is rig.original_checkpoint


@pytest.mark.parametrize("value", [-1, 2**32, True, "private-code"])
def test_invalid_numeric_fields_are_unavailable(rig, value):
    error = PermissionError(errno.EACCES, "private")
    error.errno = value
    error.winerror = value

    def fail(*args, **kwargs):
        raise error

    rig.state.callback = fail
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        assert rig.invoke(rig.path)[1] is error
    record = observation.report()["records"][0]
    assert record["errno"] is None and record["winerror"] is None


def test_retired_thread_is_observed_without_an_added_join(rig):
    with observe(rig) as observation:
        rig.probe.bind_corpus(rig.daemon)
        rig.invoke(rig.path)
    assert observation.report()["owned_writer_thread_retired"] is False
