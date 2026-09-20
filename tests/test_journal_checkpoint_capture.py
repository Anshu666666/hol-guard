"""Forwarding, privacy and finite-loss controls for the journal observer."""

from __future__ import annotations

import errno
import json
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, NoReturn

import pytest

from ci.native_runtime.journal_checkpoint_binding import operation_registry, source_binding
from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture


def _raise(error: BaseException) -> NoReturn:
    raise error


def _checkpoint(writer: ModuleType, error: OSError) -> tuple[OSError, object]:
    try:
        _raise(error)
    except OSError as original:
        return original, writer.evidence_failure_code(original)


def _masked(writer: ModuleType, first: OSError, last: OSError) -> tuple[OSError, object]:
    try:
        try:
            _raise(first)
        finally:
            _raise(last)
    except OSError as original:
        return original, writer.evidence_failure_code(original)


def _fixture(checkpoint: Any = _checkpoint) -> tuple[JournalCheckpointCapture, Any, Any, list[Any]]:
    writer: Any = ModuleType("writer_fixture")
    probe: Any = ModuleType("probe_fixture")
    calls: list[Any] = []
    marker = object()

    def classify(error: BaseException) -> object:
        calls.append(error)
        return marker

    def end(*args: Any, **kwargs: Any) -> object:
        calls.append((args, kwargs))
        return marker

    writer.evidence_failure_code = classify
    probe.end_corpus = end
    capture = JournalCheckpointCapture(
        writer,
        probe,
        checkpoint_code=checkpoint.__code__,
        sites={_raise.__code__: {_raise.__code__.co_firstlineno + 1: "fixed_os_operation"}},
    )
    return capture, writer, probe, calls


def _end(probe: ModuleType, count: int = 1) -> None:
    probe.end_corpus(None, None, {"failure_diagnostics": {"journal_checkpoint/os_permission": count}})


def test_original_error_result_and_snapshot_objects_are_forwarded_once() -> None:
    capture, writer, probe, calls = _fixture()
    classify, end = writer.evidence_failure_code, probe.end_corpus
    error = PermissionError(errno.EACCES, "private-message", "/private/path")
    with capture:
        original, result = _checkpoint(writer, error)
        assert original is error and result is not None and calls == [error]
        args = (object(), object(), {"failure_diagnostics": {"journal_checkpoint/os_permission": 1}})
        assert probe.end_corpus(*args) is result
        assert calls[1][0] == args
        assert all(a is b for a, b in zip(calls[1][0], args, strict=True))
    report = capture.report()
    assert writer.evidence_failure_code is classify and probe.end_corpus is end
    assert report["observation_complete"] and report["end_return_event_count"] == 1
    encoded = json.dumps(report)
    assert "private-message" not in encoded and "/private/path" not in encoded


def test_cleanup_error_keeps_terminal_and_original_context() -> None:
    capture, writer, probe, calls = _fixture(_masked)
    first, last = PermissionError(13, "first-private"), PermissionError(1, "last-private")
    with capture:
        original, _ = _masked(writer, first, last)
        assert original is last and last.__context__ is first and calls == [last]
        _end(probe)
    event = capture.report()["events"][0]
    assert [row["relation"] for row in event["chain"]] == ["terminal", "context"]
    assert [row["errno"] for row in event["chain"]] == [1, 13]
    assert event["complete"]


def test_original_classifier_exception_identity_survives() -> None:
    capture, writer, probe, calls = _fixture()
    original = RuntimeError("original classifier failure")

    def refused(error: BaseException) -> None:
        calls.append(error)
        raise original

    writer.evidence_failure_code = refused
    capture = JournalCheckpointCapture(writer, probe, checkpoint_code=_checkpoint.__code__, sites={})
    with pytest.raises(RuntimeError) as caught, capture:
        _checkpoint(writer, PermissionError(13, "secret"))
    assert caught.value is original and len(calls) == 1
    assert writer.evidence_failure_code is refused


def test_original_end_exception_identity_and_restoration() -> None:
    capture, writer, probe, _ = _fixture()
    original = RuntimeError("original end failure")

    def refused(*args: Any, **kwargs: Any) -> None:
        raise original

    probe.end_corpus = refused
    capture = JournalCheckpointCapture(writer, probe, checkpoint_code=_checkpoint.__code__, sites={})
    with pytest.raises(RuntimeError) as caught, capture:
        probe.end_corpus(None, None, None)
    assert caught.value is original and probe.end_corpus is refused
    assert not capture.report()["observation_complete"]


@pytest.mark.parametrize("failure", ["lock_busy", "collector_raises", "missing_origin", "counter_missing"])
def test_diagnostic_loss_never_changes_original_outcome(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    capture, writer, probe, calls = _fixture()
    error = PermissionError(13, "private")
    if failure == "collector_raises":
        monkeypatch.setattr(capture, "_observe", lambda error: _raise(RuntimeError("diagnostic")))
    if failure == "missing_origin":
        capture._sites = {}
    with capture:
        if failure == "lock_busy":
            capture._lock.acquire()
        try:
            original, result = _checkpoint(writer, error)
            assert original is error and result is not None and calls == [error]
        finally:
            if failure == "lock_busy":
                capture._lock.release()
        if failure == "counter_missing":
            probe.end_corpus(None, None, {})
        else:
            _end(probe)
    assert not capture.report()["observation_complete"]


def test_event_overflow_is_explicit_without_extra_classifier_calls() -> None:
    capture, writer, probe, calls = _fixture()
    with capture:
        for _ in range(17):
            _checkpoint(writer, PermissionError(13, "hidden"))
        _end(probe, 17)
    report = capture.report()
    assert len(calls) == 18 and len(report["events"]) == 16
    assert report["overflow"] and not report["observation_complete"]


def test_after_snapshot_failures_do_not_join_earlier_count() -> None:
    capture, writer, probe, _ = _fixture()
    with capture:
        _checkpoint(writer, PermissionError(13, "before"))
        _end(probe)
        _checkpoint(writer, PermissionError(13, "after"))
    report = capture.report()
    assert report["end_return_event_count"] == report["events_through_end_return_with_permission_errno"] == 1
    assert len(report["events"]) == 2 and report["observation_complete"]


def test_unsupported_exception_does_not_call_custom_hooks() -> None:
    class ForbiddenMeta(type):
        def __hash__(cls) -> int:
            raise AssertionError("metaclass hook must not run")

    class PrivateError(PermissionError, metaclass=ForbiddenMeta):
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError("attribute hook must not run")

        def __str__(self) -> str:
            raise AssertionError("string hook must not run")

    capture, writer, probe, calls = _fixture()
    error = PrivateError(13, "private")
    with capture:
        original, _ = _checkpoint(writer, error)
        assert original is error and calls[0] is error
        _end(probe)
    assert not capture.report()["observation_complete"]


@pytest.mark.parametrize("shape", ["cycle", "long_chain", "long_trace"])
def test_finite_chain_and_trace_limits(shape: str) -> None:
    capture, writer, probe, _ = _fixture()
    error = PermissionError(13, "private")
    if shape == "cycle":
        error.__context__ = error
    elif shape == "long_chain":
        current = error
        for _ in range(8):
            current.__context__ = PermissionError(13, "private")
            current = current.__context__
    else:

        def recurse(left: int) -> None:
            if left:
                recurse(left - 1)
            else:
                raise error

        try:
            recurse(40)
        except PermissionError as caught:
            assert caught is error
    with capture:
        _checkpoint(writer, error)
        _end(probe)
    report = capture.report()
    assert not report["observation_complete"]
    assert len(report["events"][0]["chain"]) <= 4


def test_no_failure_remains_non_reproduction_with_complete_empty_snapshot() -> None:
    capture, _writer, probe, _ = _fixture()
    with capture:
        probe.end_corpus(None, None, {"failure_diagnostics": {}})
    report = capture.report()
    assert report["observation_complete"] and not report["failure_reproduced"]


@pytest.mark.parametrize("masked", [False, True])
def test_actual_checkpoint_reports_replace_and_cleanup_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, masked: bool
) -> None:
    import codex_plugin_scanner
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer_module

    root = Path(__file__).resolve().parents[1]
    assert len(source_binding(Path(codex_plugin_scanner.__file__).parent, root)) == 8
    writer = object.__new__(writer_module.RuntimeHookEvidenceWriter)
    writer._condition = threading.Condition()
    writer._checkpoint_pending = {"committed"}
    writer._journal_path = tmp_path / "private-journal"
    writer._max_bytes = 4096
    writer._failures = 0
    writer._degraded = False
    writer._failure_diagnostics = {}
    writer._receipt_failure_diagnostics = {}
    first, last = PermissionError(13, "private replace"), PermissionError(1, "private cleanup")
    operations: list[str] = []
    original_unlink = Path.unlink

    def replace(*args: Any) -> None:
        operations.append("replace")
        raise first

    def unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        if masked and path.name.endswith(".tmp"):
            operations.append("cleanup")
            raise last
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(journal, "os", SimpleNamespace(**{**vars(journal.os), "replace": replace}))
    monkeypatch.setattr(Path, "unlink", unlink)
    probe: Any = ModuleType("probe_fixture")
    probe.end_corpus = lambda *args: None
    with JournalCheckpointCapture(
        writer_module,
        probe,
        checkpoint_code=writer_module.RuntimeHookEvidenceWriter._checkpoint_completed_records.__code__,
        sites=operation_registry(journal),
    ) as capture:
        writer._checkpoint_completed_records()
        probe.end_corpus(None, None, {"failure_diagnostics": writer._failure_diagnostics})
    report = capture.report()
    assert writer._failures == 1 and writer._degraded and writer._checkpoint_pending == {"committed"}
    assert writer._receipt_failure_diagnostics == {}
    assert writer._failure_diagnostics == {"journal_checkpoint/os_permission": 1}
    assert operations == (["replace", "cleanup"] if masked else ["replace"])
    event = report["events"][0]
    assert event["chain"][0]["terminal_operation"] == (
        "checkpoint_journal_462_unlink" if masked else "checkpoint_journal_458_replace"
    )
    if masked:
        assert last.__context__ is first
        assert event["chain"][1]["terminal_operation"] == "checkpoint_journal_458_replace"
    assert report["observation_complete"]
    assert "private replace" not in json.dumps(report) and str(tmp_path) not in json.dumps(report)
    # Retire the deliberately retained fixture temporary using the original API.
    for path in tmp_path.glob("*.tmp"):
        original_unlink(path)
