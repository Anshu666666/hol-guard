"""Actual persistence controls plus bounded observer failure/privacy contracts."""

from __future__ import annotations

import json
import sqlite3
import sys
from itertools import pairwise
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import codex_plugin_scanner
from ci.native_runtime.sqlite_failure_binding import verified_registry
from ci.native_runtime.sqlite_failure_capture import SQLiteFailureCapture
from codex_plugin_scanner.guard import store_review_event_outbox_schema as outbox

from . import test_guard_evidence_failure_diagnostics as existing


def _bound() -> SQLiteFailureCapture:
    writer, scopes, sites, proof = verified_registry(Path(str(codex_plugin_scanner.__file__)).parent)
    assert len(proof) == 6
    return SQLiteFailureCapture(writer, scopes=scopes, sites=sites)


def test_existing_real_receipt_lock_drain_with_original_timeout_and_database_assertions(tmp_path, monkeypatch):
    with _bound() as capture:
        existing.test_actual_sqlite_busy_retains_failure_after_idempotent_drain(tmp_path, monkeypatch)
    report = capture.report()
    assert report["observation_complete"]
    assert report["events"]
    for event in report["events"]:
        assert event["phase"] == "receipt_persistence"
        assert event["chain"][0]["operation"] == "receipt_insert"
        assert event["chain"][0]["sqlite_primary_code"] == (5 if sys.version_info >= (3, 11) else None)
        assert not event["chain"][0]["post_commit_path_proven"]
    assert not report["failed_record_units_reconciled"]


@pytest.mark.parametrize("failure", ["after_commit", "single_ack", "batch_ack"])
def test_existing_postcommit_ack_retry_contract_is_unchanged(tmp_path, monkeypatch, failure):
    with _bound() as capture:
        existing.test_committed_receipt_retry_keeps_failure_and_never_counts_a_second_processed_receipt(
            tmp_path, monkeypatch, failure
        )
    report = capture.report()
    assert report["callbacks_restored"]
    if failure == "after_commit":
        assert len(report["events"]) == 1
        assert report["events"][0]["chain"][0]["operation"] == "unknown"
        assert not report["observation_complete"]
    else:
        # The original explicit unacknowledged code bypasses its classifier.
        assert report["events"] == []
        assert not report["failed_record_units_reconciled"]


def _call(writer: Any, function: Any) -> tuple[object, BaseException | None]:
    try:
        return function(), None
    except BaseException as error:
        return writer.evidence_failure_code(error), error


def _fixture(classifier=lambda error: "unchanged"):
    writer: Any = ModuleType("synthetic_writer")
    writer.evidence_failure_code = classifier
    scopes = {_call.__code__: {_call.__code__.co_firstlineno + 2: "receipt_persistence"}}
    return writer, scopes


def _raised(error):
    raise error


def test_original_classifier_return_and_exception_identity_and_call_count():
    calls = []
    result = object()
    writer, scopes = _fixture(lambda error: calls.append(error) or result)
    error = sqlite3.OperationalError("private SQL path payload")
    error.sqlite_errorcode = 5 | (27 << 8)
    sites = {_raised.__code__: {_raised.__code__.co_firstlineno + 1: "synthetic_failure"}}
    with SQLiteFailureCapture(writer, scopes=scopes, sites=sites) as capture:
        returned, caught = _call(writer, lambda: _raised(error))
    assert returned is result and caught is error and calls == [error]
    row = capture.report()["events"][0]["chain"][0]
    assert row["sqlite_errorcode"] == 6917 and row["sqlite_primary_code"] == 5
    assert "private" not in json.dumps(capture.report())


def test_classifier_failure_is_not_replaced_or_observed():
    primary = RuntimeError("original classifier exception")

    def classify(error):
        raise primary

    writer, scopes = _fixture(classify)
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture, pytest.raises(RuntimeError) as caught:
        _call(writer, lambda: _raised(ValueError()))
    assert caught.value is primary
    assert capture.report()["events"] == []
    assert capture.report()["classifier_failed"]
    assert not capture.report()["observation_complete"]


def test_recording_failure_preserves_original_return(monkeypatch):
    writer, scopes = _fixture()
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        monkeypatch.setattr(capture, "_observe", lambda error: _raised(KeyboardInterrupt()))
        assert _call(writer, lambda: _raised(ValueError()))[0] == "unchanged"
    assert capture.report()["recording_failed"]
    assert not capture.report()["observation_complete"]


@pytest.mark.parametrize("code", [None, -1, 2**32, True, "private code"])
def test_unavailable_or_invalid_codes_are_not_synthesized(code):
    writer, scopes = _fixture()
    error = sqlite3.OperationalError("private SQL")
    if code is not None:
        error.sqlite_errorcode = code
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        _call(writer, lambda: _raised(error))
    row = capture.report()["events"][0]["chain"][0]
    assert row["sqlite_errorcode"] is row["sqlite_primary_code"] is None
    assert row["operation"] == "unknown"
    assert not capture.report()["observation_complete"]


def test_overflow_nonblocking_lock_and_detached_report():
    writer, scopes = _fixture()
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        for _ in range(129):
            _call(writer, lambda: _raised(ValueError()))
        with capture._lock:
            assert _call(writer, lambda: _raised(ValueError()))[0] == "unchanged"
    report = capture.report()
    assert len(report["events"]) == 128
    assert report["overflow"] and report["lost"]
    report["events"].clear()
    assert len(capture.report()["events"]) == 128


def test_secondary_cleanup_error_remains_distinct_from_original_context():
    original = sqlite3.OperationalError("private original")
    original.sqlite_errorcode = 5
    secondary = PermissionError(13, "private cleanup path")

    def cleanup():
        try:
            _raised(original)
        finally:
            _raised(secondary)

    writer, scopes = _fixture()
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        _, caught = _call(writer, cleanup)
    assert caught is secondary
    chain = capture.report()["events"][0]["chain"]
    assert [(row["relation"], row["kind"], row["sqlite_errorcode"]) for row in chain] == [
        ("terminal", "PermissionError", None),
        ("context", "OperationalError", 5),
    ]
    assert not capture.report()["observation_complete"]
    assert "private" not in json.dumps(capture.report())


def test_real_commit_succeeded_before_actual_postcommit_read_failure(tmp_path):
    class DenyReadAfterCommit(sqlite3.Connection):
        def commit(self):
            super().commit()
            self.set_authorizer(lambda *args: sqlite3.SQLITE_DENY)

    path = tmp_path / "database.db"
    connection = sqlite3.connect(path, factory=DenyReadAfterCommit)
    connection.execute("create table sample(value integer)")
    connection.execute("insert into sample values(1)")
    writer, scopes = _fixture()
    _, _, sites, _ = verified_registry(Path(str(codex_plugin_scanner.__file__)).parent)
    with SQLiteFailureCapture(writer, scopes=scopes, sites=sites) as capture:
        _, error = _call(writer, lambda: outbox.commit_review_event_transaction(connection, 0, lambda elapsed: None))
    connection.close()
    assert type(error) is sqlite3.DatabaseError
    row = capture.report()["events"][0]["chain"][0]
    assert row["operation"] == "wake_schema_read"
    assert row["post_commit_path_proven"]
    assert capture.report()["observation_complete"]
    with sqlite3.connect(path) as check:
        assert check.execute("select value from sample").fetchall() == [(1,)]
    check.close()


def test_real_commit_error_is_distinct_from_postcommit_read(tmp_path):
    path = tmp_path / "database.db"
    connection = sqlite3.connect(path)
    connection.execute("create table sample(value integer)")
    connection.execute("insert into sample values(1)")
    connection.set_authorizer(lambda *args: sqlite3.SQLITE_DENY)
    writer, scopes = _fixture()
    _, _, sites, _ = verified_registry(Path(str(codex_plugin_scanner.__file__)).parent)
    try:
        with SQLiteFailureCapture(writer, scopes=scopes, sites=sites) as capture:
            _, error = _call(
                writer, lambda: outbox.commit_review_event_transaction(connection, 0, lambda elapsed: None)
            )
    finally:
        connection.set_authorizer(None)
        connection.rollback()
        connection.close()
    assert type(error) is sqlite3.DatabaseError
    row = capture.report()["events"][0]["chain"][0]
    assert row["operation"] == "transaction_commit"
    assert not row["post_commit_path_proven"]
    with sqlite3.connect(path) as check:
        assert check.execute("select value from sample").fetchall() == []
    check.close()


def test_trace_and_chain_bounds_remain_explicit():
    def recurse(depth):
        if depth:
            return recurse(depth - 1)
        raise ValueError("private deep payload")

    writer, scopes = _fixture()
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        _call(writer, lambda: recurse(40))
        errors = [ValueError() for _ in range(6)]
        for first, second in pairwise(errors):
            first.__cause__ = second
        _call(writer, lambda: _raised(errors[0]))
    events = capture.report()["events"]
    assert not events[0]["chain"][0]["trace_complete"]
    assert len(events[1]["chain"]) == 4 and events[1]["chain_truncated"]
    assert not capture.report()["observation_complete"]


def test_hostile_exception_attributes_and_metaclass_are_never_called():
    class HostileMeta(type):
        def __eq__(cls, other):
            raise AssertionError("private metaclass equality")

    class HostileError(Exception, metaclass=HostileMeta):
        def __getattribute__(self, name):
            raise AssertionError("private attribute hook")

        def __str__(self):
            raise AssertionError("private message")

    original = HostileError()
    writer, scopes = _fixture()
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        _, error = _call(writer, lambda: _raised(original))
    assert error is original
    assert not capture.report()["recording_failed"]
    assert capture.report()["events"][0]["chain"][0]["kind"] == "unsupported_exception"


def test_restore_failure_does_not_replace_original_exception():
    original = ValueError("private original")
    secondary = OSError("private restore")

    class RefusesRestore:
        def __setattr__(self, name, value):
            raise secondary

    writer, scopes = _fixture()
    capture = SQLiteFailureCapture(writer, scopes=scopes, sites={})
    try:
        with pytest.raises(ValueError) as caught, capture:
            capture._writer = RefusesRestore()
            raise original
    finally:
        writer.evidence_failure_code = capture._original
    assert caught.value is original
    assert capture.report()["restoration_failed"]
    assert not capture.report()["callbacks_restored"]


def test_unrelated_failure_and_nested_entry_do_not_change_alias():
    writer, scopes = _fixture()
    original = writer.evidence_failure_code
    with SQLiteFailureCapture(writer, scopes=scopes, sites={}) as capture:
        assert writer.evidence_failure_code(ValueError()) == "unchanged"
        with pytest.raises(RuntimeError, match="alias_not_original"):
            capture.__enter__()
    assert writer.evidence_failure_code is original
    assert capture.report()["events"] == []


@pytest.mark.parametrize("change", ["origin", "bytes", "code"])
def test_source_binding_rejects_wrong_origin_changed_bytes_or_rebound_function(tmp_path, monkeypatch, change):
    from codex_plugin_scanner.guard import store_native_decision_receipts as receipts

    root = Path(str(codex_plugin_scanner.__file__)).parent
    if change == "origin":
        root = tmp_path
    elif change == "bytes":
        original = Path.read_bytes
        monkeypatch.setattr(
            Path,
            "read_bytes",
            lambda path: b"changed" if path.name == "store_native_decision_receipts.py" else original(path),
        )
    else:
        monkeypatch.setattr(receipts, "_record_native_decision_receipts", lambda *args: ())
    with pytest.raises(RuntimeError, match=r"sqlite_observer_(origin|source|code)_mismatch"):
        verified_registry(root)
