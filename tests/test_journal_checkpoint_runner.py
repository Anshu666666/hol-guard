"""Original outcome and strict source/role binding controls for the driver."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime.journal_checkpoint_binding import GUARDS, SITES, source_binding
from ci.native_runtime.journal_checkpoint_run import observe_once
from tests.test_journal_checkpoint_capture import _checkpoint, _fixture


@pytest.mark.parametrize("original_fails", [False, True])
@pytest.mark.parametrize("export_fails", [False, True])
def test_one_call_and_primary_exception_survive_export(original_fails: bool, export_fails: bool) -> None:
    capture, writer, probe, _ = _fixture()
    primary, secondary = RuntimeError("original"), OSError("export")
    calls: list[str] = []
    original_classifier, original_end = writer.evidence_failure_code, probe.end_corpus

    def call() -> int:
        calls.append("call")
        if original_fails:
            raise primary
        return 7

    def export(report: dict[str, Any]) -> None:
        calls.append("export")
        assert report["callbacks_restored"]
        if export_fails:
            raise secondary

    if original_fails:
        with pytest.raises(RuntimeError) as caught:
            observe_once(call, capture, export)
        assert caught.value is primary
    else:
        assert observe_once(call, capture, export) == 7
    assert calls == ["call", "export"]
    assert writer.evidence_failure_code is original_classifier and probe.end_corpus is original_end


def test_original_return_survives_failed_export_and_failed_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime import journal_checkpoint_run as driver

    capture, _writer, _probe, _ = _fixture()

    def fail(*args: Any, **kwargs: Any) -> None:
        raise OSError("diagnostic-only failure")

    monkeypatch.setattr(driver, "print", fail, raising=False)
    assert observe_once(lambda: 7, capture, fail) == 7


def test_source_mutation_is_rejected_before_code_registry(tmp_path: Path) -> None:
    package = tmp_path / "package"
    name = next(iter(GUARDS)).removeprefix("src/codex_plugin_scanner/")
    target = package / name
    target.parent.mkdir(parents=True)
    target.write_text("wrong source\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="journal_diagnostic_source_binding_failed"):
        source_binding(package, tmp_path)


def test_shared_leaf_retains_actual_registered_caller_roles(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from ci.native_runtime.journal_checkpoint_binding import operation_registry
    from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal

    capture, writer, probe, _ = _fixture()
    capture = JournalCheckpointCapture(
        writer, probe, checkpoint_code=_checkpoint.__code__, sites=operation_registry(journal)
    )

    def denied(*args: Any, **kwargs: Any) -> None:
        raise PermissionError(13, "private", "/private")

    monkeypatch.setattr(journal, "_open_journal", denied)
    for function, kwargs, role in (
        (journal._read_journal_records_locked, {"max_bytes": 8}, "aggregate_read_open"),
        (journal._read_preview_sidecar, {}, "preview_read_open"),
    ):
        try:
            function(tmp_path / "private", **kwargs)
        except PermissionError as error:
            checkpoint, operations, complete = capture._trace(error)
            assert not checkpoint and complete and operations == [role]
        else:
            pytest.fail("original private operation did not fail")
    assert SITES["checkpoint_journal"][454] == "aggregate_temporary_write"
    assert SITES["_rewrite_preview_sidecar"][354] == "preview_temporary_write"


def test_event_during_original_end_is_not_claimed_as_snapshot_member() -> None:
    capture, writer, probe, _ = _fixture()

    def end(*args: Any) -> None:
        _checkpoint(writer, OSError(5, "late private event"))

    probe.end_corpus = end
    from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture

    capture = JournalCheckpointCapture(writer, probe, checkpoint_code=_checkpoint.__code__, sites=capture._sites)
    with capture:
        probe.end_corpus(None, None, {"failure_diagnostics": {}})
    report = capture.report()
    assert report["end_return_event_count"] == 1 and report["snapshot_permission_count_reconciled"]
    assert not report["individual_event_snapshot_membership_proven"]
    assert report["event_boundary"] == "after_original_end_corpus_return"
    assert "late private event" not in json.dumps(report)


def test_partial_callback_installation_restores_original() -> None:
    capture, writer, _probe, _ = _fixture()
    classifier = writer.evidence_failure_code
    failure = RuntimeError("fixture refusal")

    class Refusing(ModuleType):
        def __setattr__(self, name: str, value: Any) -> None:
            raise failure

    capture._probe = Refusing("refusing")
    with pytest.raises(RuntimeError) as caught:
        capture.__enter__()
    assert caught.value is failure and writer.evidence_failure_code is classifier


@pytest.mark.parametrize("operation", ["truncate", "acquire", "release"])
def test_original_lock_generator_distinguishes_fixed_sites(
    operation: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ci.native_runtime.journal_checkpoint_binding import operation_registry
    from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal

    # Real file lifecycle, with injected CRT calls only. This is not Win32 execution.
    error = PermissionError(13, "private injected error")
    calls: list[str] = []
    closed: list[int] = []
    original_close = journal.os.close
    original_open = journal.os.open
    opened: list[int] = []

    def open_file(*args: Any, **kwargs: Any) -> int:
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def truncate(descriptor: int, size: int) -> None:
        calls.append("truncate")
        if operation == "truncate":
            raise error

    def locking(descriptor: int, mode: int, size: int) -> None:
        label = "acquire" if mode == 1 else "release"
        calls.append(label)
        if operation == label:
            raise error

    def close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    fake: Any = ModuleType("msvcrt")
    fake.LK_LOCK, fake.LK_UNLCK, fake.locking = 1, 2, locking
    monkeypatch.setattr(journal, "msvcrt", fake)
    monkeypatch.setattr(journal, "fcntl", None)
    monkeypatch.setattr(
        journal,
        "os",
        SimpleNamespace(**{**vars(journal.os), "name": "nt", "ftruncate": truncate, "close": close, "open": open_file}),
    )
    capture, writer, probe, _ = _fixture()
    capture = JournalCheckpointCapture(
        writer, probe, checkpoint_code=_checkpoint.__code__, sites=operation_registry(journal)
    )
    try:
        with pytest.raises(PermissionError) as caught, journal._journal_lock(tmp_path / "journal"):
            calls.append("body")
    finally:
        for descriptor in opened:
            if descriptor not in closed:
                original_close(descriptor)
    assert caught.value is error
    assert (
        calls
        == {
            "truncate": ["truncate"],
            "acquire": ["truncate", "acquire"],
            "release": ["truncate", "acquire", "body", "release"],
        }[operation]
    )
    expected = {
        "truncate": "journal_lock_485_ftruncate",
        "acquire": "journal_lock_487_locking",
        "release": "journal_lock_497_locking",
    }[operation]
    assert capture._trace(error)[1] == [expected]
    # The original release finally does not close if unlock itself raises.
    assert len(closed) == (0 if operation == "release" else 1)
    if operation == "release":
        # The outer test finally retired this real descriptor; product behavior is unchanged.
        assert not closed


def test_actual_preview_deletion_retains_its_role(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from ci.native_runtime.journal_checkpoint_binding import operation_registry
    from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal

    capture, writer, probe, _ = _fixture()
    capture = JournalCheckpointCapture(
        writer, probe, checkpoint_code=_checkpoint.__code__, sites=operation_registry(journal)
    )
    error = PermissionError(13, "private preview")
    original_unlink = Path.unlink

    def unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        if path.name == "journal.preview":
            raise error
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(PermissionError) as caught:
        journal.checkpoint_journal(tmp_path / "journal", remove_record_ids=(), max_bytes=4096)
    assert caught.value is error
    assert capture._trace(error)[1][-1] == "rewrite_preview_sidecar_345_unlink"


@pytest.mark.parametrize("origin", ["nested_venv", "source", "outside_venv"])
def test_binding_admits_installed_nested_venv_but_rejects_source(
    origin: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ci.native_runtime import journal_checkpoint_run as driver

    root = tmp_path / "candidate"
    prefix = root / ".venv"
    package = {
        "nested_venv": prefix / "Lib/site-packages/codex_plugin_scanner",
        "source": root / "src/codex_plugin_scanner",
        "outside_venv": tmp_path / "other/codex_plugin_scanner",
    }[origin]
    package.mkdir(parents=True)
    admitted = RuntimeError("next_exact_source_guard")
    calls: list[tuple[str, ...]] = []

    def next_guard(*args: str) -> str:
        calls.append(args)
        raise admitted

    monkeypatch.setattr(driver, "ROOT", root)
    monkeypatch.setattr(driver, "sys", SimpleNamespace(prefix=str(prefix), version_info=(3, 12, 10)))
    monkeypatch.setattr(
        driver,
        "os",
        SimpleNamespace(name="nt", environ={"DIAGNOSTIC_SOURCE_SHA": "source", "DIAGNOSTIC_SOURCE_TREE": "tree"}),
    )
    monkeypatch.setattr(driver, "_git", next_guard)
    with pytest.raises(RuntimeError) as caught:
        driver.binding(package)
    if origin == "nested_venv":
        assert caught.value is admitted and calls == [("rev-parse", "HEAD")]
    else:
        assert str(caught.value) == "journal_diagnostic_installed_import_required" and not calls
