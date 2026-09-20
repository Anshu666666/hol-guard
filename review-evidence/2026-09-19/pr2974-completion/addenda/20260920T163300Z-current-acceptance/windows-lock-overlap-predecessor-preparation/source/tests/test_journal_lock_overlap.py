"""Source-only actual Windows serialization contract and bounded harness controls."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime import journal_lock_child as child
from ci.native_runtime import journal_lock_process as process
from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal


@pytest.mark.skipif(os.name != "nt", reason="actual Windows CRT byte-lock control")
@pytest.mark.parametrize("cell", ["uncontended", "held", "released", "nonblocking", "blocking"])
def test_actual_windows_journal_overlap(cell: str, tmp_path: Path, record_property: Any) -> None:
    report = process.run_cell(tmp_path / "evidence.jsonl", cell)
    record_property("journal_lock_report", json.dumps(report, sort_keys=True))
    assert report["controller_error"] is None
    assert "holder_cleanup_error" not in report
    assert len(report["cleanup"]) == (1 if cell == "uncontended" else 2)
    for cleanup in report["cleanup"]:
        assert cleanup["returncode"] == 0 and not cleanup["killed"]
        assert cleanup["reader_joined"] and cleanup["reader_error"] is None
    for body in (report["holder"], report["contender"]):
        if body is None:
            continue
        assert body["callbacks_restored"]
        assert body["opened_descriptors"] == 1
        assert body["original_descriptors_closed"] == [True]
        assert body["emergency_close_results"] == []
        assert body["calls"]["open"] == 1 and body["calls"]["close"] == 1
    if report["holder"] is not None:
        assert report["holder"]["entered"] and report["holder"]["error"] is None
        assert report["holder"]["calls"]["acquire"] == 1
        assert report["holder"]["calls"]["unlock"] == 1
    contender = report["contender"]
    if cell == "nonblocking":
        assert not contender["entered"]
        assert contender["error"]["kind"] in ("os_error", "permission")
        assert contender["calls"]["ftruncate"] == 0
        assert contender["calls"]["acquire"] == 1 and contender["calls"]["unlock"] == 0
        assert contender["failures"] == [{"operation": "acquire", **contender["error"]}]
        assert report["completed_before_release"] is True
    else:
        # A pre-lock failure remains a failed product serialization contract.
        assert contender["error"] is None
        assert contender["entered"]
        assert contender["calls"]["acquire"] == 1 and contender["calls"]["unlock"] == 1
        assert contender["calls"]["ftruncate"] == (0 if cell == "blocking" else 1)
        if cell in ("held", "blocking"):
            assert report["completed_before_release"] is False


@pytest.mark.parametrize("fails", [False, True])
def test_forward_calls_once_and_preserves_result_or_exception(fails: bool) -> None:
    source = ModuleType("os_fixture")
    marker, primary = object(), PermissionError(13, "private-secret", "/private/path")
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def original(*args: Any, **kwargs: Any) -> object:
        calls.append((args, kwargs))
        if fails:
            raise primary
        return marker

    source.__dict__["ftruncate"] = original
    events: list[dict[str, object]] = []
    proxy = child.Forward(source, events.append)
    if fails:
        with pytest.raises(PermissionError) as caught:
            proxy.ftruncate(42, 1, sentinel=marker)
        assert caught.value is primary
        assert "private" not in json.dumps(proxy.failures)
    else:
        assert proxy.ftruncate(42, 1, sentinel=marker) is marker
    assert calls == [((42, 1), {"sentinel": marker})]
    assert events == [{"event": "ftruncate_begin"}]
    assert proxy.calls["ftruncate"] == 1


def _windows_aliases(monkeypatch: pytest.MonkeyPatch, *, fail: str | None = None) -> tuple[Any, list[tuple[int, int]]]:
    calls: list[tuple[int, int]] = []

    def locking(descriptor: int, mode: int, length: int) -> None:
        assert os.fstat(descriptor).st_nlink == 1
        calls.append((mode, length))

    crt = SimpleNamespace(LK_LOCK=1, LK_NBLCK=2, LK_UNLCK=0, locking=locking)
    original_os = journal.os
    os_alias = SimpleNamespace(**{name: getattr(original_os, name) for name in dir(original_os)})
    if fail == "truncate":

        def denied(_descriptor: int, _length: int) -> None:
            raise PermissionError(13, "never export", "/private")

        os_alias.ftruncate = denied
    if fail == "metadata":
        real_fstat = original_os.fstat
        inspected: list[int] = []

        def metadata(descriptor: int) -> Any:
            if not inspected:
                inspected.append(descriptor)
                return SimpleNamespace(st_mode=0, st_nlink=1)
            return real_fstat(descriptor)

        os_alias.fstat = metadata
    monkeypatch.setattr(journal, "os", os_alias)
    monkeypatch.setattr(journal, "fcntl", None)
    monkeypatch.setattr(journal, "msvcrt", crt)
    monkeypatch.setattr(journal, "_apply_private_file_mode", lambda _descriptor: None)
    return os_alias, calls


@pytest.mark.parametrize("role", ["original", "blocking", "nonblocking"])
def test_real_descriptor_forwarding_and_cleanup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, role: str) -> None:
    original_os, calls = _windows_aliases(monkeypatch)
    events: list[dict[str, object]] = []
    report = child.observe(journal, tmp_path / "journal", role, events.append, lambda: "release\n")
    assert report["entered"] and report["error"] is None
    assert report["original_descriptors_closed"] == [True]
    assert report["emergency_close_results"] == [] and report["callbacks_restored"]
    assert journal.os is original_os
    assert calls == [(2 if role == "nonblocking" else 1, 1), (0, 1)]


@pytest.mark.parametrize("failure", ["truncate", "metadata"])
def test_original_failure_closes_fd_before_any_acquisition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    original_os, calls = _windows_aliases(monkeypatch, fail=failure)
    report = child.observe(journal, tmp_path / "journal", "original", lambda _event: None, lambda: "release\n")
    assert not report["entered"] and report["error"] is not None
    assert report["callbacks_restored"] and journal.os is original_os and calls == []
    assert report["original_descriptors_closed"] == [True]
    if failure == "truncate":
        assert report["failures"] == [{"operation": "ftruncate", "kind": "permission", "errno": 13, "winerror": None}]
    assert "private" not in json.dumps(report)


def test_invalid_holder_release_retains_error_and_unlocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _os, calls = _windows_aliases(monkeypatch)
    report = child.observe(journal, tmp_path / "journal", "holder", lambda _event: None, lambda: "wrong\n")
    assert report["error"] == {"kind": "runtime", "errno": None, "winerror": None}
    assert report["entered"] and report["original_descriptors_closed"] == [True]
    assert calls == [(1, 1), (0, 1)]


def _valid_report() -> dict[str, Any]:
    return {
        "role": "original",
        "entered": True,
        "error": None,
        "calls": dict.fromkeys(child.OPERATIONS, 0),
        "failures": [],
        "opened_descriptors": 0,
        "original_descriptors_closed": [],
        "emergency_close_results": [],
        "callbacks_restored": True,
        "source_sha256": child.JOURNAL_SHA256,
    }


@pytest.mark.parametrize("mutation", ["extra", "kind", "operation", "scalar", "overflow", "source"])
def test_report_rejects_unbounded_or_private_fields(mutation: str) -> None:
    value = _valid_report()
    if mutation == "extra":
        value["path"] = "/private"
    elif mutation == "kind":
        value["error"] = {"kind": "private", "errno": None, "winerror": None}
    elif mutation == "operation":
        value["failures"] = [{"operation": "/private", "kind": "os_error", "errno": 13, "winerror": 5}]
    elif mutation == "scalar":
        value["error"] = {"kind": "os_error", "errno": "/private", "winerror": None}
    elif mutation == "overflow":
        value["calls"]["open"] = 100
    else:
        value["source_sha256"] = "wrong"
    with pytest.raises(ValueError):
        process.validate_report(value)


def test_duplicate_json_keys_rejected_before_retention() -> None:
    with pytest.raises(ValueError, match="duplicate_child_key"):
        json.loads('{"event":"/private","event":"held"}', object_pairs_hook=process._pairs)


def test_malformed_real_child_is_reaped_without_private_retention() -> None:
    runner = process.Child([sys.executable, "-I", "-c", 'print(\'{"event":"private-path-and-secret"}\', flush=True)'])
    with pytest.raises(RuntimeError, match="child_protocol_ended"):
        runner.event()
    report = runner.retire()
    assert report["returncode"] == 0 and report["reader_joined"]
    assert report["reader_error"] is not None
    assert "private" not in json.dumps(report)


def test_unknown_cell_spawns_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def forbidden(*_args: Any) -> None:
        pytest.fail("unexpected child")

    monkeypatch.setattr(process, "_child", forbidden)
    with pytest.raises(ValueError, match="unknown_cell"):
        process.run_cell(tmp_path, "unknown")


def test_original_close_failure_is_retained_before_emergency_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    os_alias, _calls = _windows_aliases(monkeypatch)
    original_close = os_alias.close
    attempts: list[int] = []

    def close(descriptor: int) -> None:
        attempts.append(descriptor)
        if len(attempts) == 1:
            raise PermissionError(13, "private-close")
        original_close(descriptor)

    os_alias.close = close
    report = child.observe(journal, tmp_path / "journal", "original", lambda _event: None, lambda: "release\n")
    assert report["error"] == {"kind": "permission", "errno": 13, "winerror": None}
    assert report["original_descriptors_closed"] == [False]
    assert report["emergency_close_results"] == [True]
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert report["callbacks_restored"]


def test_unresponsive_direct_child_is_killed_and_reaped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process, "WAIT_SECONDS", 0.05)
    runner = process.Child([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
    report = runner.retire()
    assert report["killed"] and report["returncode"] is not None
    assert report["reader_joined"] and report["reader_error"] is None


def test_spawn_failure_is_retained_without_cleanup_claim(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def denied(*_args: Any) -> None:
        raise PermissionError(13, "private", "/private")

    monkeypatch.setattr(process, "_child", denied)
    report = process.run_cell(tmp_path / "journal", "held")
    assert report["controller_error"] == {"kind": "permission", "errno": 13, "winerror": None}
    assert report["cleanup"] == []
    assert "private" not in json.dumps(report)
