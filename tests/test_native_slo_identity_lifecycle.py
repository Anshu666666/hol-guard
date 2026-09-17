from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from scripts.native_slo_identity_lifecycle import LifecycleObserver
from scripts.native_slo_identity_lifecycle_record import MAX_BYTES, MAX_CALLS, LifecycleJournal, read_lifecycle
from tests.test_native_slo_identity_phases import fixture_runtime, hook

BINDING = {"build_sha": "1" * 40, "runtime_sha256": "2" * 64, "installed_package_sha256": "3" * 64}


def cold_runtime(tmp_path):
    runtime, handler, executable = fixture_runtime(tmp_path)
    original = runtime._inspect_native_runtime_status

    def status(**kwargs):
        original(**kwargs)
        return SimpleNamespace(
            identity=SimpleNamespace(sha256=BINDING["runtime_sha256"]),
            capabilities=SimpleNamespace(build_sha=BINDING["build_sha"]),
        )

    runtime._inspect_native_runtime_status = status

    class Publisher:
        def _publish_once(self):
            return runtime.native_runtime_status()

    return runtime, handler, Publisher, executable


def observe_all(tmp_path, *, extra=None):
    runtime, handler, publisher, executable = cold_runtime(tmp_path)
    path = tmp_path / "observer.jsonl"
    observer = LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher)
    with observer:
        with observer.preparation():
            runtime.native_runtime_status()
            thread = threading.Thread(target=publisher()._publish_once)
            thread.start()
            thread.join(2)
            assert not thread.is_alive()
        observer.phase("ready")
        if extra is not None:
            extra(observer, runtime)
        for _ in range(3):
            hook(handler)
        observer.phase("cleanup")
    return read_lifecycle(path, BINDING), path, observer, executable


def test_preparation_publication_and_hooks_preserve_exact_hash_bytes(tmp_path):
    report, path, observer, executable = observe_all(tmp_path)
    assert report["complete"] and report["preparation_status_calls"] == 2
    assert report["hook_status_calls"] == [1, 1, 1]
    assert report["calls_started"] == 5 and report["calls_unfinished"] == 0
    totals = report["totals_by_owner"]
    assert totals["preparation"]["capability_cache_misses"] == 1
    assert totals["publication"]["capability_cache_hits"] == 1
    assert totals["hook"]["capability_cache_hits"] == 3
    assert totals["hook"]["executable_hashed_bytes"] == 3 * executable.stat().st_size
    assert report["cold_preparation_to_first_handler_return_ns"] > 0
    assert observer.runtime.lookups == 5 and not observer._installed
    assert str(executable) not in path.read_text() and "synthetic executable" not in path.read_text()
    assert path.stat().st_size < MAX_BYTES and path.stat().st_mode & 0o777 == 0o600


def test_unassigned_and_direct_capability_process_are_not_omitted(tmp_path):
    def extra(_observer, runtime):
        thread = threading.Thread(target=runtime.native_runtime_status)
        thread.start()
        thread.join(2)
        runtime._run_native_process(None, ("capabilities", "--json"))

    report, _, _, _ = observe_all(tmp_path, extra=extra)
    assert not report["complete"] and report["unassigned_calls"] == 2
    assert report["totals_by_owner"]["unassigned"]["status_calls"] == 1
    assert report["totals_by_owner"]["unassigned"]["capability_process_calls"] == 1


def test_publication_crossing_phase_is_explicit_not_charged_to_hook(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    original = runtime._inspect_native_runtime_status
    entered, release = threading.Event(), threading.Event()

    def blocked(**kwargs):
        entered.set()
        assert release.wait(2)
        return original(**kwargs)

    runtime._inspect_native_runtime_status = blocked
    path = tmp_path / "crossing.jsonl"
    with LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer:
        thread = threading.Thread(target=publisher()._publish_once)
        thread.start()
        assert entered.wait(2)
        observer.phase("ready")
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        for _ in range(3):
            hook(handler)
    report = read_lifecycle(path, BINDING)
    assert not report["complete"] and report["cross_boundary_calls"] == 1
    assert report["totals_by_owner"]["publication"]["status_calls"] == 1
    assert report["totals_by_owner"]["hook"]["status_calls"] == 3


def test_same_original_exception_and_single_status_call_survive_journal_failure(tmp_path, monkeypatch):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    failure = OSError("private exception payload")
    runtime.fail = failure
    path = tmp_path / "failed.jsonl"
    with (
        pytest.raises(OSError) as caught,
        LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer,
    ):
        monkeypatch.setattr(observer.journal, "append", lambda *a, **kw: None)
        with observer.preparation():
            runtime.native_runtime_status()
    assert caught.value is failure and runtime.lookups == 1
    assert not observer._installed and not read_lifecycle(path, BINDING)["complete"]
    assert "private exception payload" not in path.read_text()


def test_publisher_patch_install_failure_restores_all_wrappers_and_lock(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    original = runtime._inspect_native_runtime_status
    del publisher._publish_once
    observer = LifecycleObserver(
        tmp_path / "failed.jsonl", BINDING, runtime=runtime, handler=handler, publisher=publisher
    )
    with pytest.raises(AttributeError):
        observer.__enter__()
    assert runtime._inspect_native_runtime_status is original and not observer._installed
    publisher._publish_once = lambda _self: None
    with LifecycleObserver(tmp_path / "next.jsonl", BINDING, runtime=runtime, handler=handler, publisher=publisher):
        pass


def test_existing_capability_cache_is_not_cleared_or_relabelled(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    runtime.native_runtime_status()
    path = tmp_path / "prepared.jsonl"
    with LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer:
        with observer.preparation():
            runtime.native_runtime_status()
        observer.phase("ready")
        for _ in range(3):
            hook(handler)
    report = read_lifecycle(path, BINDING)
    assert report["complete"] and report["terminal"]["initial_cache_entries"] == 1
    assert report["totals_by_owner"]["preparation"]["capability_cache_hits"] == 1


@pytest.mark.parametrize(
    "change", ["binding", "unknown", "bool_call", "backwards", "partial", "missing_terminal", "identity"]
)
def test_mutated_or_partial_records_never_claim_complete(tmp_path, change):
    report, path, _, _ = observe_all(tmp_path)
    assert report["complete"]
    records = [json.loads(line) for line in path.read_text().splitlines()]
    if change == "binding":
        records[0]["binding"]["runtime_sha256"] = "4" * 64
    elif change == "unknown":
        records[1]["private"] = "private sentinel"
    elif change == "bool_call":
        next(row for row in records if row["kind"] == "call_finished")["call"] = False
    elif change == "backwards":
        records[2]["elapsed_ns"] = 0
    elif change == "identity":
        next(row for row in records if row["kind"] == "call_finished")["identity_matches"] = False
    elif change == "missing_terminal":
        records.pop()
    path.write_text("".join(json.dumps(row) + "\n" for row in records) + ("{partial" if change == "partial" else ""))
    report = read_lifecycle(path, BINDING)
    assert not report["complete"]
    assert "private sentinel" not in json.dumps(report)


def test_unfinished_call_remains_retained_before_child_termination(tmp_path):
    path = tmp_path / "interrupted.jsonl"
    journal = LifecycleJournal(path, BINDING)
    journal.append(
        "call_started",
        call=0,
        operation="status",
        owner="publication",
        phase="preparation",
        phase_epoch=0,
        hook=None,
        parent_call=None,
    )
    journal.close()
    report = read_lifecycle(path, BINDING)
    assert report["available"] and not report["complete"]
    assert report["calls_started"] == report["calls_unfinished"] == 1
    assert report["hooks_started"] == 0 and report["cold_preparation_to_first_handler_return_ns"] is None


def test_call_bound_does_not_suppress_original_calls_or_claim_complete(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    path = tmp_path / "overflow.jsonl"
    with (
        LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer,
        observer.preparation(),
    ):
        for _ in range(MAX_CALLS + 1):
            runtime.native_runtime_status()
    report = read_lifecycle(path, BINDING)
    assert runtime.lookups == MAX_CALLS + 1
    assert not report["complete"] and report["terminal"]["overflow"]
    assert path.stat().st_size <= MAX_BYTES


def test_nested_status_keeps_parent_identity_and_no_exclusive_total_claim(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    original = runtime._inspect_native_runtime_status
    nesting = False

    def nested(**kwargs):
        nonlocal nesting
        if not nesting:
            nesting = True
            try:
                runtime._inspect_native_runtime_status()
            finally:
                nesting = False
        return original(**kwargs)

    runtime._inspect_native_runtime_status = nested
    path = tmp_path / "nested.jsonl"
    with (
        LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer,
        observer.preparation(),
    ):
        runtime.native_runtime_status()
    report = read_lifecycle(path, BINDING)
    assert not report["complete"] and report["nested_calls"] == 1
    assert report["calls"][0]["parent_call"] is None and report["calls"][1]["parent_call"] == 0
    assert runtime.lookups == 2


def test_concurrent_global_capability_deltas_are_ambiguous(tmp_path):
    import functools

    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    barrier = threading.Barrier(2)

    @functools.lru_cache(maxsize=16)
    def capabilities(*key):
        barrier.wait(2)
        return runtime._run_native_process(None, ("capabilities", "--json"))

    runtime._capabilities_for_identity = capabilities
    path = tmp_path / "concurrent.jsonl"
    with LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher):
        threads = [threading.Thread(target=publisher()._publish_once), threading.Thread(target=lambda: hook(handler))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive()
    report = read_lifecycle(path, BINDING)
    assert not report["complete"] and report["capability_cache_ambiguous"] >= 1
    assert report["totals_by_owner"]["hook"]["capability_cache_hits"] == 0
    assert report["totals_by_owner"]["publication"]["capability_cache_hits"] == 0
    assert runtime.lookups == 2


def test_short_journal_write_cannot_replace_original_return(tmp_path):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    path = tmp_path / "short.jsonl"
    with LifecycleObserver(path, BINDING, runtime=runtime, handler=handler, publisher=publisher) as observer:

        class Short:
            def write(self, data):
                return len(data) - 1

        observer.journal._stream = Short()
        with observer.preparation():
            assert runtime.native_runtime_status().identity.sha256 == BINDING["runtime_sha256"]
    assert runtime.lookups == 1 and observer.journal.failed
    assert not read_lifecycle(path, BINDING)["complete"]


def test_child_journal_creation_uses_private_atomic_admission(tmp_path, monkeypatch):
    from scripts import native_slo_identity_lifecycle_record as record

    original = record.atomic_exclusive
    created = []

    def create(path, content):
        created.append((path, content))
        return original(path, content)

    monkeypatch.setattr(record, "atomic_exclusive", create)
    path = tmp_path / "private.jsonl"
    journal = record.LifecycleJournal(path, BINDING)
    journal.close()
    assert created == [(path, b"")]
    with pytest.raises(FileExistsError):
        record.LifecycleJournal(path, BINDING)


@pytest.mark.parametrize("body_failure", [False, True])
def test_directory_close_failure_preserves_active_original_exception(tmp_path, monkeypatch, body_failure):
    runtime, handler, publisher, _ = cold_runtime(tmp_path)
    observer = LifecycleObserver(
        tmp_path / "close.jsonl", BINDING, runtime=runtime, handler=handler, publisher=publisher
    )
    original = OSError("private original error")
    original_close = observer.journal._stack.close

    def fail_close():
        original_close()
        raise ValueError("private changed directory")

    monkeypatch.setattr(observer.journal._stack, "close", fail_close)
    with pytest.raises((OSError, RuntimeError)) as caught, observer:
        if body_failure:
            raise original
    assert observer.journal.close_failed and not observer._installed
    if body_failure:
        assert caught.value is original
    else:
        assert str(caught.value) == "qualification cold journal close failed"
    assert "private changed directory" not in observer.journal.path.read_text()
