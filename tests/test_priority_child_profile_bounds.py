"""Closed profiler failure behavior using real Python frames and hooks."""

from __future__ import annotations

import json
import sys
import threading
from typing import Any

import pytest

from scripts.ci.priority_launcher_child import profile_runtime as runtime


def observed(value):
    return value


def nested(depth):
    return nested(depth - 1) if depth else observed("PRIVATE_VALUE")


def configuration(tmp_path) -> dict[str, Any]:
    return {
        "modules": {},
        "frames": [
            {
                "file": fn.__code__.co_filename,
                "qualname": fn.__qualname__,
                "line": fn.__code__.co_firstlineno,
                "id": fn.__name__,
            }
            for fn in (observed, nested)
        ],
        "output": str(tmp_path),
        "configuration_sha256": "a" * 64,
        "active_registered_argv": list(sys.orig_argv),
        "module_roster_after_setup": [],
    }


@pytest.mark.parametrize("bound", ["MAX_CALLBACKS", "MAX_RECORDS", "MAX_DEPTH", "MAX_THREADS"])
def test_bounds_disable_capture_preserving_original_value(monkeypatch, tmp_path, bound):
    monkeypatch.setattr(runtime, bound, 0)
    profile = runtime.Profile(configuration(tmp_path))
    sentinel = object()
    try:
        profile.start()
        assert observed(sentinel) is sentinel
    finally:
        profile.restore()
    assert profile.faults and profile.enabled is False
    assert sys.getprofile() is None and threading.getprofile() is None


def test_clock_failure_cannot_replace_original_exception(tmp_path):
    profile = runtime.Profile(configuration(tmp_path))
    original = RuntimeError("original private error")

    def broken():
        raise ValueError("diagnostic private error")

    try:
        profile.start()
        profile.clock = broken
        with pytest.raises(RuntimeError) as caught:
            raise original
        assert caught.value is original
    finally:
        profile.restore()
    assert profile.faults


def test_preexisting_profile_is_preserved_and_refused(tmp_path):
    def existing(*_args):
        return None

    try:
        sys.setprofile(existing)
        profile = runtime.Profile(configuration(tmp_path))
        assert not profile.start()
        assert sys.getprofile() is existing
        profile.restore()
        assert sys.getprofile() is existing and profile.faults == ["preexisting_profile"]
    finally:
        sys.setprofile(None)


def test_intervening_profile_is_not_overwritten(tmp_path):
    def replacement(*_args):
        return None

    profile = runtime.Profile(configuration(tmp_path))
    try:
        assert profile.start()
        sys.setprofile(replacement)
        profile.restore()
        assert sys.getprofile() is replacement
        assert not profile.restore_complete
    finally:
        sys.setprofile(None)
        threading.setprofile(None)


def test_changed_selected_frame_identity_is_incomplete(tmp_path):
    config = configuration(tmp_path)
    config["frames"][0]["line"] += 1
    profile = runtime.Profile(config)
    try:
        profile.start()
        assert observed(42) == 42
    finally:
        profile.restore()
    assert "frame_identity_changed" in profile.faults


def test_nested_intervals_and_no_argument_values(tmp_path):
    profile = runtime.Profile(configuration(tmp_path))
    try:
        profile.start()
        assert nested(3) == "PRIVATE_VALUE"
    finally:
        profile.restore()
    profile.finish()
    document = json.loads(next(tmp_path.glob("*.json")).read_bytes())
    assert document["observation_complete"] is True
    assert len(document["records"]) == 5
    for row in document["records"]:
        if row["parent"] is not None:
            parent = document["records"][row["parent"]]
            assert parent["start_ns"] <= row["start_ns"] <= row["end_ns"] <= parent["end_ns"]
    assert "PRIVATE_VALUE" not in json.dumps(document)


def test_byte_limit_withholds_records_without_overwriting_existing_report(tmp_path, monkeypatch):
    profile = runtime.Profile(configuration(tmp_path))
    profile.restore()
    profile.config["module_roster_after_setup"] = []
    monkeypatch.setattr(runtime, "MODULES_BEFORE", ())
    profile.records = [{"padding": "x" * 10000}]
    monkeypatch.setattr(runtime, "MAX_BYTES", 2048)
    profile.finish()
    path = next(tmp_path.glob("*.json"))
    report = json.loads(path.read_bytes())
    assert report["records_withheld"] is True and report["observation_complete"] is False
    original = path.read_bytes()
    second = runtime.Profile(configuration(tmp_path))
    second.finish()
    assert path.read_bytes() == original and "export_failed" in second.faults


def test_partial_install_failure_unwinds_only_owned_files(tmp_path, monkeypatch):
    from scripts.ci.priority_launcher_child import installation

    site, output = tmp_path / "site", tmp_path / "out"
    site.mkdir()
    output.mkdir(mode=0o700)
    config = {"executable": sys.executable, "observed_argv0": sys.executable, "parent_pid": 1, "argv": []}
    observer = installation.Installation(site, output, config)
    original = installation.os.open
    count = 0

    def opening(path, *args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("diagnostic failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(installation.os, "open", opening)
    with pytest.raises(OSError):
        observer.__enter__()
    assert not list(site.iterdir()) and not observer.cleanup_faults


def test_finish_freezes_an_inflight_callback_as_incomplete_without_waiting(tmp_path):
    import time

    entered, release = threading.Event(), threading.Event()
    main = threading.get_ident()
    blocked = False

    def clock():
        nonlocal blocked
        if threading.get_ident() != main and not blocked:
            blocked = True
            entered.set()
            assert release.wait(5)
        return time.perf_counter_ns()

    profile = runtime.Profile(configuration(tmp_path), clock=clock)
    thread = threading.Thread(target=lambda: observed("PRIVATE_VALUE"))
    try:
        profile.start()
        thread.start()
        assert entered.wait(5)
        profile.finish()
        path = next(tmp_path.glob("*.json"))
        frozen = path.read_bytes()
        report = json.loads(frozen)
        assert report["callbacks_in_flight_at_snapshot"] == 1
        assert report["worker_hooks_not_retired"] == 1
        assert report["observation_complete"] is False
    finally:
        release.set()
        thread.join(5)
        profile.restore()
    assert not thread.is_alive() and path.read_bytes() == frozen


def test_unseen_first_callback_before_lock_makes_finish_incomplete(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    main = threading.get_ident()
    underlying = threading.RLock()
    blocked = False

    class AdmissionLock:
        def __enter__(self):
            nonlocal blocked
            if threading.get_ident() != main and not blocked:
                blocked = True
                entered.set()
                assert release.wait(5)
            underlying.acquire()
            return self

        def __exit__(self, *_args):
            underlying.release()

    profile = runtime.Profile(configuration(tmp_path))
    monkeypatch.setattr(profile, "lock", AdmissionLock())
    thread = threading.Thread(target=lambda: observed("PRIVATE_VALUE"), daemon=True)
    try:
        profile.start()
        thread.start()
        assert entered.wait(5)
        profile.finish()
        path = next(tmp_path.glob("*.json"))
        frozen = path.read_bytes()
        report = json.loads(frozen)
        assert report["callbacks_in_flight_at_snapshot"] == 0
        assert report["worker_hooks_not_retired"] == 0
        assert report["current_worker_threads_at_snapshot"] == 1
        assert report["thread_census_complete"] is True
        assert report["observation_complete"] is False
    finally:
        release.set()
        thread.join(5)
        profile.restore()
    assert not thread.is_alive() and path.read_bytes() == frozen


@pytest.mark.parametrize("mode", ["failure", "over_bound"])
def test_thread_census_refusal_is_incomplete(tmp_path, monkeypatch, mode):
    profile = runtime.Profile(configuration(tmp_path))
    profile.start()

    def census():
        if mode == "failure":
            raise RuntimeError("PRIVATE_CENSUS_ERROR")
        return [threading.current_thread()] * (runtime.MAX_THREADS + 1)

    monkeypatch.setattr(threading, "enumerate", census)
    profile.finish()
    report = json.loads(next(tmp_path.glob("*.json")).read_bytes())
    assert report["thread_census_complete"] is False
    assert report["observation_complete"] is False
    assert report["faults"] == ["thread_census_failed" if mode == "failure" else "thread_census_limit"]
