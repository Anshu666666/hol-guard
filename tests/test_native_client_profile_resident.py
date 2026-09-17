from __future__ import annotations

import copy
import io
import json
import threading
from pathlib import Path
from queue import Queue
from unittest.mock import Mock

import pytest

from scripts import native_slo_session
from scripts.native_client_profile_observer import ClientObserver
from scripts.native_client_profile_records import decode_record
from scripts.native_client_profile_resident import require_evaluated, validate_relay_chains
from tests.native_client_profile_support import record, resident_record
from tests.test_native_client_profile_observer import Journal


def chain():
    residents = [{"helper": 1, "resident_profile": resident_record()}]
    relays = [
        {
            "helper": 1,
            "relay": {
                "schema": "hol-guard.native-resident-profile-relay.v1",
                "parent_process_id": 222,
                "child_process_id": 123,
                "records": 1,
                "complete": True,
            },
        },
        {
            "helper": 1,
            "relay": {
                "schema": "hol-guard.native-resident-profile-relay.v1",
                "parent_process_id": 111,
                "child_process_id": 222,
                "records": 2,
                "complete": True,
            },
        },
    ]
    return residents, relays


def test_resident_digest_and_separate_span_round_trip():
    value = resident_record()
    assert decode_record(json.dumps(value).encode() + b"\n") == value
    require_evaluated(value)
    residents, relays = chain()
    for row in relays:
        assert decode_record(json.dumps(row["relay"]).encode() + b"\n") == row["relay"]
    validate_relay_chains({1: 111}, residents, relays)


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "digest",
        "generation",
        "pid",
        "boolean",
        "calls",
        "successes",
        "null",
        "duration",
        "outcome",
        "overflow",
    ],
)
def test_resident_admission_and_evaluated_profile_fail_closed(change):
    value = resident_record()
    if change == "extra":
        value["private"] = "untrusted"
    elif change == "digest":
        value["request_sha256"] = "a" * 63
    elif change in {"generation", "pid", "boolean"}:
        value[{"generation": "generation", "pid": "process_id", "boolean": "sequence"}[change]] = (
            False if change == "boolean" else 0
        )
    elif change == "calls":
        value["edge_evaluation"]["calls"] = 2
    elif change == "successes":
        value["edge_evaluation"]["succeeded"] = 0
    elif change == "null":
        value["dispatch_encode_nanoseconds"] = None
    elif change == "duration":
        value["edge_evaluation"]["nanoseconds"] = 61
    elif change == "outcome":
        value["outcome"] = "rejected"
    else:
        value["overflow"] = True
    with pytest.raises(ValueError):
        require_evaluated(decode_record(json.dumps(value).encode() + b"\n"))


@pytest.mark.parametrize(
    "change",
    ["missing", "duplicate", "helper", "resident", "parent", "child", "count", "first_count", "incomplete", "unowned"],
)
def test_eof_requires_both_exact_owned_pipe_edges_and_counts(change):
    residents, relays = chain()
    helpers = {1: 111}
    if change == "missing":
        relays.pop()
    elif change == "duplicate":
        relays.append(copy.deepcopy(relays[0]))
    elif change == "helper":
        helpers[1] = 112
    elif change == "resident":
        residents[0]["resident_profile"]["process_id"] = 124
    elif change == "parent":
        relays[0]["relay"]["parent_process_id"] = 223
    elif change == "child":
        relays[1]["relay"]["child_process_id"] = 223
    elif change == "count":
        relays[0]["relay"]["records"] = 0
    elif change == "first_count":
        relays[1]["relay"]["records"] = 1
    elif change == "incomplete":
        relays[0]["relay"]["complete"] = False
    else:
        relays[0]["helper"] = 2
    with pytest.raises(ValueError):
        validate_relay_chains(helpers, residents, relays)


def test_observer_accepts_out_of_order_worker_emissions_but_rejects_gap_and_duplicate():
    for sequences, expected in [([2, 1], False), ([2], True), ([1, 1], True)]:
        observer = ClientObserver(Path("/runtime"), Journal())
        payload = b"".join(json.dumps(resident_record(sequence=n)).encode() + b"\n" for n in sequences)
        observer._read(io.BytesIO(payload), 1)
        observer.__exit__()
        assert observer.failure is expected


@pytest.mark.parametrize("failure", [False, True])
def test_observer_retirement_wait_always_preserves_original_close_result(monkeypatch, failure):
    output = object()
    close = Mock(return_value=output)
    monkeypatch.setattr(native_slo_session, "close_native_resident_clients", close)
    with ClientObserver(Path("/runtime"), Journal()) as observer:
        wait = Mock(side_effect=ValueError("bounded") if failure else None)
        monkeypatch.setattr(observer, "_wait_for_relay_eof", wait)
        assert native_slo_session.close_native_resident_clients(Path("/fixture")) is output
        wait.assert_called_once_with()
        close.assert_called_once_with(Path("/fixture"))
    assert observer.failure is failure
    assert native_slo_session.close_native_resident_clients is close


def test_cleanup_observer_waits_for_eof_not_just_all_resident_records(monkeypatch):
    observer = ClientObserver(Path("/runtime"), Journal())
    observer.spawns = 1
    observer.helper_pids = {1: 111}
    residents, relays = chain()
    observer.resident_records = residents
    observed_wait = threading.Event()
    original_wait = observer.condition.wait

    def wait(timeout):
        observed_wait.set()
        return original_wait(timeout)

    monkeypatch.setattr(observer.condition, "wait", wait)

    def publish_eof():
        assert observed_wait.wait(1)
        with observer.condition:
            observer.relay_records = relays
            observer.condition.notify_all()

    writer = threading.Thread(target=publish_eof)
    writer.start()
    observer._wait_for_relay_eof()
    writer.join(1)
    assert not writer.is_alive() and observed_wait.is_set()


def test_missing_eof_has_bounded_wait_and_preserves_cleanup_exception(monkeypatch):
    sentinel = OSError("original cleanup")
    close = Mock(side_effect=sentinel)
    monkeypatch.setattr(native_slo_session, "close_native_resident_clients", close)
    with ClientObserver(Path("/runtime"), Journal()) as observer:
        observer.spawns = 1
        # Deterministic diagnostic deadline exhaustion, no wall-clock sleep.
        with monkeypatch.context() as clock:
            clock.setattr(
                "scripts.native_client_profile_observer.time",
                type("Clock", (), {"monotonic": staticmethod(iter([0, 3]).__next__)}),
            )
            with pytest.raises(OSError) as result:
                native_slo_session.close_native_resident_clients(Path("/fixture"))
        assert result.value is sentinel and observer.failure
        close.assert_called_once()


@pytest.mark.parametrize("late", ["client", "resident", "auxiliary"])
def test_late_duplicate_hook_digest_is_rejected_after_truthful_eof(late):
    lines = Queue()

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def readline(self, _bound):
            return lines.get(timeout=2)

    observer = ClientObserver(Path("/runtime"), Journal())
    observer.helper_pids = {1: 111}
    observer.spawns = 1
    observer.reader_helpers = {1}
    observer.requests = ["a" * 64]
    reader = threading.Thread(target=observer._read, args=(Stream(), 1), daemon=True)
    observer.readers = [reader]
    reader.start()

    def emit(value):
        lines.put(json.dumps(value).encode() + b"\n")

    emit(record())
    emit(resident_record())
    assert observer.request_profile(0)["profile"]["sequence"] == 1
    assert observer.resident_profile("a" * 64)["resident_profile"]["sequence"] == 1
    # Both first lookups have succeeded. The still-open reader now receives a
    # valid later sequence with either the selected or an auxiliary digest.
    emit(record(sequence=2, digest="a" * 64 if late == "client" else "b" * 64))
    emit(resident_record(sequence=2, digest="a" * 64 if late == "resident" else "b" * 64))
    if late == "auxiliary":
        emit(record(sequence=3, digest="b" * 64))
        emit(resident_record(sequence=3, digest="b" * 64))
    _, relays = chain()
    for offset, item in enumerate(relays):
        item["relay"]["records"] = (3 if late == "auxiliary" else 2) + offset
        emit(item["relay"])
    lines.put(b"")
    observer.__exit__()
    assert not observer.failure and not reader.is_alive()
    if late == "auxiliary":
        observer.validate_resident_capture()
    else:
        with pytest.raises(ValueError):
            observer.validate_resident_capture()


@pytest.mark.parametrize("missing", ["second_helper", "eof", "reader", "pid", "client_record"])
def test_every_actual_helper_requires_owned_reader_clean_eof_and_client_record(missing):
    observer = ClientObserver(Path("/runtime"), Journal())
    observer.spawns = 1
    observer.helper_pids = {1: 111}
    observer.reader_helpers = observer.eof_helpers = {1}
    observer.readers = [threading.Thread()]
    observer.records = [{"helper": 1, "profile": record()}]
    observer.resident_records, observer.relay_records = chain()
    observer.selected_clients = {"a" * 64: (1, 1)}
    observer.selected_residents = {"a" * 64: (1, 123, 1, 1)}
    observer.validate_resident_capture()
    if missing == "second_helper":
        observer.spawns = 2
        observer.helper_pids[2] = 999
        observer.reader_helpers = {1, 2}
        observer.eof_helpers = {1, 2}
        observer.readers.append(threading.Thread())
    elif missing == "eof":
        observer.eof_helpers = set()
    elif missing == "reader":
        observer.reader_helpers = set()
    elif missing == "pid":
        observer.helper_pids = {}
    else:
        observer.records = []
    with pytest.raises(ValueError):
        observer.validate_resident_capture()


def test_existing_resident_can_serve_a_different_owned_helper():
    observer = ClientObserver(Path("/runtime"), Journal())
    observer.spawns = 2
    observer.helper_pids = {1: 111, 2: 999}
    observer.reader_helpers = observer.eof_helpers = {1, 2}
    observer.readers = [threading.Thread(), threading.Thread()]
    observer.records = [{"helper": 1, "profile": record(digest="b" * 64)}, {"helper": 2, "profile": record()}]
    observer.resident_records, observer.relay_records = chain()
    observer.selected_clients = {"a" * 64: (2, 1)}
    observer.selected_residents = {"a" * 64: (1, 123, 1, 1)}
    observer.validate_resident_capture()


@pytest.mark.parametrize("side", ["client", "resident"])
def test_a_later_hook_cannot_reuse_an_already_selected_frame(side):
    observer = ClientObserver(Path("/runtime"), Journal())
    observer.requests = ["a" * 64]
    observer.records = [{"helper": 1, "profile": record()}]
    observer.resident_records, _ = chain()
    observer.request_profile(0)
    observer.resident_profile("a" * 64)
    observer.requests.append("a" * 64)
    with pytest.raises(ValueError):
        if side == "client":
            observer.request_profile(1)
        else:
            observer.resident_profile("a" * 64)
