"""Finite trace admission and actual Python forwarding; no native lookup credit."""

from __future__ import annotations

import copy
import errno
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_dnssd_phase_child as child
from scripts.ci import native_macos_dnssd_phase_evidence as evidence
from tests.test_native_macos_dnssd_python import BRIDGE as BASE_BRIDGE
from tests.test_native_macos_dnssd_python import IMAGES
from tests.test_native_macos_dnssd_python import RUNTIME as BASE_RUNTIME
from tests.test_native_macos_dnssd_python import records as base_records
from tests.test_native_macos_dnssd_python import wire

RUNTIME = BASE_RUNTIME | {evidence.EXTRA_RUNTIME_KEY: "f" * 64}
BRIDGE = BASE_BRIDGE | {"filetype": 6}
BINARY = BASE_BRIDGE | {"filetype": 2, "sha256": "1" * 64}


def records(mode="dns_simple", context="python", cycles=1):
    base = base_records(mode)
    base[0][evidence.EXTRA_RUNTIME_KEY] = RUNTIME[evidence.EXTRA_RUNTIME_KEY]
    base[-1][evidence.EXTRA_RUNTIME_KEY] = RUNTIME[evidence.EXTRA_RUNTIME_KEY]
    rows = base[:7] if context == "python" else base[5:7]
    sequence = 0

    def trace(call, phase, **values):
        nonlocal sequence
        sequence += 1
        if sequence <= 32:
            rows.append({"kind": "call_trace", "sequence": sequence, "call": call, "phase": phase, **values})
        elif sequence == 33:
            rows.append({"kind": "call_trace_overflow", "sequence": 33})

    for index in range(cycles):
        trace("poll", "enter", fd=7, events=1, nfds=1, timeout=-1)
        trace("poll", "return", result=1, errno=0, revents=1)
        trace("DNSServiceProcessResult", "enter")
        if index == cycles - 1:
            rows.append(base[7])
        trace("DNSServiceProcessResult", "return", result=0, errno=0)
    return rows + (base[8:] if context == "python" else base[8:9])


def parse(rows, mode="dns_simple", context="python", runtime=None, identity=None):
    return evidence.parse_trace(
        wire(rows), mode, 123, runtime or RUNTIME,
        identity or (BRIDGE if context == "python" else BINARY), python=context == "python",
    )


@pytest.mark.parametrize("context", ("standalone", "python"))
@pytest.mark.parametrize("mode", child.MODES)
def test_success_and_every_unfinished_prefix(context, mode):
    rows = records(mode, context)
    assert parse(rows, mode, context)["loopback_label"]
    for length in range(1, len(rows)):
        observed = parse(rows[:length], mode, context)
        assert observed["valid"] and not observed["complete"] and not observed["loopback_label"]
    partial = evidence.parse_trace(
        wire(rows)[:-1], mode, 123, RUNTIME, BRIDGE if context == "python" else BINARY, python=context == "python"
    )
    assert partial["valid"] and partial["partial_line"] and not partial["complete"]


def test_pending_boundaries_and_complete_return_without_callback_record():
    rows = records(cycles=2)
    assert parse(rows[:8])["pending_call"] == "poll"
    assert parse(rows[:10])["pending_call"] == "DNSServiceProcessResult"
    pending = parse(rows[:12])
    assert pending["pending_call"] == "poll" and pending["process_returns_without_callback_record"] == 1
    assert parse(rows)["process_returns_without_callback_record"] == 1
    assert parse(records()[:11])["process_returns_without_callback_record"] == 0


@pytest.mark.parametrize("cycles", (1, 8, 9, 17))
def test_trace_limit_preserves_bounded_prefix_and_censors_success(cycles):
    observed = parse(records(cycles=cycles))
    assert observed["valid"]
    assert observed["trace_records"] == min(cycles * 4, 32)
    assert observed["trace_overflow"] is (cycles > 8)
    assert observed["complete"] is (cycles <= 8)
    assert observed["loopback_label"] is (cycles <= 8)


@pytest.mark.parametrize("index,key,value", [
    (7, "sequence", True), (7, "sequence", 2), (7, "fd", -1), (7, "nfds", 2),
    (7, "events", True), (7, "events", 2), (7, "timeout", 5000), (7, "private_path", "hidden"),
    (8, "result", 2), (8, "result", True), (8, "errno", True), (8, "revents", 0),
    (8, "revents", 65536), (9, "call", "poll"), (9, "phase", "return"),
    (11, "result", -65537), (11, "errno", []), (11, "sequence", 3),
    (0, "phase_child_source_sha256", "0" * 64), (0, "call_policy", "PyDLL"),
    (5, "cpu_subtype", 1), (5, "dnssd_uuid", "0" * 32), (10, "private_rdata", "hidden"),
])
def test_mutated_trace_or_identity_is_refused(index, key, value):
    rows = records()
    rows[index][key] = value
    assert parse(rows)["records"] == []


@pytest.mark.parametrize("index", (7, 8, 9, 11))
def test_missing_half_of_call_pair_cannot_earn_completion(index):
    rows = records()
    del rows[index]
    assert not parse(rows)["valid"]


def test_descriptor_cannot_change_between_calls_and_trace_cannot_follow_overflow():
    rows = records(cycles=2)
    rows[11]["fd"] = 8
    assert not parse(rows)["valid"]
    rows = records(cycles=9)
    marker = next(index for index, row in enumerate(rows) if row["kind"] == "call_trace_overflow")
    for extra in ({"kind": "call_trace_overflow", "sequence": 33}, records()[7] | {"sequence": 34}):
        changed = copy.deepcopy(rows)
        changed.insert(marker + 1, extra)
        assert not parse(changed)["valid"]
    rows = records()
    rows.insert(7, {"kind": "call_trace_overflow", "sequence": 33})
    assert not parse(rows)["valid"]


def test_interrupted_poll_can_repeat_but_cannot_skip_processing_on_readiness():
    rows = records()
    early = copy.deepcopy(rows[7:9])
    early[1].update(result=-1, errno=errno.EINTR, revents=0)
    for row in rows:
        if row["kind"] == "call_trace":
            row["sequence"] += 2
    rows[7:7] = early
    observed = parse(rows)
    assert observed["complete"] and observed["trace_records"] == 6
    rows = records()
    del rows[9:12]
    assert not parse(rows)["valid"]


@pytest.mark.parametrize("processing", (False, True))
def test_observed_call_error_must_agree_with_unsuccessful_final_result(processing):
    rows = records()
    prefix = rows[:10] if processing else rows[:8]
    returned = rows[11] | {"result": -65537} if processing else rows[8] | {"result": -1, "errno": errno.EINVAL, "revents": 0}
    final = rows[12] | {"error": -65537, "callbacks": 0, "loopback_label": False}
    suffix = copy.deepcopy(rows[13:])
    suffix[-1]["return_code"] = 2
    observed = parse(prefix + [returned, final] + suffix)
    assert observed["valid"] and observed["complete"] and not observed["loopback_label"]


def test_original_callback_reporting_limit_does_not_become_an_absence_of_invocation_claim():
    rows = records()
    callbacks = [rows[10] | {"sequence": index + 1, "flags": rows[10]["flags"] | 1} for index in range(16)]
    second = [row | {"sequence": row["sequence"] + 4} for row in (rows[7], rows[8], rows[9], rows[11])]
    final = rows[12] | {"callbacks": 16, "overflow": True}
    suffix = copy.deepcopy(rows[13:])
    suffix[-1]["return_code"] = 2
    observed = parse(rows[:10] + callbacks + [rows[11]] + second + [final] + suffix)
    assert observed["valid"] and observed["complete"] and not observed["loopback_label"]
    assert observed["process_returns_without_callback_record"] == 1 and observed["callback_record_limit"] == 16


@pytest.mark.parametrize("raw", [b"[]\n", b"{}\n", b'{"kind":[]}\n', b'{"kind":{}}\n', b'{"kind":1,"kind":2}\n', b"\xff\n", b"x" * 16385])
def test_malformed_or_oversized_records_are_refused(raw):
    assert evidence.parse_trace(raw, "dns_simple", 123, RUNTIME, BRIDGE, python=True)["records"] == []


@pytest.mark.parametrize("identity", [BRIDGE | {"filetype": 2}, BRIDGE | {"cpu_type": 7}, BRIDGE | {"cpu_subtype": 1}])
def test_loaded_protocol_must_match_expected_helper_type_and_cpu(identity):
    assert not parse(records(), identity=identity)["valid"]


@pytest.mark.parametrize("mode,operation", [("dns_simple", 0), ("dns_shared", 1)])
def test_python_child_forwards_one_typed_cdll_call(mode, operation, tmp_path, monkeypatch, capsys):
    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    calls, loads = [], []

    def native(value):
        calls.append(value)
        print(wire(records(mode)[5:-3]).decode("ascii"), end="", flush=True)
        return 0

    def identities(a, b, c, capacity):
        assert capacity == 33
        for buffer, value in zip((a, b, c), IMAGES.values(), strict=True):
            buffer.value = value.encode("ascii")
        return 0

    library = SimpleNamespace(
        hol_guard_dnssd_python_call=Function(native), hol_guard_resolver_bridge_identity=Function(identities)
    )
    monkeypatch.setattr(child, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(child, "file_sha", lambda _: BRIDGE["sha256"])
    monkeypatch.setattr(child.os, "getpid", lambda: 123)
    monkeypatch.setattr(child.ctypes, "CDLL", lambda path: loads.append(path) or library)
    bridge = tmp_path / "bridge"
    assert child.execute(mode, bridge, BRIDGE["sha256"]) == 0
    output = capsys.readouterr()
    assert not output.err and calls == [operation] and loads == [str(bridge)]
    assert library.hol_guard_dnssd_python_call.argtypes == [child.ctypes.c_uint]
    assert library.hol_guard_dnssd_python_call.restype == child.ctypes.c_int
    assert evidence.parse_trace(output.out.encode(), mode, 123, RUNTIME, BRIDGE, python=True)["loopback_label"]
