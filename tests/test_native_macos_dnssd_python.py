"""Bounded DNS-SD-in-Python protocol and native-call forwarding controls."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_dnssd_python_child as child
from scripts.ci import native_macos_dnssd_python_evidence as evidence

RUNTIME = {key: "a" * 64 for key in evidence.RUNTIME_KEYS}
BRIDGE = {"sha256": "b" * 64, "uuid": "c" * 32, "cpu_type": 16777228, "cpu_subtype": 0}
IMAGES = {"bridge_uuid": BRIDGE["uuid"], "libinfo_uuid": "d" * 32, "dnssd_uuid": "e" * 32}


def records(mode="dns_simple"):
    return [
        {"kind": "python_identity", "mode": mode, "pid": 123, "call_policy": child.CALL_POLICY, **RUNTIME},
        {"kind": "phase", "phase": "before_load"},
        {"kind": "phase", "phase": "after_load"},
        {"kind": "bridge_image", "phase": "before", **IMAGES},
        {"kind": "phase", "phase": "call_enter"},
        {
            "kind": "identity",
            "mode": mode,
            "pid": 123,
            "cpu_type": BRIDGE["cpu_type"],
            "cpu_subtype": 0,
            "libinfo_uuid": IMAGES["libinfo_uuid"],
            "dnssd_uuid": IMAGES["dnssd_uuid"],
        },
        {
            "kind": "query",
            "shared": mode == "dns_shared",
            "requested_flags": 0x15000 if mode == "dns_shared" else 0,
            "error": 0,
        },
        {
            "kind": "callback",
            "sequence": 1,
            "flags": 0x40000002,
            "interface_index": 0xFFFFFFFF,
            "error": 0,
            "type": 12,
            "class": 1,
            "data_bytes": 11,
            "question_matches": True,
            "loopback_label": True,
        },
        {"kind": "result", "error": 0, "callback_error": 0, "callbacks": 1, "overflow": False, "loopback_label": True},
        {"kind": "phase", "phase": "call_return"},
        {"kind": "bridge_image", "phase": "after", **IMAGES},
        {"kind": "python_complete", "return_code": 0, "bridge_sha256": BRIDGE["sha256"], **RUNTIME},
    ]


def wire(rows):
    return b"".join(json.dumps(row).encode("ascii") + b"\n" for row in rows)


def parse(rows, mode="dns_simple"):
    return evidence.parse_comparison(wire(rows), mode, 123, RUNTIME, BRIDGE)


@pytest.mark.parametrize("mode", child.MODES)
def test_complete_sequence_and_every_incomplete_prefix(mode):
    rows = records(mode)
    assert parse(rows, mode)["loopback_label"]
    for count in range(1, len(rows)):
        result = parse(rows[:count], mode)
        assert result["valid"] and not result["complete"] and not result["loopback_label"]
    assert not evidence.parse_comparison(wire(rows)[:-1], mode, 123, RUNTIME, BRIDGE)["complete"]


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "pid", 124),
        (0, "pid", True),
        (0, "call_policy", "PyDLL"),
        (0, "dnssd_child_source_sha256", "f" * 64),
        (0, "child_source_sha256", "f" * 64),
        (1, "phase", "call_enter"),
        (3, "bridge_uuid", "f" * 32),
        (5, "mode", "dns_shared"),
        (5, "pid", 124),
        (5, "cpu_type", 7),
        (5, "dnssd_uuid", "f" * 32),
        (6, "requested_flags", 0x15000),
        (6, "shared", True),
        (7, "sequence", 2),
        (7, "type", 1),
        (7, "class", 2),
        (7, "data_bytes", 12),
        (7, "question_matches", False),
        (8, "callbacks", 2),
        (8, "callback_error", -1),
        (9, "phase", "call_enter"),
        (10, "libinfo_uuid", "f" * 32),
        (11, "bridge_sha256", "f" * 64),
        (11, "return_code", 2),
        (11, "ctypes_sha256", "f" * 64),
    ],
)
def test_mutation_of_an_admitted_sequence_is_rejected(index, key, value):
    rows = records()
    assert parse(rows)["complete"]
    rows[index][key] = value
    assert parse(rows)["records"] == []


@pytest.mark.parametrize(
    "count,stage",
    [
        (1, "before_load"),
        (2, "after_load"),
        (3, "after_load"),
        (4, "call_enter"),
        (5, "call_enter"),
        (7, "call_enter"),
        (9, "call_return"),
        (10, "call_return"),
        (11, "final_binding"),
    ],
)
def test_reachable_failure_prefix_retains_original_failure(count, stage):
    prefix = records()[:count]
    assert parse(prefix)["valid"]
    result = parse([*prefix, {"kind": "failure", "stage": stage, "error_type": "OSError"}])
    assert result["valid"] and not result["complete"]


@pytest.mark.parametrize(
    "count,stage",
    [
        (1, "final_binding"),
        (2, "call_return"),
        (3, "call_enter"),
        (4, "before_load"),
        (5, "final_binding"),
        (7, "call_return"),
        (10, "final_binding"),
        (11, "before_load"),
    ],
)
def test_unreachable_failure_stage_is_refused(count, stage):
    prefix = records()[:count]
    assert parse(prefix)["valid"]
    assert not parse([*prefix, {"kind": "failure", "stage": stage, "error_type": "ValueError"}])["valid"]


@pytest.mark.parametrize("index", range(12))
def test_private_metadata_never_survives_rejection(index):
    rows = records()
    rows[index]["private_data"] = "private.example.invalid"
    assert parse(rows)["records"] == []


@pytest.mark.parametrize(
    "raw", [b"[]\n", b"{}\n", b'{"kind":1,"kind":2}\n', b"\xff\n", b"x" * 16385, b"[" * 2000 + b"]" * 2000 + b"\n"]
)
def test_malformed_or_oversized_protocol_is_refused(raw):
    assert evidence.parse_comparison(raw, "dns_simple", 123, RUNTIME, BRIDGE)["records"] == []


def test_callback_batch_limit_is_not_vacuous():
    rows = records()
    callbacks = []
    for index in range(16):
        callback = copy.deepcopy(rows[7])
        callback.update(sequence=index + 1, flags=0x40000003 if index < 15 else 0x40000002)
        callbacks.append(callback)
    bounded = [*rows[:7], *callbacks, {**rows[8], "callbacks": 16}, *rows[9:]]
    assert parse(bounded)["loopback_label"]
    overflow = copy.deepcopy(bounded)
    overflow.insert(23, {**callbacks[-1], "sequence": 17})
    assert not parse(overflow)["valid"]
    callbacks[-1]["flags"] |= 1
    assert not parse([*rows[:7], *callbacks, {**rows[8], "callbacks": 16}, *rows[9:]])["loopback_label"]


def test_callback_error_remains_completed_unsuccessful_outcome():
    rows = records()
    rows[7].update(
        flags=0,
        interface_index=0,
        error=-65537,
        type=0,
        **{"class": 0},
        data_bytes=0,
        question_matches=False,
        loopback_label=False,
    )
    rows[8].update(callback_error=-65537, loopback_label=False)
    rows[11]["return_code"] = 2
    result = parse(rows)
    assert result["valid"] and result["complete"] and not result["loopback_label"]
    rows[7]["private_rdata"] = "secret"
    assert not parse(rows)["valid"]


@pytest.mark.parametrize("mode,operation", [("dns_simple", 0), ("dns_shared", 1)])
def test_child_calls_the_typed_cdll_function_once(mode, operation, tmp_path, monkeypatch, capsys):
    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    calls, loads = [], []

    def native(value):
        calls.append(value)
        for row in records(mode)[5:9]:
            print(json.dumps(row), flush=True)
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
    captured = capsys.readouterr()
    assert not captured.err and calls == [operation] and loads == [str(bridge)]
    assert library.hol_guard_dnssd_python_call.argtypes == [child.ctypes.c_uint]
    assert library.hol_guard_dnssd_python_call.restype == child.ctypes.c_int
    result = evidence.parse_comparison(captured.out.encode(), mode, 123, RUNTIME, BRIDGE)
    assert result["complete"] and result["loopback_label"]


def test_load_failure_is_bounded_and_does_not_call_native(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(child, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(child, "file_sha", lambda _: BRIDGE["sha256"])
    monkeypatch.setattr(child.os, "getpid", lambda: 123)

    def fail(_):
        raise OSError("private path message")

    monkeypatch.setattr(child.ctypes, "CDLL", fail)
    assert child.execute("dns_simple", tmp_path / "bridge", BRIDGE["sha256"]) == 3
    out = capsys.readouterr().out
    assert "private" not in out
    result = evidence.parse_comparison(out.encode(), "dns_simple", 123, RUNTIME, BRIDGE)
    assert result["valid"] and not result["complete"]
