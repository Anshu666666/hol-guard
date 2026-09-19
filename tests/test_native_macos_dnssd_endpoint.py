"""New endpoint/loader evidence remains subordinate to the original query protocol."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_dnssd_endpoint_child as child
from scripts.ci.native_macos_dnssd_endpoint_evidence import parse_context
from tests.test_native_macos_dnssd_phase import BINARY, BRIDGE, RUNTIME as OLD_RUNTIME, records as old_records
from tests.test_native_macos_dnssd_python import IMAGES, wire

RUNTIME = OLD_RUNTIME | {child.RUNTIME_KEY: "e" * 64}
FLAGS = 6


def records(context="python", mode="dns_simple"):
    rows = copy.deepcopy(old_records(mode, "python" if context == "python" else "standalone"))
    native = next(row for row in rows if row["kind"] == "identity")
    index = next(index for index, row in enumerate(rows) if row["kind"] == "query") + 1
    address = bytes((25, 1)) + b"/var/run/mDNSResponder\0"
    socket_stat = {"rc": 0, "errno": 0, "dev": "1", "ino": "2", "mode": 0o140777}
    snapshot = {
        "kind": "endpoint_context", "sequence": 1, "context": ("standalone", "native_dlopen", "python").index(context),
        "configured": True, "loader_flags": 0 if context == "standalone" else FLAGS, "fd": 7, "pid": 123, "ppid": 122,
        "uid": 501, "euid": 501, "gid": 20, "egid": 20, "main_thread": 1, "thread_rc": 0, "thread_id": "7",
        "mask_rc": 0, "blocked_signals": "0", "pipe_rc": 0, "pipe_errno": 0, "pipe_kind": 0, "images_ok": True,
        "images": {"main": BINARY["uuid"], "observer": BRIDGE["uuid"], "query": native["dnssd_uuid"],
                   "descriptor": "d" * 32, "process": "d" * 32, "poll": "f" * 32},
        "stat_before": dict(socket_stat), "stat_after": dict(socket_stat),
        "fd_flags": {"rc": 1, "errno": 0}, "status_flags": {"rc": 2, "errno": 0},
        "socket_type": {"rc": 0, "errno": 0, "length": 4, "value": 1},
        "local": {"rc": 0, "errno": 0, "length": 2, "captured": 2, "hex": "0201"},
        "peer": {"rc": 0, "errno": 0, "length": len(address), "captured": len(address), "hex": address.hex()},
    }
    rows.insert(index, snapshot)
    if context == "python":
        rows[0][child.RUNTIME_KEY] = rows[-1][child.RUNTIME_KEY] = RUNTIME[child.RUNTIME_KEY]
    if context == "native_dlopen":
        images = {"bridge_uuid": BRIDGE["uuid"], "libinfo_uuid": native["libinfo_uuid"], "dnssd_uuid": native["dnssd_uuid"]}
        rows = [
            {"kind": "native_host", "phase": "load_enter", "pid": 123, "mode": mode, "loader_flags": FLAGS},
            {"kind": "native_host", "phase": "call_enter", **images},
            *rows, {"kind": "native_host", "phase": "complete", "return_code": 0, **images},
        ]
    return rows


def parse(rows, context="python", mode="dns_simple"):
    return parse_context(wire(rows), mode, 123, RUNTIME, context, BINARY, BINARY if context == "standalone" else BRIDGE, FLAGS)


def endpoint(rows):
    return next(row for row in rows if row["kind"] == "endpoint_context")


@pytest.mark.parametrize("context", ("standalone", "native_dlopen", "python"))
@pytest.mark.parametrize("mode", ("dns_simple", "dns_shared"))
def test_same_inner_protocol_is_required_and_raw_endpoint_is_not_exported(context, mode):
    observed = parse(records(context, mode), context, mode)
    assert observed["valid"] and observed["complete"] and observed["loopback_label"]
    snapshot = observed["endpoint"]
    assert snapshot["observation_complete"] and snapshot["peer"]["unix_mdnsresponder_path"]
    assert "hex" not in snapshot["peer"] and "hex" not in snapshot["local"]
    assert all(row["kind"] != "endpoint_context" for row in observed["records"])
    assert snapshot["same_OFD_claimed"] is snapshot["atomic_fd_snapshot_claimed"] is snapshot["daemon_acceptance_claimed"] is False


@pytest.mark.parametrize("context", ("standalone", "native_dlopen", "python"))
@pytest.mark.parametrize("mode", ("dns_simple", "dns_shared"))
def test_new_pending_poll_keeps_the_original_failure_boundary(context, mode):
    rows = records(context, mode)
    first = next(index for index, row in enumerate(rows) if row["kind"] == "call_trace")
    observed = parse(rows[:first + 1], context, mode)
    assert observed["valid"] and not observed["complete"] and not observed["loopback_label"]
    assert observed["pending_call"] == "poll" and observed["endpoint"]["observation_complete"]


@pytest.mark.parametrize("kind", ("missing", "duplicate", "moved", "overflow", "fd_mismatch"))
def test_snapshot_cannot_float_between_other_call_boundaries(kind):
    rows = records()
    index = rows.index(endpoint(rows))
    if kind == "missing":
        del rows[index]
    elif kind == "duplicate":
        rows.insert(index, copy.deepcopy(rows[index]))
    elif kind == "moved":
        rows.insert(index + 2, rows.pop(index))
    elif kind == "overflow":
        rows.insert(index + 1, {"kind": "endpoint_overflow"})
    else:
        rows[index]["fd"] = 8
    assert not parse(rows)["valid"]


@pytest.mark.parametrize("key,value", [
    ("context", True), ("configured", 1), ("loader_flags", 0), ("pid", 124), ("fd", True),
    ("uid", -1), ("thread_id", "01"), ("thread_id", str(2**64)), ("blocked_signals", []),
    ("main_thread", True), ("pipe_kind", 3), ("images_ok", "true"), ("sequence", True),
])
def test_malformed_snapshot_fields_cannot_earn_an_observation(key, value):
    rows = records()
    endpoint(rows)[key] = value
    assert not parse(rows)["valid"]


@pytest.mark.parametrize("mutation", ("address_length", "address_hex", "observer_image", "new_runtime", "unknown_field"))
def test_endpoint_bytes_loaded_image_and_runtime_source_are_bound(mutation):
    rows = records()
    snapshot = endpoint(rows)
    if mutation == "address_length":
        snapshot["peer"]["captured"] = 129
    elif mutation == "address_hex":
        snapshot["peer"]["hex"] += "ff"
    elif mutation == "observer_image":
        snapshot["images"]["observer"] = "0" * 32
    elif mutation == "new_runtime":
        rows[0][child.RUNTIME_KEY] = "0" * 64
    else:
        snapshot["unowned_data"] = "not admitted"
    assert not parse(rows)["valid"]


@pytest.mark.parametrize("mutation", ("stat_changed", "peer_denied", "image_unavailable", "thread_error"))
def test_metadata_failure_is_retained_without_claiming_complete_observation(mutation):
    rows = records()
    snapshot = endpoint(rows)
    if mutation == "stat_changed":
        snapshot["stat_after"]["ino"] = "3"
    elif mutation == "peer_denied":
        snapshot["peer"] = {"rc": -1, "errno": 13, "length": 128, "captured": 0, "hex": ""}
    elif mutation == "image_unavailable":
        snapshot["images_ok"] = False
        snapshot["images"]["main"] = ""
    else:
        snapshot["thread_rc"] = 22
    observed = parse(rows)
    assert observed["valid"] and not observed["endpoint"]["observation_complete"]


@pytest.mark.parametrize("mutation", ("flags", "bridge", "return", "completion_order"))
def test_native_host_must_bind_the_same_held_image_before_and_after(mutation):
    rows = records("native_dlopen")
    if mutation == "flags":
        rows[0]["loader_flags"] = 0
    elif mutation == "bridge":
        rows[1]["bridge_uuid"] = "0" * 32
    elif mutation == "return":
        rows[-1]["return_code"] = 2
    else:
        rows.insert(2, rows.pop())
    assert not parse(rows, "native_dlopen")["valid"]


@pytest.mark.parametrize("raw", [b"[]\n", b'{"kind":1,"kind":2}\n', b"\xff\n", b"x" * 16385])
def test_malformed_or_censored_raw_input_is_refused(raw):
    assert not parse_context(raw, "dns_simple", 123, RUNTIME, "python", BINARY, BRIDGE, FLAGS)["valid"]


@pytest.mark.parametrize("mode,operation", (("dns_simple", 0), ("dns_shared", 1)))
def test_python_child_preserves_actual_cdll_abi_loader_flags_and_single_query(mode, operation, tmp_path, monkeypatch, capsys):
    class Function:
        def __init__(self, callback):
            self.callback = callback
        def __call__(self, *arguments):
            return self.callback(*arguments)

    calls, loads, configurations = [], [], []
    def identity(a, b, c, capacity):
        assert capacity == 33
        for buffer, value in zip((a, b, c), IMAGES.values(), strict=True):
            buffer.value = value.encode("ascii")
        return 0

    library = SimpleNamespace(
        hol_guard_endpoint_configure=Function(lambda context, flags: configurations.append((context, flags)) or 0),
        hol_guard_dnssd_python_call=Function(lambda value: calls.append(value) or 0),
        hol_guard_resolver_bridge_identity=Function(identity),
    )
    monkeypatch.setattr(child, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(child, "file_sha", lambda _: BRIDGE["sha256"])
    monkeypatch.setattr(child.ctypes, "CDLL", lambda path, mode: loads.append((path, mode)) or library)
    bridge = tmp_path / "bridge"
    assert child.execute(mode, bridge, BRIDGE["sha256"]) == 0
    output = capsys.readouterr()
    assert not output.err
    flags = child.os.RTLD_NOW | child.os.RTLD_LOCAL
    assert loads == [(str(bridge), flags)] and configurations == [(2, flags)] and calls == [operation]
    assert library.hol_guard_endpoint_configure.argtypes == [child.ctypes.c_uint, child.ctypes.c_int]
    assert library.hol_guard_dnssd_python_call.argtypes == [child.ctypes.c_uint]
    assert library.hol_guard_dnssd_python_call.restype == child.ctypes.c_int
