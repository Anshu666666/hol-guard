"""New signal records preserve the original endpoint validator and owned call ABI."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_dnssd_sigpipe_child as child
from scripts.ci.native_macos_dnssd_sigpipe_evidence import parse_signal
from tests.test_native_macos_dnssd_endpoint import BINARY, BRIDGE, FLAGS
from tests.test_native_macos_dnssd_endpoint import RUNTIME as OLD_RUNTIME
from tests.test_native_macos_dnssd_endpoint import records as endpoint_records
from tests.test_native_macos_dnssd_python import IMAGES, wire

RUNTIME = OLD_RUNTIME | {child.RUNTIME_KEY: "9" * 64}


def state(stage, sequence, requested, initial):
    return {
        "kind": "sigpipe_condition",
        "sequence": sequence,
        "stage": stage,
        "requested": requested,
        "pid": 123,
        "main_thread": 1,
        "active": stage not in ("before", "restored"),
        "action_rc": 0,
        "action_errno": 0,
        "handler_kind": initial if stage in ("before", "restored") else requested,
        "flags": 0,
        "action_mask": "0",
        "action_mask_rc": 0,
        "blocked_mask": "0",
        "blocked_mask_rc": 0,
        "mask_rc": 0,
        "set_called": stage in ("installed", "restored"),
        "set_rc": 0,
        "set_errno": 0,
    }


def records(context="python", condition="ignore", mode="dns_simple"):
    rows = endpoint_records(context, mode)
    requested, initial = int(condition == "ignore"), int(context == "python")
    if context == "python":
        rows[0][child.RUNTIME_KEY] = rows[-1][child.RUNTIME_KEY] = RUNTIME[child.RUNTIME_KEY]
    first = 1 if context == "native_dlopen" else 3
    rows[first:first] = [state("before", 1, requested, initial), state("installed", 2, requested, initial)]
    index = next(index for index, row in enumerate(rows) if row["kind"] == "endpoint_context")
    rows[index]["pipe_kind"] = requested
    rows[index + 1 : index + 1] = [
        state("query", 3, requested, initial),
        {
            "kind": "sigpipe_socket",
            "sequence": 1,
            "pid": 123,
            "fd": rows[index]["fd"],
            "rc": 0,
            "errno": 0,
            "length": 4,
            "integer_bytes": 4,
            "value": 4096,
        },
    ]
    result = next(index for index, row in enumerate(rows) if row["kind"] == "result")
    rows[result + 1 : result + 1] = [state("after", 4, requested, initial), state("restored", 5, requested, initial)]
    return rows


def parse(rows, context="python", condition="ignore", mode="dns_simple"):
    return parse_signal(wire(rows), mode, 123, RUNTIME, context, BINARY, BRIDGE, FLAGS, condition)


@pytest.mark.parametrize("context", ("native_dlopen", "python"))
@pytest.mark.parametrize("condition", ("default", "ignore"))
@pytest.mark.parametrize("mode", ("dns_simple", "dns_shared"))
def test_each_declared_condition_remains_bound_to_the_original_protocol(context, condition, mode):
    result = parse(records(context, condition, mode), context, condition, mode)
    assert result["valid"] and result["complete"] and result["loopback_label"]
    assert result["condition"]["admitted"] and result["condition"]["restoration_observed"]
    assert result["condition"]["socket"]["value"] == 4096
    assert result["endpoint"]["pipe_kind"] == int(condition == "ignore")
    assert result["endpoint"]["observation_complete"]
    assert all(row["kind"] not in ("sigpipe_condition", "sigpipe_socket") for row in result["records"])
    assert result["condition"]["loader_initialization_condition_claimed"] is False
    assert result["condition"]["SO_NOSIGPIPE_modified"] is False


@pytest.mark.parametrize("context", ("native_dlopen", "python"))
@pytest.mark.parametrize("condition", ("default", "ignore"))
def test_pending_poll_retains_missing_post_query_and_restore_evidence(context, condition):
    rows = records(context, condition)
    index = next(index for index, row in enumerate(rows) if row["kind"] == "call_trace")
    result = parse(rows[: index + 1], context, condition)
    assert result["valid"] and not result["complete"]
    assert result["pending_call"] == "poll" and result["condition"]["admitted"]
    assert result["condition"]["post_query_observed"] is False
    assert result["condition"]["restoration_observed"] is False


@pytest.mark.parametrize(
    "mutation",
    (
        "moved_install",
        "changed_mask",
        "changed_flags",
        "wrong_handler",
        "socket_error",
        "socket_length",
        "missing_restore",
        "wrong_image",
    ),
)
def test_changed_conditions_or_unbound_observations_are_retained_and_refused(mutation):
    rows = records()
    states = {row["stage"]: row for row in rows if row["kind"] == "sigpipe_condition"}
    socket = next(row for row in rows if row["kind"] == "sigpipe_socket")
    if mutation == "moved_install":
        index = rows.index(states["installed"])
        rows.insert(index + 2, rows.pop(index))
    elif mutation == "changed_mask":
        states["query"]["action_mask"] = "1"
    elif mutation == "changed_flags":
        states["query"]["flags"] = 2
    elif mutation == "wrong_handler":
        states["installed"]["handler_kind"] = 0
    elif mutation == "socket_error":
        socket.update(rc=-1, errno=13)
    elif mutation == "socket_length":
        socket["length"] = 8
    elif mutation == "missing_restore":
        rows.remove(states["restored"])
    else:
        next(row for row in rows if row["kind"] == "endpoint_context")["images"]["observer"] = "0" * 32
    result = parse(rows)
    assert not result["valid"] and not result["complete"]
    assert result["condition_records"] and result["error_type"] == "ValueError"


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *arguments):
        return self.callback(*arguments)


def library(monkeypatch, events, failure=None):
    def operation(name, value=None):
        events.append((name, value))
        if failure == name:
            if name == "query":
                raise ValueError("owned query refusal")
            return 3
        return 0

    def identity(a, b, c, capacity):
        assert capacity == 33
        events.append(("identity", capacity))
        for buffer, value in zip((a, b, c), IMAGES.values(), strict=True):
            buffer.value = value.encode("ascii")
        return 0

    value = SimpleNamespace(
        hol_guard_endpoint_configure=Function(lambda context, flags: operation("configure", (context, flags))),
        hol_guard_sigpipe_enter=Function(lambda condition: operation("enter", condition)),
        hol_guard_sigpipe_leave=Function(lambda: operation("leave")),
        hol_guard_dnssd_python_call=Function(lambda mode: operation("query", mode)),
        hol_guard_resolver_bridge_identity=Function(identity),
    )
    monkeypatch.setattr(child, "runtime_identity", lambda: copy.deepcopy(RUNTIME))
    monkeypatch.setattr(child, "file_sha", lambda _: BRIDGE["sha256"])
    monkeypatch.setattr(child.ctypes, "CDLL", lambda path, mode: events.append(("load", (path, mode))) or value)
    return value


@pytest.mark.parametrize("condition,requested", (("default", 0), ("ignore", 1)))
@pytest.mark.parametrize("mode,operation", (("dns_simple", 0), ("dns_shared", 1)))
def test_python_calls_the_shared_condition_abi_once_around_the_original_query(
    monkeypatch,
    tmp_path,
    capsys,
    condition,
    requested,
    mode,
    operation,
):
    events = []
    value = library(monkeypatch, events)
    image = tmp_path / "same-image.dylib"
    assert child.execute(mode, image, BRIDGE["sha256"], condition) == 0
    assert [name for name, _ in events] == ["load", "configure", "enter", "identity", "query", "leave", "identity"]
    assert events[0][1] == (str(image), child.os.RTLD_NOW | child.os.RTLD_LOCAL)
    assert events[2] == ("enter", requested) and events[4] == ("query", operation)
    assert value.hol_guard_sigpipe_enter.argtypes == [child.ctypes.c_uint]
    assert value.hol_guard_sigpipe_enter.restype == child.ctypes.c_int
    assert value.hol_guard_sigpipe_leave.argtypes == [] and value.hol_guard_sigpipe_leave.restype == child.ctypes.c_int
    assert value.hol_guard_dnssd_python_call.argtypes == [child.ctypes.c_uint]
    assert value.hol_guard_dnssd_python_call.restype == child.ctypes.c_int
    assert not capsys.readouterr().err


@pytest.mark.parametrize("failure", ("enter", "query", "leave"))
def test_owned_python_failure_attempts_restoration_once_without_replaying_query(monkeypatch, tmp_path, capsys, failure):
    events = []
    library(monkeypatch, events, failure)
    assert child.execute("dns_simple", tmp_path / "image", BRIDGE["sha256"], "default") == 3
    names = [name for name, _ in events]
    assert names.count("leave") == 1 and names.count("query") == (0 if failure == "enter" else 1)
    assert '"kind": "failure"' in capsys.readouterr().out
