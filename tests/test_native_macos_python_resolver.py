"""Finite identity, forwarding, phase, privacy and failure controls; no Mac claims."""

from __future__ import annotations

import copy
import hashlib
import json
import shlex
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_python_resolver_child as child
from scripts.ci import native_macos_python_resolver_evidence as evidence
from scripts.ci import native_macos_python_resolver_path as collector

RUNTIME = {key: "a" * 64 for key in evidence.RUNTIME_KEYS}
BRIDGE = {"sha256": "b" * 64, "uuid": "c" * 32, "cpu_type": 16777228, "cpu_subtype": 0}
IMAGES = {"bridge_uuid": BRIDGE["uuid"], "libinfo_uuid": "d" * 32, "dnssd_uuid": "e" * 32}


def records(mode):
    identity = {"kind": "python_identity", "mode": mode, "pid": 123, **RUNTIME}
    complete = {"kind": "python_complete", "return_code": 0, "bridge_sha256": "", **RUNTIME}
    enter, leave = {"kind": "phase", "phase": "call_enter"}, {"kind": "phase", "phase": "call_return"}
    if mode.startswith("socket_"):
        return [
            identity,
            enter,
            {"kind": "socket_result", "error_kind": "none", "error_code": 0, "loopback_label": True},
            leave,
            complete,
        ]
    complete["bridge_sha256"] = BRIDGE["sha256"]
    return [
        identity,
        {"kind": "phase", "phase": "before_load"},
        {"kind": "phase", "phase": "after_load"},
        {"kind": "bridge_image", "phase": "before", **IMAGES},
        enter,
        {
            "kind": "identity",
            "mode": "libc_name" if mode == "c_name" else "libc_addr",
            "pid": 123,
            "libinfo_uuid": IMAGES["libinfo_uuid"],
            "dnssd_uuid": IMAGES["dnssd_uuid"],
            "cpu_type": BRIDGE["cpu_type"],
            "cpu_subtype": 0,
        },
        {"kind": "result", "error": 0, "loopback_label": True},
        leave,
        {"kind": "bridge_image", "phase": "after", **IMAGES},
        complete,
    ]


def wire(rows):
    return b"".join(json.dumps(row).encode("ascii") + b"\n" for row in rows)


def parse(rows, mode="c_addr"):
    return evidence.parse_comparison(wire(rows), mode, 123, RUNTIME, BRIDGE)


@pytest.mark.parametrize("mode", evidence.MODES)
def test_complete_bound_rows_and_every_prefix_are_distinct(mode):
    rows = records(mode)
    assert parse(rows, mode)["loopback_label"]
    for count in range(1, len(rows)):
        result = parse(rows[:count], mode)
        assert result["valid"] and not result["complete"] and not result["loopback_label"]
    partial = evidence.parse_comparison(wire(rows)[:-1], mode, 123, RUNTIME, BRIDGE)
    assert partial["valid"] and not partial["complete"]


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "pid", 124),
        (0, "python_sha256", "f" * 64),
        (0, "ctypes_sha256", "f" * 64),
        (0, "child_source_sha256", "f" * 64),
        (1, "phase", "call_enter"),
        (3, "bridge_uuid", "f" * 32),
        (5, "pid", 124),
        (5, "mode", "libc_name"),
        (5, "cpu_type", 7),
        (5, "libinfo_uuid", "f" * 32),
        (6, "error", True),
        (8, "dnssd_uuid", "f" * 32),
        (9, "bridge_sha256", "f" * 64),
        (9, "return_code", 2),
        (9, "socket_sha256", "f" * 64),
    ],
)
def test_wrong_identity_phase_or_outcome_cannot_be_admitted(index, key, value):
    rows = records("c_addr")
    assert parse(rows)["complete"]
    rows[index][key] = value
    result = parse(rows)
    assert not result["valid"] and result["records"] == []


@pytest.mark.parametrize("mode", evidence.MODES)
def test_private_fields_and_extra_records_are_never_exported(mode):
    rows = records(mode)
    rows[0]["private_hostname"] = "private.example.invalid"
    assert parse(rows, mode)["records"] == []
    assert not parse([*records(mode), {"kind": "private", "path": "/private"}], mode)["valid"]


@pytest.mark.parametrize(
    "raw", [b"{}\n", b"[]\n", b'{"kind":1,"kind":2}\n', b"x" * 16385, b"\xff\n", b"[" * 2000 + b"]" * 2000 + b"\n"]
)
def test_malformed_and_oversized_wire_is_rejected(raw):
    assert evidence.parse_comparison(raw, "c_addr", 123, RUNTIME, BRIDGE)["records"] == []


def test_fixed_failure_prefix_retains_stage_without_completion():
    rows = [*records("c_addr")[:2], {"kind": "failure", "stage": "before_load", "error_type": "OSError"}]
    result = parse(rows)
    assert result["valid"] and not result["complete"] and result["records"][-1]["stage"] == "before_load"
    rows[-1]["error_type"] = {"private": "message"}
    assert not parse(rows)["valid"]
    socket_rows = records("socket_addr")
    socket_rows[2]["error_kind"] = []
    assert not parse(socket_rows, "socket_addr")["valid"]


@pytest.mark.parametrize(
    "length,stage",
    [(2, "final_binding"), (3, "call_return"), (4, "before_load"), (5, "final_binding"), (8, "before_load")],
)
def test_failure_cannot_attest_an_unreachable_stage(length, stage):
    prefix = records("c_addr")[:length]
    assert parse(prefix)["valid"]
    assert not parse([*prefix, {"kind": "failure", "stage": stage, "error_type": "ValueError"}])["valid"]


def macho(commands=None, **header):
    commands = struct.pack("<II", 0x1B, 24) + bytes.fromhex(BRIDGE["uuid"]) if commands is None else commands
    fields = {
        "magic": 0xFEEDFACF,
        "cpu": BRIDGE["cpu_type"],
        "subtype": 0,
        "filetype": 6,
        "count": 1,
        "size": len(commands),
        "flags": 0,
        "reserved": 0,
    } | header
    return struct.pack("<IiiIIIII", *fields.values()) + commands


def test_actual_file_bridge_hash_and_bounded_uuid_are_bound(tmp_path):
    path = tmp_path / "bridge"
    data = macho() + b"executable section bytes"
    path.write_bytes(data)
    result = collector.bridge_identity(path)
    assert result == BRIDGE | {"sha256": hashlib.sha256(data).hexdigest()}
    assert child.file_sha(path) == result["sha256"]


def test_report_read_swap_cannot_bind_middle_bytes_to_matching_outer_hashes(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    first, middle = b'{"value":"first"}', b'{"value":"private-middle"}'
    path.write_bytes(first)
    expected = hashlib.sha256(first).hexdigest()
    assert collector.read_report(path) == ({"value": "first"}, expected)
    original_sha, hashes = collector.file_sha, []

    def swap(source, maximum):
        if hashes:
            source.write_bytes(first)
        digest = original_sha(source, maximum=maximum)
        if not hashes:
            source.write_bytes(middle)
        hashes.append(digest)
        return digest

    monkeypatch.setattr(collector, "file_sha", swap)
    with pytest.raises(ValueError, match="report boundary"):
        collector.read_report(path)
    assert hashes == [expected, expected] and path.read_bytes() == first


@pytest.mark.parametrize(
    "data",
    [
        b"",
        macho(magic=0xCAFEBABE),
        macho(filetype=2),
        macho(count=1025),
        macho(size=100),
        macho(struct.pack("<II", 0x1B, 32) + bytes(16)),
        macho(struct.pack("<II", 1, 8)),
        macho((struct.pack("<II", 0x1B, 24) + bytes(16)) * 2, count=2),
        macho(struct.pack("<II", 0x1B, 0)),
        macho() + b"hidden",
        b"x" * (1024 * 1024 + 33),
    ],
)
def test_macho_identity_refuses_unsupported_or_ambiguous_headers(data):
    with pytest.raises(ValueError):
        evidence.macho_identity(data)


@pytest.fixture
def child_harness(monkeypatch):
    monkeypatch.setattr(child, "runtime_identity", lambda: RUNTIME.copy())
    monkeypatch.setattr(child.os, "getpid", lambda: 123)
    monkeypatch.setattr(child, "file_sha", lambda _path: BRIDGE["sha256"])
    calls = []

    def addr(address):
        calls.append(("addr", address))
        return "localhost", ["private alias not exported"], [address]

    def name(address, flags):
        calls.append(("name", address, flags))
        return "localhost", "0"

    monkeypatch.setattr(child.socket, "gethostbyaddr", addr)
    monkeypatch.setattr(child.socket, "getnameinfo", name)
    return calls


@pytest.mark.parametrize("mode", ["socket_addr", "socket_name"])
def test_real_python_forwarding_matches_fixed_c_inputs(child_harness, capsys, mode):
    assert child.execute(mode, Path("/unused"), BRIDGE["sha256"]) == 0
    output = capsys.readouterr().out.encode()
    assert evidence.parse_comparison(output, mode, 123, RUNTIME, BRIDGE)["loopback_label"]
    expected = (
        [("addr", "127.0.0.1")]
        if mode == "socket_addr"
        else [("name", ("127.0.0.1", 0), child.socket.NI_NAMEREQD | child.socket.NI_NUMERICSERV)]
    )
    assert child_harness == expected and b"private" not in output


@pytest.mark.parametrize("mode", ["c_addr", "c_name"])
def test_bridge_calls_keep_original_return_and_before_after_images(child_harness, monkeypatch, capsys, mode):
    calls = []

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *values):
            return self.callback(*values)

    def image(*arguments):
        *buffers, capacity = arguments
        assert capacity == 33 and all(len(buffer) == 33 for buffer in buffers)
        for buffer, value in zip(buffers, IMAGES.values(), strict=True):
            buffer.value = value.encode("ascii")
        calls.append("image")
        return 0

    def call(operation):
        calls.append(operation)
        assert operation == int(mode == "c_name")
        for row in records(mode)[5:7]:
            child.emit(**row)
        return 0

    library = SimpleNamespace(
        hol_guard_resolver_call=Function(call), hol_guard_resolver_bridge_identity=Function(image)
    )
    monkeypatch.setattr(
        child.ctypes, "CDLL", lambda path: library if path == "/fixed/bridge" else pytest.fail("wrong bridge")
    )
    assert child.execute(mode, Path("/fixed/bridge"), BRIDGE["sha256"]) == 0
    result = evidence.parse_comparison(capsys.readouterr().out.encode(), mode, 123, RUNTIME, BRIDGE)
    assert result["loopback_label"] and calls == ["image", int(mode == "c_name"), "image"]
    assert library.hol_guard_resolver_call.argtypes == [child.ctypes.c_uint]
    assert library.hol_guard_resolver_call.restype is child.ctypes.c_int


def test_bridge_identity_buffers_reject_non_uuid_bytes_without_emission(capsys):
    def corrupt(*arguments):
        for buffer in arguments[:3]:
            buffer.value = b"private"
        return 0

    with pytest.raises(ValueError):
        child.bridge_image(SimpleNamespace(hol_guard_resolver_bridge_identity=corrupt), "before")
    assert capsys.readouterr().out == ""


def test_socket_error_is_preserved_without_private_exception_text(child_harness, monkeypatch, capsys):
    def fail(_address):
        raise child.socket.herror(1, "private hostname")

    monkeypatch.setattr(child.socket, "gethostbyaddr", fail)
    assert child.execute("socket_addr", Path("/unused"), BRIDGE["sha256"]) == 2
    output = capsys.readouterr().out.encode()
    result = evidence.parse_comparison(output, "socket_addr", 123, RUNTIME, BRIDGE)
    assert result["valid"] and result["complete"] and not result["loopback_label"]
    assert result["records"][2]["error_kind"] == "herror" and b"private" not in output


def test_changed_bridge_cannot_load_and_changed_runtime_cannot_complete(child_harness, monkeypatch, capsys):
    monkeypatch.setattr(child.ctypes, "CDLL", lambda _path: pytest.fail("must not load"))
    monkeypatch.setattr(child, "file_sha", lambda _path: "f" * 64)
    assert child.execute("c_addr", Path("/private"), BRIDGE["sha256"]) == 3
    output = capsys.readouterr().out.encode()
    assert parse(json.loads(line) for line in output.splitlines())["complete"] is False
    identities = iter([RUNTIME, RUNTIME | {"python_sha256": "f" * 64}])
    monkeypatch.setattr(child, "runtime_identity", lambda: next(identities))
    assert child.execute("socket_addr", Path("/unused"), BRIDGE["sha256"]) == 3
    assert b"python_complete" not in capsys.readouterr().out.encode()


@pytest.fixture
def collection(monkeypatch, tmp_path):
    state = {"calls": [], "failure": None, "cleanup": True, "changed": None, "saves": []}
    source = {
        "head": "a" * 40,
        "sha256": {str(collector.CHILD.relative_to(collector.original.ROOT)): RUNTIME["child_source_sha256"]},
    }
    tools = {"python_sha256": RUNTIME["python_sha256"], "python_socket_module_sha256": RUNTIME["socket_sha256"]}
    values = {"source": source, "tools": tools, "runtime": RUNTIME, "bridge": BRIDGE}
    counts = {key: 0 for key in values}

    def identity(key):
        counts[key] += 1
        result = copy.deepcopy(values[key])
        if state["changed"] == key and counts[key] > 1:
            result["changed"] = True
        return result

    monkeypatch.setattr(collector.original, "_eligible", lambda: True)
    monkeypatch.setattr(collector.original, "source_identity", lambda: identity("source"))
    monkeypatch.setattr(collector.original, "tool_identity", lambda: identity("tools"))
    monkeypatch.setattr(collector, "runtime_identity", lambda: identity("runtime"))
    monkeypatch.setattr(collector, "bridge_identity", lambda _path: identity("bridge"))

    def capture(arguments):
        mode = arguments[4]
        assert arguments == (
            sys.executable,
            "-I",
            str(collector.CHILD),
            "--mode",
            mode,
            "--bridge",
            str(tmp_path / "bridge"),
            "--bridge-sha256",
            BRIDGE["sha256"],
        )
        state["calls"].append(mode)
        failed = state["failure"] == mode
        result = {
            "status": "deadline_exceeded" if failed else "completed",
            "return_code": -9 if failed else 0,
            "pid": 123,
            "direct_child_reaped": state["cleanup"] if failed else True,
            "termination_attempted": failed,
            "stderr_bytes": 0,
        }
        return result, wire(records(mode)[:2] if failed else records(mode))

    monkeypatch.setattr(collector, "run_lookup", capture)
    prepared = collector.original._base() | {"status": "prepared", "source": source, "tools": tools}
    prior = collector.original._base() | {
        "status": "experiment_finished",
        "stage": "complete",
        "source_before": source,
        "tools_before": tools,
        "source_unchanged": True,
        "tools_unchanged": True,
        "binary_unchanged": True,
        "rows": [
            {"mode": mode, "capture": {"pid": 123, "direct_child_reaped": True}} for mode in collector.original.MODES
        ],
    }
    state["prior"] = prior
    state["prepared"] = prepared
    state["collect"] = lambda: collector.collect(
        prepared, tmp_path / "bridge", prior, lambda row: state["saves"].append(copy.deepcopy(row))
    )
    return state


def test_additional_controls_complete_with_all_bindings_without_qualification(collection):
    collection["prior"]["rows"][-1]["capture"].update(status="deadline_exceeded", return_code=-9)
    result = collection["collect"]()
    assert result["diagnostic_passed"] and collection["calls"] == list(evidence.MODES)
    assert not result["qualification_pass"] and not result["service_intervention_attempted"]
    assert not result["installed_baseline_startup_verified"] and not result["configuration_modified"]
    assert collection["prior"]["diagnostic_passed"] is False
    assert collection["prior"]["rows"][-1]["capture"]["return_code"] == -9


@pytest.mark.parametrize("fault", ["retirement", "missing_row", "unfinished", "binding", "source", "tools", "run"])
def test_unproved_original_report_prevents_any_additional_call(collection, fault):
    prior = collection["prior"]
    assert collector.original_admission(prior, collection["prepared"]) is None
    if fault == "retirement":
        prior["rows"][-1]["capture"]["direct_child_reaped"] = False
    elif fault == "missing_row":
        prior["rows"].pop()
    elif fault == "unfinished":
        prior["status"] = "direct_child_cleanup_unproved"
    elif fault == "binding":
        prior["tools_unchanged"] = False
    elif fault == "source":
        prior["source_before"] = {}
    elif fault == "tools":
        prior["tools_before"] = {"python_sha256": "f" * 64}
    else:
        prior["workflow_run"] = "other"
    result = collection["collect"]()
    assert result["status"] == "original_report_refused" and collection["calls"] == []


@pytest.mark.parametrize("mode", evidence.MODES)
def test_failed_call_is_retained_and_independent_suffix_continues(collection, mode):
    collection["failure"] = mode
    result = collection["collect"]()
    assert not result["diagnostic_passed"] and collection["calls"] == list(evidence.MODES)
    failed = next(row for row in result["rows"] if row["mode"] == mode)
    assert failed["capture"]["return_code"] == -9 and not failed["metadata"]["complete"]


def test_unreaped_lookup_stops_additional_suffix(collection):
    collection.update(failure="socket_name", cleanup=False)
    result = collection["collect"]()
    assert result["status"] == "direct_child_cleanup_unproved"
    assert collection["calls"] == ["socket_addr", "socket_name"]
    assert collection["saves"][-1]["rows"][-1]["capture"]["direct_child_reaped"] is False


@pytest.mark.parametrize("changed", ["source", "tools", "runtime", "bridge"])
def test_changed_final_binding_rejects_successful_calls(collection, changed):
    collection["changed"] = changed
    result = collection["collect"]()
    assert not result["diagnostic_passed"] and not result[changed + "_unchanged"]


@pytest.mark.parametrize("changed", ["workflow_commit", "workflow_run", "workflow_attempt", "tools"])
def test_stale_preparation_cannot_launch_additional_calls(collection, changed):
    collection["prepared"][changed] = "stale"
    assert not collection["collect"]()["diagnostic_passed"] and collection["calls"] == []


def test_bridge_workflow_is_separate_after_original_controls_and_source_bound():
    workflow = (collector.original.ROOT / ".github/workflows/native-macos-resolver-path.yml").read_text()
    original_index = workflow.index("        id: lookups\n")
    bridge_index = workflow.index("        id: bridge\n")
    assert original_index < workflow.index("        id: python_admission\n") < bridge_index
    build = workflow[bridge_index:].split("      - name:", 1)[0]
    assert "if: ${{ always() && steps.python_admission.outcome == 'success' }}" in build
    command = shlex.split(build.split("        run: |\n", 1)[1].replace("\\\n", ""))
    assert command == [
        "/usr/bin/xcrun",
        "--sdk",
        "macosx",
        "clang",
        *collector.BRIDGE_FLAGS,
        "scripts/ci/native_macos_python_resolver_bridge.c",
        "-o",
        "$RUNNER_TEMP/macos-resolver-path-build/resolver-bridge.dylib",
        ">",
        "$RUNNER_TEMP/macos-resolver-path-build/bridge.stdout",
        "2>",
        "$RUNNER_TEMP/macos-resolver-path-build/bridge.stderr",
    ]
    assert "if: ${{ always() && steps.bridge.outcome == 'success' }}" in workflow
    for name in ("bridge.c", "child.py", "evidence.py", "path.py"):
        assert "scripts/ci/native_macos_python_resolver_" + name in collector.original.SOURCES
    assert "tests/test_native_macos_python_resolver.py" in collector.original.SOURCES
