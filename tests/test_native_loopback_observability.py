from __future__ import annotations

import base64
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

import pytest

from scripts.ci import native_loopback_dns as dns
from scripts.ci import native_loopback_observability as observation
from scripts.ci import native_loopback_resolver as resolver


def _block(domain=dns.REVERSE_NAME, *, port=54321, server="127.0.0.1"):
    return f"resolver #1\n  domain : {domain}\n  nameserver[0] : {server}\n  port : {port}\n"


def test_registration_fields_must_come_from_same_exact_resolver_block():
    raw = "DNS configuration\n" + _block() + "\nresolver #2\n  domain : private.example\n"
    value = observation.registration_projection(raw.encode(), 54321)
    assert value == dict.fromkeys(
        ("exact_zone_present", "loopback_nameserver_only", "expected_port_present", "matching_registration_present"),
        True,
    )
    assert "private.example" not in json.dumps(value)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (_block(domain="other." + dns.REVERSE_NAME), (False, False, False, False)),
        (_block(server="192.0.2.1"), (True, False, True, False)),
        (_block(port=53), (True, True, False, False)),
        (_block(server="192.0.2.1") + _block(domain="private.example"), (True, False, True, False)),
        (_block() + " nameserver[1] : 192.0.2.1\n", (True, False, True, False)),
        (_block() + " port : 53\n", (True, True, False, False)),
    ],
)
def test_registration_never_combines_unrelated_fields_or_accepts_ambiguous_fields(raw, expected):
    value = observation.registration_projection(("DNS configuration\n" + raw).encode(), 54321)
    assert tuple(value.values()) == expected


def test_before_phase_cannot_claim_unknown_future_port_binding():
    value = observation.registration_projection(("DNS configuration\n" + _block()).encode(), None)
    assert value["exact_zone_present"] is True
    assert value["expected_port_present"] is None and value["matching_registration_present"] is None


@pytest.mark.parametrize("raw", [b"", b"arbitrary private error", b"\xff", b"x" * 65537])
def test_truncated_or_unrecognized_scutil_output_cannot_prove_absence(raw):
    with pytest.raises(ValueError):
        observation.registration_projection(raw, 54321)


def test_scutil_projection_never_publishes_raw_output_or_returned_names(monkeypatch):
    raw = ("DNS configuration\n" + _block() + " private_field : secret-name\n").encode()
    monkeypatch.setattr(observation, "_capture_scutil", lambda _deadline: ("completed", raw, b"private stderr", 0))
    public, private = observation.scutil_diagnostics(expected_port=54321, deadline=time.monotonic() + 5)
    assert public["matching_registration_present"] is True
    assert "secret-name" not in json.dumps(public) and "private stderr" not in json.dumps(public)
    assert base64.b64decode(private["stdout_base64"]) == raw
    assert base64.b64decode(private["stderr_base64"]) == b"private stderr"


@pytest.mark.parametrize("status", ["deadline_exceeded", "output_bound", "failed", "cleanup_incomplete"])
def test_failed_scutil_retains_private_bytes_but_no_absence_or_registration_claim(monkeypatch, status):
    monkeypatch.setattr(observation, "_capture_scutil", lambda _deadline: (status, b"partial", b"error", None))
    public, private = observation.scutil_diagnostics(expected_port=54321, deadline=time.monotonic() + 5)
    assert public["status"] == status
    assert public["exact_zone_present"] is None and public["matching_registration_present"] is None
    assert base64.b64decode(private["stdout_base64"]) == b"partial"


def test_capture_has_real_stream_byte_bound_and_fixed_read_only_command(monkeypatch):
    popen = subprocess.Popen

    def substitute(arguments, **kwargs):
        assert arguments == ["/usr/sbin/scutil", "--dns"]
        return popen([sys.executable, "-I", "-c", "import os; os.write(1,b'x'*200000)"], **kwargs)

    monkeypatch.setattr(observation.subprocess, "Popen", substitute)
    status, stdout, stderr, code = observation._capture_scutil(time.monotonic() + 2)
    assert status == "output_bound" and len(stdout) == 65536 and len(stderr) <= 65536
    assert code is not None


@pytest.mark.parametrize("behavior", ["timeout", "nonzero"])
def test_capture_contains_failed_process_and_keeps_partial_diagnostics(monkeypatch, behavior):
    popen = subprocess.Popen
    processes = []

    def substitute(arguments, **kwargs):
        assert arguments == ["/usr/sbin/scutil", "--dns"]
        action = "import time; time.sleep(30)" if behavior == "timeout" else "raise SystemExit(7)"
        process = popen([sys.executable, "-I", "-c", "import os; os.write(2,b'private failure'); " + action], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(observation.subprocess, "Popen", substitute)
    status, _stdout, stderr, code = observation._capture_scutil(time.monotonic() + 0.5)
    assert status == ("deadline_exceeded" if behavior == "timeout" else "failed")
    assert code is not None and processes[0].poll() is not None
    if behavior == "nonzero":
        assert code == 7 and stderr == b"private failure"


def test_expired_capture_never_starts_os_command(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("expired collector launched scutil")

    monkeypatch.setattr(observation.subprocess, "Popen", forbidden)
    assert observation._capture_scutil(time.monotonic() - 1) == ("deadline_exceeded", b"", b"", None)


def test_private_files_are_exclusive_flat_and_private(tmp_path):
    root = tmp_path / "private_samples"
    captures = {"before": {"stdout_base64": "cHJpdmF0ZQ=="}}
    assert observation.retain_private_captures(root, captures)
    path = root / "resolver-before-scutil.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == captures["before"]
    assert not observation.retain_private_captures(root, captures)
    assert not observation.retain_private_captures(root, {"unexpected-name": {}})


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX retained private directory")
def test_private_directory_symlink_is_not_followed(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    assert not observation.retain_private_captures(alias, {"before": {}})
    assert not list(target.iterdir())


def test_libc_probe_uses_packed_bytes_and_only_reports_pointer_presence(monkeypatch):
    query = resolver._query("libc_gethostbyaddr")
    assert "ctypes.CDLL('/usr/lib/libSystem.B.dylib')" in query
    assert "lookup.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int]" in query
    assert "address=(ctypes.c_ubyte*4)(127,0,0,1)" in query
    assert "lookup(ctypes.byref(address),4,2)" in query
    assert "socket" not in query and "h_name" not in query
    assert query.index("flush=True") < query.index("result=lookup")
    compile(query, "fixed-libc-probe", "exec")
    monkeypatch.setattr(
        resolver.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(
            args, 0, resolver._STARTED + '\n{"result_present":true}\n', ""
        ),
    )
    value = resolver.resolver_probe("libc_gethostbyaddr")
    assert value["status"] == "completed" and value["result_present"] is True
    assert "loopback_label" not in value


def test_libc_timeout_retains_actual_call_start_without_guessing_completion(monkeypatch):
    def timeout(arguments, **kwargs):
        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output=(resolver._STARTED + "\n").encode())

    monkeypatch.setattr(resolver.subprocess, "run", timeout)
    value = resolver.resolver_probe("libc_gethostbyaddr")
    assert value["status"] == "deadline_exceeded" and value["call_started"] is True
    assert value["result_present"] is False


def test_registration_probes_and_selftest_share_one_phase_deadline(monkeypatch):
    barrier = threading.Barrier(3)
    deadlines = []

    def probes(*, deadline, native_capture=None):
        assert native_capture is None
        deadlines.append(deadline)
        barrier.wait(timeout=1)
        return {kind: {"status": "failed"} for kind in resolver._QUERIES}

    def scutil(*, expected_port, deadline):
        assert expected_port == 54321
        deadlines.append(deadline)
        barrier.wait(timeout=1)
        return {"status": "failed"}, {"private": "not_public_name"}

    class Responder:
        def self_test(self, *, deadline):
            deadlines.append(deadline)
            barrier.wait(timeout=1)
            return {"status": "failed", "response_verified": False}

    monkeypatch.setattr(resolver, "resolver_diagnostics", probes)
    monkeypatch.setattr(resolver, "scutil_diagnostics", scutil)
    report, captures = {}, {}
    resolver._diagnose_phase(report, "after", captures, port=54321, responder=Responder())
    assert len(deadlines) == 3 and len(set(deadlines)) == 1
    assert 0 < deadlines[0] - time.monotonic() <= 5
    assert captures == {"after": {"private": "not_public_name"}}
    assert "not_public_name" not in json.dumps(report)


def test_one_shot_selftest_traffic_cannot_count_as_os_resolver_traffic():
    try:
        responder = dns.LoopbackPTRResponder()
    except PermissionError:
        pytest.skip("loopback socket unavailable in this environment")
    with responder:
        result = responder.self_test(deadline=time.monotonic() + 1)
        assert result["status"] == "completed" and result["response_verified"] is True
        assert result["traffic"] == {"received": 1, "answered": 1, "rejected": 0, "errors": 0}
        assert responder.snapshot() == dict.fromkeys(("received", "answered", "rejected", "errors"), 0)
        # Keeping the selftest client bound prevents an OS query reusing its
        # ephemeral source endpoint from being misclassified as selftest traffic.
        assert responder._selftest_socket is not None
        assert responder._selftest_socket.fileno() >= 0
        assert responder.self_test(deadline=time.monotonic() + 1)["status"] == "failed"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ordinary:
            ordinary.settimeout(1)
            packet = bytes.fromhex("123401000001000000000000") + dns._wire_name(dns.REVERSE_NAME) + b"\x00\x0c\x00\x01"
            ordinary.sendto(packet, ("127.0.0.1", responder.port))
            assert ordinary.recvfrom(513)[0] == dns.ptr_response(packet)
        assert responder.snapshot()["received"] == 1
    assert responder._selftest_socket.fileno() == -1
