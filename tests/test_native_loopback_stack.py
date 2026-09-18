from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import time

import pytest

from scripts.ci import native_loopback_observability as observation
from scripts.ci import native_loopback_resolver as resolver
from scripts.ci import native_loopback_stack as stack


def _sample_text(pid=12345):
    return (
        f"Analysis of sampling Python (pid {pid}) every 1 millisecond\n"
        f"Process:         Python [{pid}]\nPath: /private/sample-user/Python\n"
        "Command: private-host.example gethostbyaddr\n\nCall graph:\n"
        "    100 Thread_111\n"
        "    + 100 gethostbyaddr (in libsystem_info.dylib) + 42 [0x1234]\n"
        "    +   100 mach_msg2_trap (in libsystem_kernel.dylib) + 8 [0x5678]\n"
        "    +     100 private_function (in PrivateLib.dylib) + 0 [0x9988]\n"
        "Total number in stack (recursive counted multiple, when >=5):\n"
        "Binary Images:\n  0x1 DNSServiceQueryRecord (in libsystem_dnssd.dylib)\n"
    ).encode()


def test_projection_only_reports_fixed_categories_from_this_probe_call_graph():
    public = stack.stack_projection(_sample_text(), 12345)
    assert public == {
        "resolver_entry_frame_observed": True,
        "libinfo_frame_observed": True,
        "dns_service_frame_observed": False,
        "mach_message_frame_observed": True,
        "synchronization_frame_observed": False,
    }
    assert "private" not in json.dumps(public) and "12345" not in json.dumps(public)


@pytest.mark.parametrize(
    "raw",
    [
        _sample_text(999),
        _sample_text().split(b"Total number in stack")[0],
        _sample_text().replace(b"Call graph:", b"Command line:"),
        _sample_text()
        .replace(b"(in libsystem_info.dylib)", b"(in library)")
        .replace(b"+ 100 gethostbyaddr", b"private 100 gethostbyaddr")
        .replace(b"+   100 mach_msg2_trap", b"private 100 mach_msg2_trap")
        .replace(b"+     100 private_function", b"private 100 private_function"),
        b"x" * 65537,
        b"\xff",
    ],
)
def test_unbound_truncated_malformed_or_oversize_stack_is_missing(raw):
    with pytest.raises(ValueError):
        stack.stack_projection(raw, 12345)


@pytest.mark.parametrize("status", ["unavailable", "deadline_exceeded", "output_bound", "cleanup_incomplete", "failed"])
def test_partial_capture_never_proves_absence_and_raw_output_stays_private(status):
    raw, error = _sample_text(), b"private diagnostic"
    public, private = stack._sample_report((status, raw, error, 1, status != "cleanup_incomplete"), 12345)
    assert public["observation_missing"] is True
    assert all(public[field] is None for field in stack._CATEGORIES)
    assert "private" not in json.dumps(public) and "12345" not in json.dumps(public)
    assert base64.b64decode(private["stdout_base64"]) == raw
    assert base64.b64decode(private["stderr_base64"]) == error


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX process groups and pipe selector")
@pytest.mark.parametrize("behavior", ["overflow", "timeout", "nonzero", "completed"])
def test_sampler_has_fixed_read_only_command_bounded_streams_and_reaps_its_child(monkeypatch, behavior):
    popen = subprocess.Popen
    processes = []

    def substitute(arguments, **kwargs):
        assert arguments == ["/usr/bin/sample", "12345", "1", "1", "-file", "/dev/stdout"]
        assert kwargs["start_new_session"] is True and kwargs["stdin"] is subprocess.DEVNULL
        if behavior == "overflow":
            action = "import os,time; os.write(1,b'x'*200000); time.sleep(30)"
        elif behavior == "timeout":
            action = "import os,time; os.write(2,b'private diagnostic'); time.sleep(30)"
        elif behavior == "nonzero":
            action = "raise SystemExit(7)"
        else:
            action = "import os; os.write(1," + repr(_sample_text()) + ")"
        process = popen([sys.executable, "-I", "-c", action], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(stack.subprocess, "Popen", substitute)
    captured = stack._sample(12345, time.monotonic() + 0.5)
    expected = {
        "overflow": "output_bound",
        "timeout": "deadline_exceeded",
        "nonzero": "failed",
        "completed": "completed",
    }
    assert captured[0] == expected[behavior]
    assert len(captured[1]) <= 65536 and len(captured[2]) <= 65536
    assert captured[4] is True and processes[0].returncode is not None
    if behavior == "overflow":
        assert len(captured[1]) == 65536
    if behavior == "nonzero":
        assert captured[3] == 7


def test_expired_or_unavailable_sampler_retains_a_missing_observation(monkeypatch):
    calls = []

    def unavailable(*args, **kwargs):
        calls.append(args)
        raise FileNotFoundError("private path")

    monkeypatch.setattr(stack.subprocess, "Popen", unavailable)
    assert stack._sample(12345, time.monotonic() - 1) == ("deadline_exceeded", b"", b"", None, True)
    assert not calls
    captured = stack._sample(12345, time.monotonic() + 1)
    public, private = stack._sample_report(captured, 12345)
    assert public["status"] == "unavailable" and public["observation_missing"] is True
    assert "private path" not in json.dumps([public, private])


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX process groups and pipe selector")
def test_sampler_complete_output_before_exit_preserves_frames_without_claiming_success(monkeypatch):
    popen = subprocess.Popen

    def close_then_delay(_arguments, **kwargs):
        query = "import os,time; os.write(1," + repr(_sample_text()) + "); os.close(1); os.close(2); time.sleep(30)"
        return popen([sys.executable, "-I", "-c", query], **kwargs)

    monkeypatch.setattr(stack.subprocess, "Popen", close_then_delay)
    captured = stack._sample(12345, time.monotonic() + 0.5)
    assert captured[0] == "completed" and captured[3] == -9 and captured[4] is True
    public, private = stack._sample_report(captured, 12345)
    assert public["observation_missing"] is False and public["libinfo_frame_observed"] is True
    assert public["process_successful_exit_observed"] is False
    assert public["process_exit_observation"] == "sigkill_exit_observed_after_output"
    assert private["returncode"] == -9


@pytest.mark.parametrize("code,raw", [(7, _sample_text()), (-9, _sample_text()[:50])])
def test_invalid_or_spontaneously_nonzero_sample_remains_missing(code, raw):
    public, _private = stack._sample_report(("completed", raw, b"", code, True), 12345)
    assert public["observation_missing"] is True and public["process_successful_exit_observed"] is False
    assert all(public[field] is None for field in stack._CATEGORIES)


def test_darwin_sample_projection_is_reviewable_on_hosts_without_sigkill(monkeypatch):
    monkeypatch.delattr(stack.signal, "SIGKILL", raising=False)
    public, private = stack._sample_report(("completed", _sample_text(), b"", -9, True), 12345)
    assert public["observation_missing"] is False and public["process_successful_exit_observed"] is False
    assert public["process_exit_observation"] == "sigkill_exit_observed_after_output" and private["returncode"] == -9


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX process groups and pipe selector")
def test_probe_complete_output_then_sigkill_never_becomes_successful_lookup(monkeypatch):
    monkeypatch.setattr(stack.sys, "platform", "darwin")
    output = (resolver._STARTED + '\n{"result_present":true}\n').encode()
    query = f"import os,time; os.write(1,{output!r}); os.close(1); os.close(2); time.sleep(30)"
    status, actual, code, public, _private = stack.observed_libc_probe(
        query,
        resolver._STARTED,
        deadline=time.monotonic() + 2.1,
    )
    assert status == "sigkill_exit_observed_after_output" and actual == output and code == -9
    assert public["probe_cleanup_complete"] is True
    monkeypatch.setattr(resolver, "observed_libc_probe", lambda *_, **__: (status, actual, code, public, {}))
    result = resolver.resolver_probe("libc_gethostbyaddr", native_capture={})
    assert result["status"] == "sigkill_exit_observed_after_output" and result["result_present"] is False


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX process groups and pipe selector")
def test_probe_is_sampled_once_after_marker_with_shared_deadline_and_no_pid_reaping(monkeypatch):
    monkeypatch.setattr(stack.sys, "platform", "darwin")
    popen = subprocess.Popen
    processes, captures = [], []
    phase_deadline = time.monotonic() + 2.1

    def start(arguments, **kwargs):
        process = popen(arguments, **kwargs)
        processes.append(process)
        return process

    def sample(pid, deadline):
        assert processes[0].pid == pid and processes[0].returncode is None
        assert deadline == phase_deadline - 0.75
        captures.append(pid)
        return "completed", _sample_text(pid), b"private sampler stderr", 0, True

    monkeypatch.setattr(stack.subprocess, "Popen", start)
    monkeypatch.setattr(stack, "_sample", sample)
    query = f"import os,time; os.write(1,{(resolver._STARTED + chr(10)).encode()!r}); time.sleep(30)"
    status, stdout, code, public, private = stack.observed_libc_probe(query, resolver._STARTED, deadline=phase_deadline)
    assert status == "deadline_exceeded" and stdout == (resolver._STARTED + "\n").encode()
    assert len(captures) == 1 and len(processes) == 1
    assert code is not None and processes[0].returncode is not None
    assert public["status"] == "completed" and public["probe_cleanup_complete"] is True
    assert "private" not in json.dumps(public)
    assert base64.b64decode(private["stderr_base64"]) == b"private sampler stderr"
    assert time.monotonic() < phase_deadline + 1


@pytest.mark.skipif(os.name == "nt", reason="macOS/POSIX process groups and pipe selector")
@pytest.mark.parametrize("case", ["completed", "no_marker", "insufficient_budget"])
def test_finished_unstarted_or_late_probe_cannot_launch_sampler(monkeypatch, case):
    monkeypatch.setattr(stack.sys, "platform", "darwin")

    def forbidden(*_args, **_kwargs):
        pytest.fail("sampler must not run for this probe")

    monkeypatch.setattr(stack, "_sample", forbidden)
    output = b"private startup error" if case == "no_marker" else (resolver._STARTED + "\n").encode()
    if case == "completed":
        output += b'{"result_present":true}\n'
    query = f"import os; os.write(1,{output!r})"
    if case == "insufficient_budget":
        query += "; import time; time.sleep(30)"
    budget = 0.3 if case == "insufficient_budget" else 2.1
    status, _stdout, code, public, private = stack.observed_libc_probe(
        query,
        resolver._STARTED,
        deadline=time.monotonic() + budget,
    )
    assert status == ("deadline_exceeded" if case == "insufficient_budget" else "completed")
    assert code is not None and public["probe_cleanup_complete"] is True
    assert public["observation_missing"] is True and not private
    assert (
        public["status"]
        == {
            "completed": "probe_already_completed",
            "no_marker": "call_not_observed",
            "insufficient_budget": "insufficient_budget",
        }[case]
    )


def test_public_probe_result_and_private_native_capture_have_separate_destinations(monkeypatch):
    public_stack = {"status": "completed", "observation_missing": False}

    def observed(query, marker, *, deadline):
        assert query == resolver._query("libc_gethostbyaddr") and marker == resolver._STARTED
        assert 0 < deadline - time.monotonic() <= 5
        return "deadline_exceeded", (marker + "\n").encode(), -9, public_stack, {"private": "native stack"}

    monkeypatch.setattr(resolver, "observed_libc_probe", observed)
    retained = {}
    value = resolver.resolver_probe("libc_gethostbyaddr", native_capture=retained)
    assert value["status"] == "deadline_exceeded" and value["call_started"] is True
    assert value["native_stack"] == public_stack and retained == {"private": "native stack"}
    assert "native stack" not in json.dumps(value)


def test_one_native_capture_is_admitted_after_pair_and_stored_under_fixed_private_name(monkeypatch, tmp_path):
    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    captures_seen = []

    def probes(*, deadline, native_capture):
        captures_seen.append(native_capture)
        if native_capture is not None:
            native_capture["private"] = "native stack"
        return {kind: {"status": "completed"} for kind in resolver._QUERIES}

    monkeypatch.setattr(resolver, "resolver_diagnostics", probes)
    monkeypatch.setattr(resolver, "scutil_diagnostics", lambda **_: ({"status": "completed"}, {"private": "scutil"}))

    def paired_command(_command):
        assert not (tmp_path / "private_samples").exists()
        return 0

    monkeypatch.setattr(resolver, "_run_command", paired_command)
    output = tmp_path / "aggregate/report.json"
    assert resolver.run_wrapped(["both-arms"], output) == 0
    assert len(captures_seen) == 2 and captures_seen[0] is not None and captures_seen[1] is None
    path = tmp_path / "private_samples/resolver-before-native-stack.json"
    assert json.loads(path.read_text()) == {"private": "native stack"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "native stack" not in output.read_text()
    assert not observation.retain_private_captures(path.parent, {"before_native_stack": {}})


@pytest.mark.parametrize("field", ["collector_cleanup_complete", "probe_cleanup_complete"])
def test_incomplete_native_cleanup_blocks_measured_arms_and_is_not_qualification_success(monkeypatch, tmp_path, field):
    monkeypatch.setattr(resolver.sys, "platform", "darwin")

    def probes(**_kwargs):
        rows = {kind: {"status": "failed"} for kind in resolver._QUERIES}
        rows["libc_gethostbyaddr"]["native_stack"] = {field: False}
        return rows

    monkeypatch.setattr(resolver, "resolver_diagnostics", probes)
    monkeypatch.setattr(resolver, "scutil_diagnostics", lambda **_: ({"status": "completed"}, {}))

    def forbidden(_command):
        pytest.fail("measurement started beside a possibly live collector")

    monkeypatch.setattr(resolver, "_run_command", forbidden)
    output = tmp_path / "report.json"
    with pytest.raises(RuntimeError, match=r"^native_stack_cleanup_incomplete$"):
        resolver.run_wrapped(["both-arms"], output)
    report = json.loads(output.read_text())
    assert report["status"] == "diagnostic_cleanup_incomplete" and report["qualification_pass"] is False
