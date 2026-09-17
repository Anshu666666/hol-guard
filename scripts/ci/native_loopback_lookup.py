"""Bounded macOS lookup witnesses, after qualification and before DNS cleanup.

Every lookup is fixed to loopback. Only a child created here can be sampled.
No original benchmark process is inspected or changed, and raw native stacks
are never exported. Diagnostic timings are not qualification samples.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time

LOOKUP_SECONDS = 5.0
_LOOKUPS = {
    "numeric_control": "socket.getnameinfo(('127.0.0.1', 0), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)[0]",
    "gethostbyaddr": "socket.gethostbyaddr('127.0.0.1')[0]",
    "getnameinfo": "socket.getnameinfo(('127.0.0.1', 0), socket.NI_NAMEREQD | socket.NI_NUMERICSERV)[0]",
}
_STACK_CATEGORIES = {
    "python_lookup": frozenset({"socket_gethostbyaddr", "socket_getnameinfo", "setipaddr"}),
    "libinfo_search": frozenset({"gethostbyaddr", "si_host_byaddr", "search_host_byaddr", "si_search", "getnameinfo"}),
    "directory_lookup": frozenset({"ds_host_byaddr", "ds_hostbyaddr", "ds_query", "si_muser_call"}),
    "mdns_query": frozenset({"mdns_hostbyaddr", "_mdns_search", "_mdns_search_ex", "_mdns_query_start"}),
    "mdns_ipc": frozenset({"DNSServiceQueryRecord", "DNSServiceQueryRecordWithAttribute", "DNSServiceProcessResult"}),
    "kevent_wait": frozenset({"kevent", "kevent64", "kevent_qos"}),
    "pthread_wait": frozenset({"pthread_mutex_lock", "__psynch_mutexwait", "__psynch_cvwait"}),
    "mach_wait": frozenset({"mach_msg", "mach_msg2_trap", "mach_msg_trap", "_dispatch_mach_send_and_wait_for_reply"}),
    "socket_wait": frozenset({"recv", "recvfrom", "recvmsg", "read", "poll", "select"}),
}


def stack_summary(data: bytes) -> dict:
    """Recognize only function frames in sample's call graph, never headers."""
    text = data.decode("utf-8", errors="replace")
    body = text.partition("Call graph:")[2].partition("Total number in stack")[0]
    categories = set()
    count = 0
    for line in body.splitlines():
        match = re.match(r"^\s*(?:[+!:|]\s*)*\d+\s+([A-Za-z_][A-Za-z0-9_.$]{0,127})\s*(?:\(|\+|$)", line)
        if match is None:
            continue
        function = match.group(1)
        recognized = {name for name, functions in _STACK_CATEGORIES.items() if function in functions}
        if recognized:
            count += 1
            categories.update(recognized)
    return {
        "categories": sorted(categories),
        "recognized_frames": count,
        "stack_sha256": hashlib.sha256(data).hexdigest(),
        "stack_bytes": len(data),
    }


def _bounded_process(
    arguments: list[str], *, timeout: float, limit: int, sample_owned: bool = False
) -> tuple[dict, bytes]:
    started = time.monotonic()
    deadline = started + timeout
    report = {"status": "completed", "contained": False}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    process = None
    sample_attempted = False
    try:
        process = subprocess.Popen(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
        with selectors.DefaultSelector() as selector:
            for channel in buffers:
                stream = getattr(process, channel)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, channel)
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline:
                    report["status"] = "deadline_exceeded"
                    break
                if sample_owned and not sample_attempted and now - started >= 0.25 and process.poll() is None:
                    # The child remains unreaped while sample runs, preventing
                    # PID reuse. No caller-supplied PID or process is accepted.
                    sample_attempted = True
                    sample, trace = _bounded_process(
                        ["/usr/bin/sample", str(process.pid), "1", "10", "-mayDie", "-file", "/dev/stdout"],
                        timeout=min(2.0, deadline - now),
                        limit=64 * 1024,
                    )
                    report["native_sample"] = {**sample, **stack_summary(trace)}
                    continue
                for key, _mask in selector.select(min(0.05, deadline - now)):
                    remaining = limit - sum(len(value) for value in buffers.values())
                    chunk = os.read(key.fileobj.fileno(), min(8192, remaining + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(chunk) > remaining:
                        buffers[key.data].extend(chunk[:remaining])
                        report["status"] = "size_limit"
                        break
                    else:
                        buffers[key.data].extend(chunk)
                if report["status"] != "completed":
                    break
        if report["status"] == "completed":
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                report["status"] = "deadline_exceeded"
    except OSError as error:
        report.update(status="unavailable", errno=error.errno)
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    report["status"] = "containment_failed"
            try:
                process.wait(timeout=1)
                report["contained"] = True
            except subprocess.TimeoutExpired:
                report["status"] = "containment_failed"
            report["return_code"] = process.returncode
            for channel in buffers:
                stream = getattr(process, channel)
                if stream is not None:
                    stream.close()
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    for channel, data in buffers.items():
        report[channel + "_bytes"] = len(data)
        report[channel + "_sha256"] = hashlib.sha256(data).hexdigest()
    return report, bytes(buffers["stdout"])


def lookup_probe(operation: str, responder: object) -> dict:
    expression = _LOOKUPS[operation]
    code = (
        "import json,socket\ntry:\n name=" + expression + "\n print(json.dumps({'status':'completed',"
        "'loopback_label':name in ('127.0.0.1','localhost','hol-guard-qualification.localhost')}),flush=True)\n"
        "except Exception as error:\n print(json.dumps({'status':'lookup_error','category':type(error).__name__,"
        "'errno':getattr(error,'errno',None)}),flush=True)\n"
    )
    before = responder.snapshot()["received"]
    report, data = _bounded_process(
        [sys.executable, "-I", "-c", code],
        timeout=LOOKUP_SECONDS,
        limit=1024,
        sample_owned=operation != "numeric_control",
    )
    report["operation"] = operation
    report["responder_packet_delta"] = max(0, responder.snapshot()["received"] - before)
    if report["status"] == "completed" and report.get("return_code") == 0:
        report["lookup"] = {"status": "invalid_child_evidence"}
        try:
            value = json.loads(data)
            if value.get("status") == "completed" and type(value.get("loopback_label")) is bool:
                report["lookup"] = {"status": "completed", "loopback_label": value["loopback_label"]}
            elif value.get("status") == "lookup_error":
                kind = value.get("category")
                report["lookup"] = {"status": "lookup_error"}
                if isinstance(kind, str) and re.fullmatch(r"[A-Za-z]{1,64}", kind):
                    report["lookup"]["category"] = kind
                if type(value.get("errno")) is int:
                    report["lookup"]["errno"] = value["errno"]
        except (ValueError, TypeError, AttributeError):
            report["lookup"] = {"status": "invalid_child_evidence"}
    return report


def lookup_witness(responder: object) -> dict:
    report = {
        "schema": "hol-guard.native-loopback-lookup-witness.v1",
        "phase": "after_qualification_before_resolver_cleanup",
        "qualification_outcomes_changed": False,
        "qualification_sample": False,
        "baseline_modified": False,
        "fixed_loopback_only": True,
        "packet_delta_scope": "responder_window_including_system_activity",
        "process_deadline_seconds": LOOKUP_SECONDS,
        "probes": [],
    }
    for operation in _LOOKUPS:
        report["probes"].append(lookup_probe(operation, responder))
    return report
