from __future__ import annotations

import hashlib
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import native_hook_edge, native_resident_stream
from scripts.native_client_profile_observer import ClientObserver
from tests.native_client_profile_support import record


class Journal:
    def __init__(self):
        self.values = []

    def append(self, value):
        self.values.append(value)


def test_module_local_command_change_and_exact_request_result(monkeypatch):
    runtime = Path("/fixture/runtime")
    payload = b"exact input bytes"
    journal = Journal()
    output = object()
    requested = Mock(return_value=output)
    spawned = Mock(
        return_value=SimpleNamespace(
            stderr=io.BytesIO(json.dumps(record(digest=hashlib.sha256(payload).hexdigest())).encode() + b"\n")
        )
    )
    original_module = native_resident_stream.subprocess
    monkeypatch.setattr(native_resident_stream, "subprocess", SimpleNamespace(Popen=spawned))
    monkeypatch.setattr(native_hook_edge, "native_resident_client_request", requested)
    global_popen = subprocess.Popen
    with ClientObserver(runtime, journal) as observer:
        process = native_resident_stream.subprocess.Popen(
            (str(runtime), "resident-client-stream", "--stdin", "/state"),
            stderr=subprocess.DEVNULL,
            cwd="/fixture",
            env={"fixed": "value"},
        )
        assert process is spawned.return_value and subprocess.Popen is global_popen
        assert native_hook_edge.native_resident_client_request(payload=payload, deadline_monotonic=17) is output
        matched = observer.request_profile(0)
        assert matched["helper"] == 1 and matched["profile"]["request_sha256"] == hashlib.sha256(payload).hexdigest()
    assert native_hook_edge.native_resident_client_request is requested
    assert native_resident_stream.subprocess is not original_module  # restores the caller's exact injected module
    assert not observer.failure
    spawned.assert_called_once_with(
        (str(runtime), "resident-client-stream-profile", "--stdin", "/state"),
        stderr=subprocess.PIPE,
        cwd="/fixture",
        env={"fixed": "value"},
    )
    requested.assert_called_once_with(payload=payload, deadline_monotonic=17)


def test_original_request_exception_is_identical_and_no_retry(monkeypatch):
    sentinel = RuntimeError("synthetic")
    original = Mock(side_effect=sentinel)
    monkeypatch.setattr(native_hook_edge, "native_resident_client_request", original)
    with ClientObserver(Path("/runtime"), Journal()) as observer:
        with pytest.raises(RuntimeError) as error:
            native_hook_edge.native_resident_client_request(payload=b"bounded", deadline_monotonic=1)
        assert error.value is sentinel
        assert len(observer.requests) == 1
    assert original.call_count == 1


@pytest.mark.parametrize("failure", ["duplicate", "sequence", "invalid", "journal"])
def test_reader_faults_stay_incomplete_and_keep_already_written_records(failure):
    journal = Journal()
    observer = ClientObserver(Path("/runtime"), journal)
    first = record()
    second = record(sequence=2)
    if failure == "sequence":
        second["sequence"] = 3
    if failure == "invalid":
        second["unknown"] = "private"
    if failure == "journal":
        journal.append = Mock(side_effect=OSError("synthetic"))
    encoded = b"".join(json.dumps(value).encode() + b"\n" for value in [first, second])
    observer._read(io.BytesIO(encoded), 1)
    observer.requests.append("a" * 64)
    with pytest.raises(ValueError):
        observer.request_profile(0)
    assert observer.failure or failure == "duplicate"
    assert len(observer.records) == (0 if failure == "journal" else 2 if failure == "duplicate" else 1)


def test_correlation_refuses_multiple_hook_calls():
    observer = ClientObserver(Path("/runtime"), Journal())
    observer.requests = ["a" * 64, "b" * 64]
    with pytest.raises(ValueError):
        observer.request_profile(0)
