"""Script-only observer of the production persistent helper, in an isolated worker."""

from __future__ import annotations

import base64
import hashlib
import subprocess
import threading
import time
from contextlib import ExitStack, suppress
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.native_client_profile_records import MAX_RECORD_BYTES, Journal, decode_record, require
from scripts.native_slo_phase_calls import ModuleProbe


class ClientObserver:
    def __init__(self, runtime: Path, journal: Journal) -> None:
        self.runtime, self.journal = runtime, journal
        self.stack = ExitStack()
        self.condition = threading.Condition()
        self.readers: list[threading.Thread] = []
        self.records: list[dict[str, Any]] = []
        self.requests: list[str] = []
        self.failure = False
        self.spawns = 0

    def __enter__(self) -> ClientObserver:
        from codex_plugin_scanner.guard import native_hook_edge, native_resident_stream

        original_popen = native_resident_stream.subprocess.Popen
        original_request = native_hook_edge.native_resident_client_request

        def popen(argv: Any, **kwargs: Any) -> Any:
            # Patch only this importing module, never the global subprocess API.
            require(isinstance(argv, (tuple, list)) and len(argv) == 4)
            require(tuple(argv[:3]) == (str(self.runtime), "resident-client-stream", "--stdin"))
            require(kwargs.get("stderr") == subprocess.DEVNULL)
            with self.condition:
                require(self.spawns < 32)
                self.spawns += 1
                helper = self.spawns
            selected = (argv[0], "resident-client-stream-profile", *argv[2:])
            options: dict[str, Any] = dict(kwargs)
            options["stderr"] = subprocess.PIPE
            process = original_popen(selected, **options)
            reader = threading.Thread(target=self._read, args=(process.stderr, helper), daemon=True)
            self.readers.append(reader)
            reader.start()
            return process

        def request(**kwargs: Any) -> Any:
            payload = kwargs.get("payload")
            require(isinstance(payload, bytes) and 0 < len(payload) <= 6 * 1024 * 1024)
            assert isinstance(payload, bytes)
            digest = hashlib.sha256(payload).hexdigest()
            with self.condition:
                require(len(self.requests) < 256)
                self.requests.append(digest)
            # Same arguments, one original call, identical result/exception.
            return original_request(**kwargs)

        try:
            self.stack.enter_context(
                patch.object(native_resident_stream, "subprocess", ModuleProbe(subprocess, {"Popen": popen}))
            )
            self.stack.enter_context(patch.object(native_hook_edge, "native_resident_client_request", request))
        except BaseException:
            self.stack.close()
            raise
        return self

    def _read(self, stream: Any, helper: int) -> None:
        sequence = 0
        line = b""
        try:
            require(stream is not None)
            with stream:
                while True:
                    line = stream.readline(MAX_RECORD_BYTES + 1)
                    if not line:
                        break
                    require(len(line) <= MAX_RECORD_BYTES and line.endswith(b"\n"))
                    record = decode_record(line)
                    sequence += 1
                    require(record["sequence"] == sequence)
                    retained = {"helper": helper, "profile": record}
                    self.journal.append(retained)
                    with self.condition:
                        require(len(self.records) < 1024)
                        self.records.append(retained)
                        self.condition.notify_all()
        except BaseException:
            # Keep a bounded private prefix even when the native diagnostic
            # framing itself fails; the public projection never contains it.
            with suppress(BaseException):
                self.journal.append(
                    {
                        "helper": helper,
                        "status": "record_unavailable",
                        "length": len(line),
                        "sha256": hashlib.sha256(line).hexdigest(),
                        "prefix_base64": base64.b64encode(line[:2048]).decode("ascii"),
                        "truncated": len(line) > 2048,
                    }
                )
            with self.condition:
                self.failure = True
                self.condition.notify_all()

    def request_profile(self, before: int) -> dict[str, Any]:
        deadline = time.monotonic() + 1
        with self.condition:
            require(len(self.requests) == before + 1)
            digest = self.requests[-1]
            while True:
                matches = [record for record in self.records if record["profile"]["request_sha256"] == digest]
                require(not self.failure and len(matches) <= 1)
                if matches:
                    return matches[0]
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                self.condition.wait(remaining)

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
        # The fixture closes/reaps its existing helper pool first. This observer
        # neither owns nor replaces its process containment/retirement policy.
        deadline = time.monotonic() + 2
        for reader in self.readers:
            reader.join(max(0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in self.readers):
            self.failure = True
