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
        self.resident_records: list[dict[str, Any]] = []
        self.relay_records: list[dict[str, Any]] = []
        self.helper_pids: dict[int, int] = {}
        self.reader_helpers: set[int] = set()
        self.eof_helpers: set[int] = set()
        self.resident_sequences: set[tuple[int, int, int]] = set()
        self.selected_clients: dict[str, tuple[int, int]] = {}
        self.selected_residents: dict[str, tuple[int, int, int, int]] = {}
        self.requests: list[str] = []
        self.failure = False
        self.spawns = 0

    def __enter__(self) -> ClientObserver:
        from codex_plugin_scanner.guard import native_hook_edge, native_resident_stream
        from scripts import native_slo_session

        original_popen = native_resident_stream.subprocess.Popen
        original_request = native_hook_edge.native_resident_client_request
        original_close = native_slo_session.close_native_resident_clients

        def close(*args: Any, **kwargs: Any) -> Any:
            # The fixture has already verified resident/supervisor retirement.
            # Observe EOF before its unchanged forced helper retirement. This
            # diagnostic wait never skips cleanup or changes a hook deadline.
            try:
                self._wait_for_relay_eof()
            except BaseException:
                self.failure = True
            return original_close(*args, **kwargs)

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
            self.helper_pids[helper] = process.pid
            reader = threading.Thread(target=self._read, args=(process.stderr, helper), daemon=True)
            self.readers.append(reader)
            self.reader_helpers.add(helper)
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
            self.stack.enter_context(patch.object(native_slo_session, "close_native_resident_clients", close))
        except BaseException:
            self.stack.close()
            raise
        return self

    def _wait_for_relay_eof(self) -> None:
        from scripts.native_client_profile_resident import validate_relay_chains

        deadline = time.monotonic() + 2
        with self.condition:
            while self.spawns:
                require(not self.failure)
                try:
                    validate_relay_chains(self.helper_pids, self.resident_records, self.relay_records)
                    return
                except ValueError:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0)
                    self.condition.wait(remaining)

    def _read(self, stream: Any, helper: int) -> None:
        sequence = 0
        line = b""
        try:
            require(stream is not None)
            with stream:
                self.journal.append(
                    {"helper": helper, "status": "helper_reader_started", "process_id": self.helper_pids.get(helper)}
                )
                while True:
                    line = stream.readline(MAX_RECORD_BYTES + 1)
                    if not line:
                        self.journal.append({"helper": helper, "status": "helper_stderr_eof"})
                        with self.condition:
                            self.eof_helpers.add(helper)
                            self.condition.notify_all()
                        break
                    require(len(line) <= MAX_RECORD_BYTES and line.endswith(b"\n"))
                    record = decode_record(line)
                    if record["schema"] == "hol-guard.native-resident-profile-relay.v1":
                        retained = {"helper": helper, "relay": record}
                        self.journal.append(retained)
                        with self.condition:
                            require(len(self.relay_records) < 64)
                            self.relay_records.append(retained)
                            if not record["complete"]:
                                self.failure = True
                            self.condition.notify_all()
                        continue
                    if record["schema"] == "hol-guard.native-resident-profile.v1":
                        retained = {"helper": helper, "resident_profile": record}
                        self.journal.append(retained)
                        with self.condition:
                            identity = (record["process_id"], record["generation"], record["sequence"])
                            require(identity not in self.resident_sequences and len(self.resident_records) < 1024)
                            self.resident_sequences.add(identity)
                            self.resident_records.append(retained)
                            self.condition.notify_all()
                        continue
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
            require(digest not in self.selected_clients)
            while True:
                matches = [record for record in self.records if record["profile"]["request_sha256"] == digest]
                require(not self.failure and len(matches) <= 1)
                if matches:
                    self.selected_clients[digest] = (matches[0]["helper"], matches[0]["profile"]["sequence"])
                    return matches[0]
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                self.condition.wait(remaining)

    def resident_profile(self, digest: str) -> dict[str, Any]:
        deadline = time.monotonic() + 1
        with self.condition:
            require(digest not in self.selected_residents)
            while True:
                matches = [
                    record for record in self.resident_records if record["resident_profile"]["request_sha256"] == digest
                ]
                require(not self.failure and len(matches) <= 1)
                if matches:
                    value = matches[0]["resident_profile"]
                    self.selected_residents[digest] = (
                        matches[0]["helper"],
                        value["process_id"],
                        value["generation"],
                        value["sequence"],
                    )
                    return matches[0]
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                self.condition.wait(remaining)

    def validate_resident_capture(self) -> None:
        from scripts.native_client_profile_resident import validate_relay_chains

        require(not self.failure)
        expected = set(range(1, self.spawns + 1))
        require(bool(expected) and set(self.helper_pids) == self.reader_helpers == self.eof_helpers == expected)
        require(len(self.readers) == self.spawns and all(not reader.is_alive() for reader in self.readers))
        require({item["helper"] for item in self.records} == expected)
        validate_relay_chains(self.helper_pids, self.resident_records, self.relay_records)
        # Lookups happen while the stream is live. Recheck the complete EOF
        # inventory so a late duplicate cannot leave an earlier span selected.
        # Repeated auxiliary policy digests are outside this hook-only set.
        require(bool(self.selected_clients) and self.selected_clients.keys() == self.selected_residents.keys())
        for digest, identity in self.selected_clients.items():
            clients = [item for item in self.records if item["profile"]["request_sha256"] == digest]
            residents = [item for item in self.resident_records if item["resident_profile"]["request_sha256"] == digest]
            require(len(clients) == len(residents) == 1)
            require((clients[0]["helper"], clients[0]["profile"]["sequence"]) == identity)
            value = residents[0]["resident_profile"]
            require(
                (residents[0]["helper"], value["process_id"], value["generation"], value["sequence"])
                == self.selected_residents[digest]
            )

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
        # The fixture closes/reaps its existing helper pool first. This observer
        # neither owns nor replaces its process containment/retirement policy.
        deadline = time.monotonic() + 2
        for reader in self.readers:
            reader.join(max(0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in self.readers):
            self.failure = True
        with self.condition:
            # Concurrent worker emissions can finish out of sequence. Gaps
            # after EOF are evidence loss; never reopen or retry a request.
            groups = {(p, g) for p, g, _ in self.resident_sequences}
            for process, generation in groups:
                sequences = {s for p, g, s in self.resident_sequences if (p, g) == (process, generation)}
                if sequences != set(range(1, max(sequences) + 1)):
                    self.failure = True
