"""Losslessly retain the existing diagnostic sink's emitted JSON objects."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import stat
import threading
import traceback

from common import REPORT, ROOT, file_identity, require, sha256, write_json

MAX_STREAM = 16 * 1024 * 1024
MAX_OBJECTS = 65536
MAX_READS = 65536
CAPTURES = []


def active_collectors() -> list[dict]:
    return [{"variant": item.variant, "name": item.thread.name,
             "ident": item.thread.ident, "native_id": item.thread.native_id}
            for item in CAPTURES if item.thread is not None and item.thread.is_alive()]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate native-stop JSON key")
        result[key] = value
    return result


class StopCapture:
    def __init__(self, variant: str):
        self.variant = variant
        self.path = ROOT / "tmp" / (variant + "-native-stop.fifo")
        self.raw_path = REPORT / variant / "native-stop-emitted-stream.raw"
        self.end = threading.Event()
        self.failure = None
        self.bytes = 0
        self.reads = []
        self.digest = hashlib.sha256()
        self.fd = self.thread = self.inode = None
        self.finished_result = None
        CAPTURES.append(self)

    def start(self) -> Path:
        require(not self.path.exists() and not self.path.is_symlink(), "Refuse existing native-stop sink")
        self.raw_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.mkfifo(self.path, 0o600)
            before = self.path.lstat()
            require(stat.S_ISFIFO(before.st_mode) and before.st_uid == os.geteuid(), "Unowned native-stop FIFO")
            self.inode = (before.st_dev, before.st_ino)
            self.fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
            actual = os.fstat(self.fd)
            require((actual.st_dev, actual.st_ino) == self.inode, "Native-stop FIFO identity changed")
            self.thread = threading.Thread(target=self._read, name="intel-native-stop-evidence", daemon=False)
            self.thread.start()
            return self.path
        except BaseException:
            self.failure = traceback.format_exc()
            self.finish(producers_retired=True)
            raise

    def _read(self) -> None:
        try:
            with self.raw_path.open("xb") as stream:
                while True:
                    readable, _, _ = select.select([self.fd], [], [], 0.05)
                    if readable:
                        try:
                            raw = os.read(self.fd, 65536)
                        except BlockingIOError:
                            continue
                        require(raw, "Unexpected EOF from owned FIFO")
                        self.bytes += len(raw)
                        self.digest.update(raw)
                        require(stream.write(raw) == len(raw), "Short native-stop evidence write")
                        self.reads.append(len(raw))
                        require(self.bytes <= MAX_STREAM and len(self.reads) <= MAX_READS,
                                "Native-stop capture exceeded stream/read bound")
                    elif self.end.is_set():
                        break
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            self.failure = traceback.format_exc()

    def finish(self, *, producers_retired: bool) -> dict:
        if self.finished_result is not None:
            return self.finished_result
        self.end.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=5)
        alive = self.thread is not None and self.thread.is_alive()
        objects = []
        result = {"scope": "Every byte/object emitted to the original diagnostic sink",
                  "not_observed": "Non-emitted in-memory NativeStopResult objects",
                  "producers_retired": producers_retired, "collector_thread_alive": alive,
                  "read_chunk_bytes": self.reads, "original_objects": objects,
                  "emitted_objects": 0, "first_failure": None, "passed": False, "complete": False,
                  "stream_read_bytes": self.bytes, "stream_read_sha256": self.digest.hexdigest()}
        failures = [self.failure] if self.failure else []
        try:
            require(not alive, "Diagnostic collector thread did not retire")
            if self.raw_path.exists():
                pin = file_identity(self.raw_path, maximum=MAX_STREAM + 65536, honor_deadline=False)
                result["raw"] = pin
                raw = self.raw_path.read_bytes()
                require(len(raw) == pin["bytes"] == self.bytes
                        and sha256(raw) == pin["sha256"] == self.digest.hexdigest(),
                        "Native-stop pipe bytes and retained readback differ")
                result["raw_readback_matches_stream"] = True
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as error:
                    text = raw[:error.start].decode("utf-8")
                    failures.append("Invalid UTF-8 after the retained decoded prefix: " + repr(error))
                decoder = json.JSONDecoder(object_pairs_hook=unique_object)
                offset = 0
                while offset < len(text):
                    while offset < len(text) and text[offset].isspace():
                        offset += 1
                    if offset == len(text):
                        break
                    value, end = decoder.raw_decode(text, offset)
                    objects.append(value)
                    result["decoded_prefix_utf8_bytes"] = len(text[:end].encode("utf-8"))
                    require(len(objects) <= MAX_OBJECTS, "Native-stop object count bound")
                    require(isinstance(value, dict) and value.get("schema")
                            == "hol-guard.native-resident-stop-diagnostic.v1", "Unexpected diagnostic object")
                    require(len(text[offset:end].encode("utf-8")) <= 65536, "Native-stop object bound")
                    offset = end
                require(self.bytes <= MAX_STREAM, "Native-stop stream bound exceeded")
            else:
                raise RuntimeError("Original native-stop raw stream was not created")
            require(producers_retired, "Residual diagnostic producers are not retired")
            actual = self.path.lstat()
            require((actual.st_dev, actual.st_ino) == self.inode and stat.S_ISFIFO(actual.st_mode),
                    "Original diagnostic FIFO changed")
        except BaseException:
            failures.append(traceback.format_exc())
        finally:
            if not alive and self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    failures.append(traceback.format_exc())
                self.fd = None
            if not alive and producers_retired and self.inode is not None:
                try:
                    actual = self.path.lstat()
                    if (actual.st_dev, actual.st_ino) == self.inode and stat.S_ISFIFO(actual.st_mode):
                        self.path.unlink()
                    else:
                        failures.append("Refused unlink of replaced diagnostic FIFO")
                except FileNotFoundError:
                    pass
                except OSError:
                    failures.append(traceback.format_exc())
            result["emitted_objects"] = len(objects)
            result["first_failure"] = next((item for item in objects if isinstance(item, dict)
                and item.get("status") in {"failed", "contained_client_cleanup_failed"}), None)
            result["complete"] = not failures
            result["passed"] = not failures
            result["errors"] = failures
            result["native_stop_succeeded"] = result["complete"] and result["first_failure"] is None
            if alive or not producers_retired:
                write_json(ROOT / "unsafe-continuation.json",
                           {"reason": "Native-stop collector/producers remain unretired", "capture": result})
            # No phase deadline check applies to this bounded terminal evidence write.
            write_json(REPORT / self.variant / "native-stop-emission-retention.json", result)
        self.finished_result = result
        return result
