"""Bounded loopback PTR responder for the disposable macOS qualification runner.

The only answer is 127.0.0.1's fixed reverse name. No forwarding, general DNS
service, application patch, or baseline artifact modification is involved.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path

REVERSE_NAME = "1.0.0.127.in-addr.arpa"
_REVERSE_LABELS = tuple(part.encode("ascii") for part in REVERSE_NAME.split("."))
LOOPBACK_NAME = "hol-guard-qualification.localhost"
RESOLVER_DIRECTORY = Path("/etc/resolver")
MAX_QUERY_BYTES = 512


def _wire_name(name: str) -> bytes:
    return b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split(".")) + b"\0"


def ptr_response(packet: bytes) -> bytes | None:
    """Accept one uncompressed IN/PTR question, optionally with one EDNS0 OPT."""
    if not 12 <= len(packet) <= MAX_QUERY_BYTES:
        return None
    identifier, flags, questions, answers, authorities, additional = struct.unpack("!6H", packet[:12])
    if flags & ~0x0130 or (questions, answers, authorities) != (1, 0, 0) or additional not in (0, 1):
        return None
    cursor, labels = 12, []
    while cursor < len(packet):
        length = packet[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63 or cursor + length > len(packet) or cursor + length - 12 > 254:
            return None
        labels.append(packet[cursor : cursor + length])
        cursor += length
    else:
        return None
    if tuple(label.lower() for label in labels) != _REVERSE_LABELS or cursor + 4 > len(packet):
        return None
    if struct.unpack("!HH", packet[cursor : cursor + 4]) != (12, 1):
        return None
    cursor += 4
    if additional:
        # OPT's owner is the root; nonzero versions/extended rcodes are unsupported.
        if len(packet) - cursor < 11 or packet[cursor] != 0:
            return None
        kind, udp_size, extended, size = struct.unpack("!HHIH", packet[cursor + 1 : cursor + 11])
        if kind != 41 or udp_size < 512 or extended & ~0x8000 or cursor + 11 + size != len(packet):
            return None
        option = cursor + 11
        while option < len(packet):
            if option + 4 > len(packet):
                return None
            option_size = struct.unpack("!H", packet[option + 2 : option + 4])[0]
            option += 4 + option_size
            if option > len(packet):
                return None
    elif cursor != len(packet):
        return None
    target = _wire_name(LOOPBACK_NAME)
    header = struct.pack("!6H", identifier, 0x8400 | (flags & 0x0100), 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, len(target)) + target
    return header + packet[12:cursor] + answer


class LoopbackPTRResponder:
    """One UDP socket on an OS-selected loopback port, with bounded shutdown."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._socket.bind(("127.0.0.1", 0))
            self._socket.settimeout(0.1)
        except BaseException:
            self._socket.close()
            raise
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._counts = {"received": 0, "answered": 0, "rejected": 0, "errors": 0}
        self._selftest_counts = dict.fromkeys(self._counts, 0)
        self._selftest_peer: tuple[str, int] | None = None
        self._selftest_socket: socket.socket | None = None
        self._selftest_done = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="qualification-loopback-ptr", daemon=True)

    def __enter__(self) -> LoopbackPTRResponder:
        self._thread.start()
        return self

    def _increment(self, name: str, *, selftest: bool = False) -> None:
        with self._lock:
            (self._selftest_counts if selftest else self._counts)[name] += 1

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                packet, peer = self._socket.recvfrom(MAX_QUERY_BYTES + 1)
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._increment("errors")
                return
            with self._lock:
                selftest = peer == self._selftest_peer
            self._increment("received", selftest=selftest)
            response = ptr_response(packet) if peer[0] == "127.0.0.1" else None
            if response is None:
                self._increment("rejected", selftest=selftest)
                if selftest:
                    self._selftest_done.set()
                continue
            try:
                self._socket.sendto(response, peer)
                self._increment("answered", selftest=selftest)
            except OSError:
                self._increment("errors", selftest=selftest)
            if selftest:
                self._selftest_done.set()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def self_test(self, *, deadline: float) -> dict[str, object]:
        """Send one fixed PTR datagram; keep its traffic outside OS-query counts."""
        started = time.monotonic()
        report: dict[str, object] = {"status": "failed", "response_verified": False}
        packet = struct.pack("!6H", 0x4847, 0x0100, 1, 0, 0, 0) + _wire_name(REVERSE_NAME) + struct.pack("!HH", 12, 1)
        try:
            if self._selftest_socket is not None:
                raise ValueError("selftest_already_attempted")
            client = self._selftest_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            until = min(started + 1.0, deadline)
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            client.settimeout(remaining)
            with self._lock:
                self._selftest_peer = client.getsockname()
            client.sendto(packet, ("127.0.0.1", self.port))
            response, peer = client.recvfrom(MAX_QUERY_BYTES + 1)
            if (
                peer == ("127.0.0.1", self.port)
                and response == ptr_response(packet)
                and self._selftest_done.wait(max(0.0, until - time.monotonic()))
            ):
                report.update(status="completed", response_verified=True)
        except TimeoutError:
            report["status"] = "deadline_exceeded"
        except (OSError, ValueError):
            pass
        finally:
            # Keep the bound socket until shutdown: its ephemeral port cannot
            # be reused by OS queries and late selftest traffic stays separate.
            with self._lock:
                report["traffic"] = dict(self._selftest_counts)
        report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        return report

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)
        self._socket.close()
        if self._selftest_socket is not None:
            self._selftest_socket.close()
        if self._thread.is_alive():
            raise RuntimeError("loopback_responder_shutdown_failed")


def resolver_configuration(port: int, owner: str) -> bytes:
    if type(port) is not int or not 1 <= port <= 65535 or re.fullmatch(r"[0-9a-f]{32}", owner) is None:
        raise ValueError("resolver_configuration_invalid")
    return (
        f"# HOL Guard qualification PTR owner {owner}\n"
        f"domain {REVERSE_NAME}\n"
        "nameserver 127.0.0.1\n"
        f"port {port}\n"
        "timeout 1\n"
        "options attempts:1\n"
    ).encode("ascii")


def _directory_fd(directory: Path, *, create: bool) -> int:
    if create:
        directory.mkdir(mode=0o755, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(fd)
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        os.close(fd)
        raise ValueError("resolver_directory_not_private_to_owner")
    return fd


def install_configuration(directory: Path, port: int, owner: str) -> bool:
    """Create only the fixed resolver file; existing files and symlinks win."""
    content = resolver_configuration(port, owner)
    directory_fd = _directory_fd(directory, create=True)
    try:
        try:
            fd = os.open(REVERSE_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=directory_fd)
        except FileExistsError:
            return False
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        return True
    finally:
        os.close(directory_fd)


def remove_configuration(directory: Path, port: int, owner: str) -> bool:
    """Remove only the regular file whose complete bytes belong to this run."""
    content = resolver_configuration(port, owner)
    try:
        directory_fd = _directory_fd(directory, create=False)
    except FileNotFoundError:
        return True
    try:
        try:
            fd = os.open(REVERSE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            return True
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or handle.read(len(content) + 1) != content:
                return False
        current = os.stat(REVERSE_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            return False
        os.unlink(REVERSE_NAME, dir_fd=directory_fd)
        return True
    finally:
        os.close(directory_fd)


def main() -> int:
    # This self-contained helper runs under isolated Python. It accepts no path,
    # nameserver, domain, shell command, or arbitrary file content from callers.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=("install", "remove"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--owner", required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() != 0:
        return 1
    try:
        resolver_configuration(args.port, args.owner)
        if args.operation == "install":
            return 0 if install_configuration(RESOLVER_DIRECTORY, args.port, args.owner) else 2
        return 0 if remove_configuration(RESOLVER_DIRECTORY, args.port, args.owner) else 3
    except (OSError, TypeError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
