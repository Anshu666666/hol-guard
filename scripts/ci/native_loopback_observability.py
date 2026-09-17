"""Read-only, bounded macOS resolver evidence with a finite public projection."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import stat
import subprocess
import time
from contextlib import suppress
from pathlib import Path

if __package__:
    from .native_loopback_dns import REVERSE_NAME
else:
    from native_loopback_dns import REVERSE_NAME  # pyright: ignore[reportImplicitRelativeImport]

_CAPTURE_BYTES = 65536
_PHASES = frozenset({"before", "after", "after_cleanup"})


def libc_query(started_marker: str) -> str:
    """Call libSystem with packed IPv4 bytes, bypassing Python socket conversion.

    Only pointer presence leaves the child. It neither dereferences static
    hostent storage nor claims that a returned name was the fixture's label.
    Darwin socklen_t is uint32_t; AF_INET is 2 on both supported macOS targets.
    """
    return (
        "import ctypes,json; libc=ctypes.CDLL('/usr/lib/libSystem.B.dylib'); "
        "lookup=libc.gethostbyaddr; lookup.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int]; "
        "lookup.restype=ctypes.c_void_p; address=(ctypes.c_ubyte*4)(127,0,0,1); "
        f"print({started_marker!r},flush=True); "
        "result=lookup(ctypes.byref(address),4,2); print(json.dumps({'result_present':result is not None}))"
    )


def registration_projection(data: bytes, expected_port: int | None) -> dict[str, bool | None]:
    """Match fields within the same exact-domain resolver block, never substrings."""
    if len(data) > _CAPTURE_BYTES or (
        expected_port is not None and (type(expected_port) is not int or not 1 <= expected_port <= 65535)
    ):
        raise ValueError("resolver_projection_bounds")
    decoded = data.decode("utf-8", errors="strict")
    if decoded.strip() != "No DNS configuration available" and not decoded.startswith("DNS configuration\n"):
        raise ValueError("resolver_output_unrecognized")
    blocks = re.split(r"(?m)^\s*resolver #[0-9]+\s*$", decoded)[1:]
    exact = loopback = matching = port_present = False
    for block in blocks:
        domains = re.findall(r"(?m)^\s*domain\s*:\s*(\S+)[ \t]*$", block)
        if domains != [REVERSE_NAME]:
            continue
        exact = True
        servers = re.findall(r"(?m)^\s*nameserver\[[0-9]+\]\s*:\s*(\S+)[ \t]*$", block)
        ports = re.findall(r"(?m)^\s*port\s*:\s*([0-9]+)[ \t]*$", block)
        same_server = servers == ["127.0.0.1"]
        same_port = expected_port is not None and ports == [str(expected_port)]
        loopback |= same_server
        port_present |= same_port
        matching |= same_server and same_port
    return {
        "exact_zone_present": exact,
        "loopback_nameserver_only": loopback,
        "expected_port_present": port_present if expected_port is not None else None,
        "matching_registration_present": matching if expected_port is not None else None,
    }


def _capture_scutil(deadline: float) -> tuple[str, bytes, bytes, int | None]:
    """Keep at most 64KiB per stream and terminate on overflow or deadline."""
    if time.monotonic() >= deadline:
        return "deadline_exceeded", b"", b"", None
    process = subprocess.Popen(
        ["/usr/sbin/scutil", "--dns"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert process.stdout is not None and process.stderr is not None
    retained = {"stdout": bytearray(), "stderr": bytearray()}
    status = "completed"
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "deadline_exceeded"
                    break
                for key, _events in selector.select(remaining):
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    destination = retained[key.data]
                    available = _CAPTURE_BYTES - len(destination)
                    destination.extend(chunk[:available])
                    if len(chunk) > available:
                        status = "output_bound"
                        break
                if status != "completed":
                    break
        if status == "completed":
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = "deadline_exceeded"
        if status != "completed" and process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            status = "cleanup_incomplete"
        if status == "completed" and process.returncode != 0:
            status = "failed"
        return status, bytes(retained["stdout"]), bytes(retained["stderr"]), process.returncode
    except (OSError, ValueError):
        return "failed", bytes(retained["stdout"]), bytes(retained["stderr"]), process.returncode
    finally:
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=1.0)
        process.stdout.close()
        process.stderr.close()


def scutil_diagnostics(*, expected_port: int | None, deadline: float) -> tuple[dict[str, object], dict[str, object]]:
    started = time.monotonic()
    try:
        status, stdout, stderr, returncode = _capture_scutil(deadline)
    except (OSError, ValueError):
        status, stdout, stderr, returncode = "failed", b"", b"", None
    projection: dict[str, bool | None] = dict.fromkeys(
        ("exact_zone_present", "loopback_nameserver_only", "expected_port_present", "matching_registration_present")
    )
    if status == "completed":
        try:
            projection = registration_projection(stdout, expected_port)
        except ValueError:
            status = "invalid_output"
    public: dict[str, object] = {
        "status": status,
        **projection,
        "stdout_bytes_retained": len(stdout),
        "stderr_bytes_retained": len(stderr),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }
    private: dict[str, object] = {
        "schema": "hol-guard.resolver-scutil-private.v1",
        "status": status,
        "returncode": returncode,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
    }
    return public, private


def retain_private_captures(directory: Path, captures: dict[str, dict[str, object]]) -> bool:
    """Publish only after the paired command's empty-directory admission.

    Fixed flat JSON names are compatible with the existing encrypted archive.
    No plaintext path or captured output is returned into public diagnostics.
    """
    if set(captures) - _PHASES:
        return False
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(parent)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                return False
            for phase, capture in captures.items():
                content = json.dumps(capture, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
                if len(content) > 192 * 1024:
                    return False
                descriptor = os.open(
                    f"resolver-{phase}-scutil.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            os.close(parent)
        return True
    except (OSError, ValueError):
        return False
