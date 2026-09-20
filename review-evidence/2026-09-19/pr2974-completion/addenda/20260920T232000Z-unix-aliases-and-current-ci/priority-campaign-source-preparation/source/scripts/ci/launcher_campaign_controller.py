"""Trusted Linux host controller for one reviewed priority campaign arm.

No product code is imported as root. The worker enters one new protected group,
drops supplementary groups/GID/UID and gains no-new-privileges before exec. The
80-minute outer budget does not replace any original launcher/producer deadline.
Output contains a PRIVATE intermediate body; the workflow must never upload it
or print it before the separate unprivileged export/cleanup join succeeds.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import selectors
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts.ci.qualification_cpu_controller import ROOT, drop_worker_identity, group_empty, kill_group

ARM_SECONDS = 80 * 60
STDOUT_LIMIT = 8 * 1024 * 1024 + 1
STDERR_LIMIT = 64 * 1024


def collect(
    process: subprocess.Popen[bytes],
    kill_owned: Callable[[], None],
    *,
    wall_seconds: float = ARM_SECONDS,
) -> tuple[bytes, bytes, str | None]:
    """Bound both streams and elapsed host time, including inherited writers."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": STDOUT_LIMIT, "stderr": STDERR_LIMIT}
    deadline = time.monotonic() + wall_seconds
    failure = None
    try:
        with selectors.DefaultSelector() as selector:
            for name in buffers:
                stream = getattr(process, name)
                if stream is None:
                    raise ValueError("campaign_controller_missing_stream")
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "wall_time"
                    break
                for key, _events in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    available = limits[name] - len(buffers[name])
                    buffers[name].extend(chunk[: max(0, available)])
                    if len(chunk) > available:
                        failure = "stdout_limit" if name == "stdout" else "stderr_limit"
                        break
                if failure is not None:
                    break
    except BaseException:
        failure = "stream_io"
    if failure is not None:
        try:
            kill_owned()
        except BaseException:
            failure += "_kill_failed"
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), failure


def run(python: Path, configuration: Path, configuration_sha256: str, uid: int, gid: int) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.launcher-host-controller.v1",
        "worker_launched": False,
        "worker_exit": None,
        "configuration_sha256": configuration_sha256,
        "outer_wall_seconds": ARM_SECONDS,
        "collection_failure": None,
        "fault": None,
        "cleanup_complete": False,
        "group_empty_before_cleanup": None,
        "emergency_group_kill_used": False,
        "worker_reaped": False,
        "private_body_is_export_approved": False,
    }
    group: Path | None = None
    group_fd = -1
    process = None
    stdout = stderr = b""
    try:
        if sys.platform != "linux" or os.getresuid() != (0, 0, 0) or uid <= 0 or gid <= 0:
            raise ValueError("campaign_controller_identity")
        if sys.flags.isolated != 1 or sys.flags.no_site != 1 or len(os.listdir("/proc/self/task")) != 1:
            raise ValueError("campaign_controller_isolation")
        if len(configuration_sha256) != 64 or any(char not in "0123456789abcdef" for char in configuration_sha256):
            raise ValueError("campaign_controller_configuration_hash")
        python = python.absolute()
        if python.is_symlink() or not python.is_file() or not os.access(python, os.X_OK):
            raise ValueError("campaign_controller_interpreter")
        worker = Path(__file__).resolve().with_name("launcher_campaign_worker.py")
        if not worker.is_file():
            raise ValueError("campaign_controller_worker")
        libc: Any = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl.restype = ctypes.c_int
        group = ROOT / ("hol-guard-launcher-campaign-" + uuid.uuid4().hex)
        group.mkdir(mode=0o555)
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(group_fd)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o555 or not group_empty(group_fd):
            raise ValueError("campaign_controller_group")
        kill_fd = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group_fd)
        os.close(kill_fd)
        bootstrap = (
            "import sys;"
            f"sys.path.insert(0,{str(worker.parents[2])!r});"
            "from scripts.ci.launcher_campaign_worker import main;"
            "raise SystemExit(main())"
        )
        command = [
            str(python),
            "-I",
            "-c",
            bootstrap,
            "--group",
            str(group),
            "--configuration",
            str(configuration.absolute()),
            "--configuration-sha256",
            configuration_sha256,
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            pass_fds=(group_fd,),
            preexec_fn=lambda: drop_worker_identity(group_fd, uid, gid, libc),
        )
        report["worker_launched"] = True

        def emergency_kill() -> None:
            report["emergency_group_kill_used"] = True
            kill_group(group_fd)

        stdout, stderr, report["collection_failure"] = collect(process, emergency_kill)
        report["worker_exit"] = process.wait(timeout=1.0)
        report["worker_reaped"] = True
    except BaseException as error:
        report["fault"] = "os" if isinstance(error, OSError) else "controller"
    finally:
        try:
            if group_fd >= 0:
                empty = group_empty(group_fd)
                report["group_empty_before_cleanup"] = empty
                if not empty:
                    report["emergency_group_kill_used"] = True
                    kill_group(group_fd)
                if process is not None:
                    report["worker_exit"] = process.wait(timeout=2.0)
                    report["worker_reaped"] = True
                deadline = time.monotonic() + 2.0
                while not group_empty(group_fd) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not group_empty(group_fd):
                    raise RuntimeError("campaign_controller_group_not_empty")
                os.close(group_fd)
                group_fd = -1
                assert group is not None
                group.rmdir()
            report["cleanup_complete"] = group is None or not group.exists()
        except BaseException:
            report["cleanup_complete"] = False
        finally:
            if group_fd >= 0:
                os.close(group_fd)
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
    for name, value in (("stdout", stdout), ("stderr", stderr)):
        report[name] = {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    # Only the closed unprivileged finalizer may admit/export this candidate.
    # Stderr is never retained beyond its aggregate, even on setup failures.
    report["private_worker_stdout_base64"] = base64.b64encode(stdout).decode("ascii")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args()
    report = run(args.python, args.configuration, args.configuration_sha256, args.uid, args.gid)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return (
        0
        if (
            report["worker_exit"] == 0
            and report["worker_reaped"] is True
            and report["cleanup_complete"] is True
            and report["group_empty_before_cleanup"] is True
            and report["emergency_group_kill_used"] is False
            and report["collection_failure"] is None
            and report["fault"] is None
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
