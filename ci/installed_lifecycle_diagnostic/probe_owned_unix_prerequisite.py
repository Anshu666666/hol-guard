"""Check the Linux Unix-listener prerequisite without importing/running Guard.

Use one newly allocated private /tmp directory. Record this interpreter's birth
identity before attempting socket creation, bind/listen, permissions, and
nonblocking mode, matching the native listener's prerequisite order. Do not
alter any resident, startup deadline, transport, selector, policy, or admission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import stat
import sys
import tempfile
from pathlib import Path


def process_identity(pid: int) -> dict[str, object]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2 :].split()
    return {
        "pid": pid,
        "start_marker": "linux:" + fields[19],
        "parent_pid": int(fields[1]),
        "process_group": int(fields[2]),
        "state": fields[0],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and sys.flags.isolated and not args.output.exists()
    executable = Path(sys.executable).resolve()
    receipt: dict[str, object] = {
        "schema": "owned-unix-listener-prerequisite.v1",
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "native_execution_performed": False,
        "guard_imported": False,
        "process_before_attempt": process_identity(os.getpid()),
        "parent_before_attempt": process_identity(os.getppid()),
        "python_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "constraints": {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith(
                ("NoNewPrivs:", "Seccomp:", "Seccomp_filters:", "CapEff:")
            )
        },
        "completed_steps": [],
        "cleanup_errors": [],
    }
    steps: list[str] = []
    cleanup_errors: list[dict[str, object]] = []
    directory = None
    endpoint = None
    listener = None
    step = "private_directory"
    try:
        directory = Path(tempfile.mkdtemp(prefix="hgr-prerequisite-", dir="/tmp"))
        metadata = directory.lstat()
        assert (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and metadata.st_mode & 0o077 == 0
        )
        endpoint = directory / "h3-prerequisite.sock"
        assert not os.path.lexists(endpoint) and len(os.fsencode(endpoint)) <= 100
        receipt["endpoint_path_bytes"] = len(os.fsencode(endpoint))
        steps.append(step)
        step = "socket_af_unix_stream"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        steps.append(step)
        step = "bind_owned_endpoint"
        listener.bind(str(endpoint))
        steps.append(step)
        step = "listen_owned_endpoint"
        listener.listen(128)
        steps.append(step)
        step = "chmod_owned_socket_0600"
        os.chmod(endpoint, 0o600)
        steps.append(step)
        step = "set_nonblocking"
        listener.setblocking(False)
        steps.append(step)
        receipt["result"] = "prerequisite_available"
    except BaseException as error:
        receipt["result"] = "prerequisite_failed"
        receipt["failure"] = {
            "step": step,
            "error_type": type(error).__name__,
            "errno": error.errno if isinstance(error, OSError) else None,
        }
    finally:
        if listener is not None:
            try:
                listener.close()
            except BaseException as error:
                cleanup_errors.append(
                    {"step": "close_own_socket", "error_type": type(error).__name__}
                )
        if endpoint is not None and os.path.lexists(endpoint):
            try:
                metadata = endpoint.lstat()
                assert (
                    stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid()
                )
                endpoint.unlink()
            except BaseException as error:
                cleanup_errors.append(
                    {"step": "unlink_own_socket", "error_type": type(error).__name__}
                )
        if directory is not None:
            try:
                directory.rmdir()
            except BaseException as error:
                cleanup_errors.append(
                    {
                        "step": "remove_own_empty_directory",
                        "error_type": type(error).__name__,
                    }
                )
        receipt["completed_steps"] = steps
        receipt["cleanup_errors"] = cleanup_errors
        receipt["owned_directory_removed"] = directory is None or not directory.exists()
        if cleanup_errors:
            receipt["result"] = "cleanup_failed"
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(
        json.dumps(
            {
                "result": receipt["result"],
                "failure": receipt.get("failure"),
                "cleanup_errors": cleanup_errors,
                "receipt_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
            }
        )
    )
    return int(receipt["result"] != "prerequisite_available")


if __name__ == "__main__":
    raise SystemExit(main())
