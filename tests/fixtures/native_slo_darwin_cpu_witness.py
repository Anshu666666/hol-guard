"""Owned Darwin-only correctness fixture, never a performance benchmark."""

from __future__ import annotations

import json
import os
import signal
import sys
import time


def burn() -> None:
    # Fixed bounded work makes child CPU distinguishable from clock rounding.
    sum(value * value for value in range(1_000_000))


def nested() -> dict[str, int]:
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read)
        grandchild = os.fork()
        if grandchild == 0:
            os.close(write)
            burn()
            os._exit(0)
        _, status, usage = os.wait4(grandchild, 0)
        if status != 0:
            os._exit(2)
        burn()
        os.write(write, str(round((usage.ru_utime + usage.ru_stime) * 1e9)).encode("ascii"))
        os.close(write)
        os._exit(0)
    os.close(write)
    _, status, usage = os.wait4(child, 0)
    raw = os.read(read, 64)
    os.close(read)
    if status != 0:
        raise RuntimeError("child failed")
    return {"waited_cpu_ns": round((usage.ru_utime + usage.ru_stime) * 1e9), "grandchild_cpu_ns": int(raw)}


def ignored() -> dict[str, int]:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read)
        burn()
        os.write(write, str(time.process_time_ns()).encode("ascii"))
        os.close(write)
        os._exit(0)
    os.close(write)
    raw = os.read(read, 64)
    os.close(read)
    # We cannot wait4 an ignored child. Require that the kernel actually reaped
    # this owned child before reporting; never infer it from elapsed time alone.
    deadline = time.monotonic() + 5
    while True:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("ignored child did not retire")
        time.sleep(0.001)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    return {"child_cpu_ns": int(raw)}


def main() -> None:
    print("ready", flush=True)
    for line in sys.stdin:
        command = line.strip()
        if command == "stop":
            return
        result = {"nested": nested, "ignored": ignored}[command]()
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
