"""Call the new observer using the preceding CDLL ABI and explicit loader flags."""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.native_macos_dnssd_phase_child import CALL_POLICY, MODES
from scripts.ci.native_macos_dnssd_endpoint_child import runtime_identity as original_runtime_identity
from scripts.ci.native_macos_python_resolver_child import bridge_image, emit, file_sha

RUNTIME_KEY = "signal_child_source_sha256"
CONDITIONS = ("default", "ignore")


def runtime_identity() -> dict[str, str]:
    return original_runtime_identity() | {RUNTIME_KEY: file_sha(Path(__file__))}


def execute(mode: str, bridge: Path, expected_sha: str, condition: str) -> int:
    if mode not in MODES or condition not in CONDITIONS:
        return 64
    stage = "runtime_binding"
    library: ctypes.CDLL | None = None
    signal_started = signal_finished = False
    try:
        before = runtime_identity()
        emit("python_identity", mode=mode, pid=os.getpid(), call_policy=CALL_POLICY, **before)
        stage = "before_load"
        emit("phase", phase=stage)
        if file_sha(bridge) != expected_sha or ctypes.RTLD_LOCAL != os.RTLD_LOCAL:
            raise ValueError("bridge or loader flags")
        flags = os.RTLD_NOW | os.RTLD_LOCAL
        library = ctypes.CDLL(str(bridge), mode=flags)
        stage = "after_load"
        emit("phase", phase=stage)
        library.hol_guard_endpoint_configure.argtypes = [ctypes.c_uint, ctypes.c_int]
        library.hol_guard_endpoint_configure.restype = ctypes.c_int
        if library.hol_guard_endpoint_configure(2, flags) != 0:
            raise ValueError("observer configuration")
        library.hol_guard_dnssd_python_call.argtypes = [ctypes.c_uint]
        library.hol_guard_dnssd_python_call.restype = ctypes.c_int
        library.hol_guard_resolver_bridge_identity.argtypes = [ctypes.POINTER(ctypes.c_char)] * 3 + [ctypes.c_uint]
        library.hol_guard_resolver_bridge_identity.restype = ctypes.c_int
        library.hol_guard_sigpipe_enter.argtypes = [ctypes.c_uint]
        library.hol_guard_sigpipe_enter.restype = ctypes.c_int
        library.hol_guard_sigpipe_leave.argtypes = []
        library.hol_guard_sigpipe_leave.restype = ctypes.c_int
        stage = "signal_install"
        signal_started = True
        if library.hol_guard_sigpipe_enter(int(condition == "ignore")) != 0:
            raise ValueError("SIGPIPE condition installation")
        bridge_image(library, "before")
        stage = "call_enter"
        emit("phase", phase=stage)
        code = library.hol_guard_dnssd_python_call(int(mode == "dns_shared"))
        stage = "signal_restore"
        signal_finished = True
        if library.hol_guard_sigpipe_leave() != 0:
            raise ValueError("SIGPIPE condition restoration")
        stage = "call_return"
        emit("phase", phase=stage)
        bridge_image(library, "after")
        stage = "final_binding"
        after, bridge_after = runtime_identity(), file_sha(bridge)
        if after != before or bridge_after != expected_sha:
            raise ValueError("execution identity changed")
        emit("python_complete", return_code=code, bridge_sha256=bridge_after, **after)
        return code
    except (OSError, ValueError, AttributeError) as error:
        emit("failure", stage=stage, error_type="OSError" if isinstance(error, OSError) else type(error).__name__)
        return 3
    finally:
        if library is not None and signal_started and not signal_finished:
            try:
                if library.hol_guard_sigpipe_leave() != 0:
                    emit("failure", stage="signal_restore", error_type="ValueError")
            except (OSError, ValueError, AttributeError) as error:
                emit("failure", stage="signal_restore", error_type=type(error).__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--condition", choices=CONDITIONS, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-sha256", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.bridge_sha256) is None:
        return 64
    return execute(args.mode, args.bridge, args.bridge_sha256, args.condition)


if __name__ == "__main__":
    raise SystemExit(main())
