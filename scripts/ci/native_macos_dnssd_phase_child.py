"""Run the bounded call observer with the preceding Python runtime and DNS-SD call policy."""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.native_macos_dnssd_python_child import runtime_identity as base_runtime_identity
from scripts.ci.native_macos_python_resolver_child import bridge_image, emit, file_sha

MODES = ("dns_simple", "dns_shared")
CALL_POLICY = "ctypes.CDLL_releases_GIL_no_explicit_thread_creation"


def runtime_identity() -> dict[str, str]:
    return base_runtime_identity() | {"phase_child_source_sha256": file_sha(Path(__file__))}


def execute(mode: str, bridge: Path, expected_sha: str) -> int:
    if mode not in MODES:
        return 64
    stage = "runtime_binding"
    try:
        before = runtime_identity()
        emit("python_identity", mode=mode, pid=os.getpid(), call_policy=CALL_POLICY, **before)
        stage = "before_load"
        emit("phase", phase=stage)
        if file_sha(bridge) != expected_sha:
            raise ValueError("bridge changed")
        # Match the preceding C-in-Python controls: CDLL releases the GIL while
        # the native function runs. This child creates no Python/native thread.
        # Libinfo/DNS-SD may create internal threads; no thread census is claimed.
        library = ctypes.CDLL(str(bridge))
        stage = "after_load"
        emit("phase", phase=stage)
        library.hol_guard_dnssd_python_call.argtypes = [ctypes.c_uint]
        library.hol_guard_dnssd_python_call.restype = ctypes.c_int
        library.hol_guard_resolver_bridge_identity.argtypes = [ctypes.POINTER(ctypes.c_char)] * 3 + [ctypes.c_uint]
        library.hol_guard_resolver_bridge_identity.restype = ctypes.c_int
        bridge_image(library, "before")
        stage = "call_enter"
        emit("phase", phase=stage)
        code = library.hol_guard_dnssd_python_call(int(mode == "dns_shared"))
        stage = "call_return"
        emit("phase", phase=stage)
        bridge_image(library, "after")
        stage = "final_binding"
        after = runtime_identity()
        bridge_after = file_sha(bridge)
        if after != before or bridge_after != expected_sha:
            raise ValueError("execution identity changed")
        emit("python_complete", return_code=code, bridge_sha256=bridge_after, **after)
        return code
    except (OSError, ValueError, AttributeError) as error:
        emit("failure", stage=stage, error_type="OSError" if isinstance(error, OSError) else type(error).__name__)
        return 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-sha256", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.bridge_sha256) is None:
        return 64
    return execute(args.mode, args.bridge, args.bridge_sha256)


if __name__ == "__main__":
    raise SystemExit(main())
