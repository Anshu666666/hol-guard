"""Opt-in pytest alias attachment; original fixture teardown runs while attached."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime.mac_recovery_capture import Capture, Proxy

NODE = "ci/native_runtime/test_native_hook_client.py::test_native_hook_client_recovers_after_supervisor_exit"
ROOT = Path(__file__).resolve().parents[2]
BINDINGS = {
    "ci/native_runtime/test_native_hook_client.py": "8c5c02d2df7d997962890b3c394ad73b83ed295dd33b7820ebacdb621f8f44b8",
    "ci/native_runtime/native_hook_client_support.py": (
        "624481f37c833871e14cc4a429c4130122bfe99c41108f2727a01f554d180d5b"
    ),
}
_active: Capture | None = None
_restore: list[tuple[Any, str, Any, Any]] = []


def verify_origins(test: Any, support: Any) -> None:
    if (
        Path(test.__file__).resolve() != ROOT / "ci/native_runtime/test_native_hook_client.py"
        or Path(support.__file__).resolve() != ROOT / "ci/native_runtime/native_hook_client_support.py"
    ):
        raise ValueError("actual_module_origin")
    for name, expected in BINDINGS.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("original_source_binding")


def attach(test: Any, support: Any, runtime: Path, state: Path) -> Capture:
    capture = Capture(str(runtime), str(state))
    original_json, original_os, original_process = test.json, support.os, support.subprocess

    def loads(*args: Any, **kwargs: Any) -> Any:
        value = original_json.loads(*args, **kwargs)
        capture.safe(lambda: capture.observe_state(value))
        return value

    replacements = [
        (test, "json", original_json, Proxy(original_json, {"loads": loads})),
        (
            support,
            "os",
            original_os,
            Proxy(original_os, {"kill": lambda *a, **k: capture.kill(original_os.kill, *a, **k)}),
        ),
        (
            support,
            "subprocess",
            original_process,
            Proxy(original_process, {"run": lambda *a, **k: capture.run(original_process.run, *a, **k)}),
        ),
    ]
    try:
        for module, name, original, replacement in replacements:
            _restore.append((module, name, original, replacement))
            setattr(module, name, replacement)
    except BaseException:
        capture.faults += 1
        restore(capture)
    return capture


def restore(capture: Capture) -> None:
    success = True
    for module, name, original, replacement in reversed(_restore):
        try:
            if getattr(module, name) is not replacement:
                success = False
            setattr(module, name, original)
        except BaseException:
            success = False
    _restore.clear()
    capture.restoration_failed = capture.restoration_failed or not success
    capture.restored = success and not capture.restoration_failed


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: Any) -> Any:
    global _active
    if item.nodeid == NODE:
        try:
            from ci.native_runtime import native_hook_client_support as support

            verify_origins(item.module, support)
            runtime, state = item.funcargs["native_runtime"]
            if type(runtime) is not type(Path()) or type(state) is not type(Path()):
                raise ValueError("owned_fixture_type")
            if state != item.funcargs["tmp_path"] / "native-runtime":
                raise ValueError("owned_fixture_scope")
            _active = attach(item.module, support, runtime, state)
        except BaseException:
            _active = Capture("", "")
            _active.faults += 1
    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Any:
    outcome = yield
    report = outcome.get_result()
    if item.nodeid == NODE and report.when == "call" and _active is not None:
        _active.test_outcome = report.outcome if report.outcome in {"passed", "failed", "skipped"} else "unregistered"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: Any, nextitem: Any) -> Any:
    yield
    if item.nodeid == NODE and _active is not None:
        restore(_active)
        try:
            encoded = json.dumps(_active.document(), sort_keys=True).encode("utf-8") + b"\n"
            if len(encoded) > 262144:
                raise ValueError("observation_output_bound")
            output = Path(os.environ["MAC_RECOVERY_OBSERVATION"])
            with output.open("xb") as stream:
                stream.write(encoded)
        except BaseException:
            # The separate driver admission rejects missing or incomplete output.
            # Never replace the original test/teardown result with export failure.
            return
