"""Diagnostic-only spans around unchanged isolated hook-worker execution."""
from __future__ import annotations

import functools
import hashlib
import json
import math
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

NODE = "tests/test_guard_hook_process_runner.py::test_prewarmed_runner_does_not_hide_a_second_worker_queue"
PINS = {
    "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py": "f93fd883481f65baed1fa80ac3d9cbb1a3bd6c6f",
    "src/codex_plugin_scanner/guard/daemon/hook_process_request.py": "75014a4c66c6ebb056921f5e2758162bf0d18b6d",
    "src/codex_plugin_scanner/guard/daemon/hook_process_runner.py": "7f036980410215bee326e27f433ab71720c0581c",
    "src/codex_plugin_scanner/guard/daemon/hook_process_slot_review.py": "1d6cab3445585c23111d9854bb95c7036af15590",
    "src/codex_plugin_scanner/guard/daemon/hook_worker.py": "ed969bba5cacff2bb80491a871bf82d645e4c042",
    "src/codex_plugin_scanner/guard/cli/commands_hook.py": "45b8d6dfa3403a25deda44d4ab38f47f6f91cba4",
    "src/codex_plugin_scanner/guard/cli/commands_hook_compat_loader.py": "f2228533cb829f5242260350412b6395d7f0953f",
}
PHASES = frozenset({
    "parent-observer", "parent-finished", "evaluator-observer", "observer-cap",
    "parent-review", "slot-roundtrip", "resident-request", "store-context",
    "worker-construction", "worker-review", "policy-readiness",
    "native-edge", "native-pretool", "compatibility-hook", "compatibility-imports",
})
_LOCK = threading.Lock()
_COUNT = 0


def _root():
    path = Path(os.environ["PREWARM_SPAN_DIR"])
    expected = Path(os.environ["RUNNER_TEMP"]) / "guard-prewarm-causal" / "spans"
    if path != expected or path.is_symlink() or not path.is_dir():
        raise ValueError("observer_output_unavailable")
    return path


def _record(phase, seconds):
    global _COUNT
    try:
        if phase not in PHASES or not math.isfinite(seconds) or not 0 <= seconds <= 180:
            raise ValueError("observer_value")
        with _LOCK:
            if _COUNT > 512:
                return
            if _COUNT == 512:
                phase, seconds = "observer-cap", 0.0
            _COUNT += 1
            data = (json.dumps({"phase": phase, "seconds": seconds}) + "\n").encode()
            path = _root() / ("span-" + str(os.getpid()) + ".jsonl")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(fd, data) != len(data):
                    raise OSError("observer_short_write")
            finally:
                os.close(fd)
    except BaseException:
        # Observer failure never changes a product return or replaces its exception.
        try:
            os.write(2, b"PREWARM_OBSERVER_INCOMPLETE\n")
        except OSError:
            pass


def _pin(function, relative, line):
    path = Path(relative).resolve()
    code = function.__code__
    data = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if (blob != PINS[relative] or Path(code.co_filename).resolve() != path
            or code.co_firstlineno != line):
        raise ValueError("observer_source_mismatch")


def _wrap(function, phase):
    @functools.wraps(function)
    def timed(*args, **kwargs):
        start = time.monotonic()
        try:
            return function(*args, **kwargs)
        finally:
            _record(phase, time.monotonic() - start)
    return timed


@contextmanager
def _evaluator_spans():
    from codex_plugin_scanner.guard.cli import commands_hook
    from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as entry
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

    bindings = [
        (entry, "_run_resident_hook_request", "resident-request", "daemon/hook_process_entrypoint.py", 256),
        (entry, "resident_hook_store_and_context", "store-context", "daemon/hook_process_request.py", 113),
        (HookWorker, "__init__", "worker-construction", "daemon/hook_worker.py", 114),
        (HookWorker, "review_http_payload", "worker-review", "daemon/hook_worker.py", 271),
        (HookWorker, "prepare_workspace_policy", "policy-readiness", "daemon/hook_worker.py", 212),
        (HookWorker, "_review_raw_hook_native", "native-edge", "daemon/hook_worker.py", 166),
        (HookWorker, "_review_pre_tool_native", "native-pretool", "daemon/hook_worker.py", 193),
        (commands_hook, "_run_guard_hook_command", "compatibility-hook", "cli/commands_hook.py", 88),
        (commands_hook, "load_hook_compatibility_surface", "compatibility-imports", "cli/commands_hook_compat_loader.py", 37),
    ]
    with pytest.MonkeyPatch.context() as patch:
        for owner, name, phase, suffix, line in bindings:
            original = getattr(owner, name)
            _pin(original, "src/codex_plugin_scanner/guard/" + suffix, line)
            patch.setattr(owner, name, _wrap(original, phase))
        _record("evaluator-observer", 0.0)
        yield


def observed_evaluator(connection, configured_guard_home):
    from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as entry

    original_loop = entry._hook_evaluator_loop
    _pin(original_loop, "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py", 167)

    def observed_loop(*args, **kwargs):
        # Bootstrap imports remain in the real evaluator before any wrappers install.
        with _evaluator_spans():
            return original_loop(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(entry, "_hook_evaluator_loop", observed_loop)
        return entry._hook_evaluator_main(connection, configured_guard_home)



def _register_guardian():
    # Register before the real guardian detaches; no store or request is created.
    pid = os.getpid()
    fields = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[1].split()
    ticks = int(fields[19])
    if ticks <= 0:
        raise ValueError("observer_identity")
    path = _root() / ("guardian-" + str(pid) + ".json")
    data = (json.dumps({"pid": pid, "startTicks": ticks}) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("observer_short_write")
    finally:
        os.close(fd)


def observed_guardian(connection, configured_guard_home):
    from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as entry

    _pin(entry.hook_worker_main, "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py", 58)
    _register_guardian()
    _pin(entry._hook_evaluator_main, "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py", 138)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(entry, "_hook_evaluator_main", observed_evaluator)
        return entry.hook_worker_main(connection, configured_guard_home)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    if item.nodeid != NODE:
        raise ValueError("observer_unexpected_test")
    from codex_plugin_scanner.guard.daemon import hook_process_spawner as spawner
    from codex_plugin_scanner.guard.daemon import hook_process_slot_review as slot_review
    from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner

    _root()
    _pin(HookProcessRunner.review, "src/codex_plugin_scanner/guard/daemon/hook_process_runner.py", 183)
    _pin(slot_review._send_review_to_slot, "src/codex_plugin_scanner/guard/daemon/hook_process_slot_review.py", 68)
    _pin(spawner.hook_worker_main, "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py", 58)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(spawner, "hook_worker_main", observed_guardian)
        patch.setattr(HookProcessRunner, "review", _wrap(HookProcessRunner.review, "parent-review"))
        patch.setattr(slot_review, "_send_review_to_slot", _wrap(slot_review._send_review_to_slot, "slot-roundtrip"))
        _record("parent-observer", 0.0)
        try:
            yield
        finally:
            _record("parent-finished", 0.0)
