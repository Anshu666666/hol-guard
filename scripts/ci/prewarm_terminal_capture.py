"""Closed terminal observation for one exact CPython test code object."""
from __future__ import annotations

import math
import sys
from types import CodeType

TOOL_ID = 5
TOOL_NAME = "guard-terminal-boundary"
COUNTERS = ("configured", "workers", "ready", "busy", "target", "timeouts", "failures", "restarts")
REASONS = frozenset({
    "daemon_hook_process_closed", "daemon_hook_process_deadline_exhausted",
    "daemon_hook_process_failed", "daemon_hook_process_guard_home_mismatch",
    "daemon_hook_process_invalid_json", "daemon_hook_process_invalid_request",
    "daemon_hook_process_not_ready", "daemon_hook_process_timeout",
})


def supported_interpreter():
    return sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 13, 15)


def project_boundary(frame, review_type):
    """Copy finite allowlisted values; never retain the frame or arbitrary locals."""
    values = frame.f_locals
    rows, stats = values.get("results"), values.get("runner_stats")
    if type(rows) is not list or len(rows) != 24 or review_type is None or type(stats) is not dict:
        return {"complete": False}
    counts = {key: 0 for key in sorted(REASONS | {"no_reason", "other"})}
    for row in rows:
        if type(row) is not review_type:
            return {"complete": False}
        reason = row.reason_code
        key = "no_reason" if reason is None else reason if type(reason) is str and reason in REASONS else "other"
        counts[key] += 1
    counters = {}
    for key in COUNTERS:
        value = stats.get(key)
        if type(value) is not int or not 0 <= value <= 1000000:
            return {"complete": False}
        counters[key] = value
    timing = {}
    for name in ("elapsed", "timing_scale"):
        value = values.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value < 10000:
            return {"complete": False}
        timing[name] = value
    if timing["timing_scale"] <= 0:
        return {"complete": False}
    return {"complete": True, "results": 24, "reasonCounts": counts,
            "runnerStats": counters, **timing}


def project_original(frame):
    module = sys.modules.get("codex_plugin_scanner.guard.daemon.hook_process_worker")
    return project_boundary(frame, getattr(module, "HookProcessReview", None))


def valid_boundary(value):
    if type(value) is not dict or set(value) != {
        "complete", "results", "reasonCounts", "runnerStats", "elapsed", "timing_scale"
    } or value["complete"] is not True or type(value["results"]) is not int or value["results"] != 24:
        return False
    reasons, stats = value["reasonCounts"], value["runnerStats"]
    if type(reasons) is not dict or set(reasons) != REASONS | {"no_reason", "other"}:
        return False
    if any(type(v) is not int or not 0 <= v <= 24 for v in reasons.values()) or sum(reasons.values()) != 24:
        return False
    if type(stats) is not dict or set(stats) != set(COUNTERS):
        return False
    if any(type(v) is not int or not 0 <= v <= 1000000 for v in stats.values()):
        return False
    for key in ("elapsed", "timing_scale"):
        v = value[key]
        if type(v) not in (float, int) or not math.isfinite(v) or not 0 <= v < 10000:
            return False
    return value["timing_scale"] > 0


class TerminalCapture:
    """Use one local return event; failure frames arrive from pytest afterward."""

    def __init__(self, code, namespace, projector=project_original, *, api=None):
        self.code, self.namespace, self.projector = code, namespace, projector
        self.api = sys.monitoring if api is None else api
        self.callback = self._on_return
        self.owned = self.registered = self.local_requested = self.installed = False
        self.closed = False
        self.return_count = self.failure_count = 0
        self.values = {"complete": False}
        self.errors = []
        self.cleanup = {"complete": False}

    def _error(self, code):
        if code not in self.errors:
            self.errors.append(code)

    def install(self):
        try:
            if not supported_interpreter() or type(self.code) is not CodeType or type(self.namespace) is not dict:
                self._error("admission")
                return False
            if self.api.get_tool(TOOL_ID) is not None:
                self._error("occupied_tool")
                return False
            if self.api.get_events(TOOL_ID) != 0 or self.api.get_local_events(TOOL_ID, self.code) != 0:
                self._error("prior_events")
                return False
            self.api.use_tool_id(TOOL_ID, TOOL_NAME)
            self.owned = True
            if self.api.get_events(TOOL_ID) != 0 or self.api.get_local_events(TOOL_ID, self.code) != 0:
                self._error("prior_events")
                self.close()
                return False
            previous = self.api.register_callback(TOOL_ID, self.api.events.PY_RETURN, self.callback)
            if previous is not None:
                self.api.register_callback(TOOL_ID, self.api.events.PY_RETURN, previous)
                self._error("prior_callback")
                self.close()
                return False
            self.registered = True
            self.local_requested = True
            self.api.set_local_events(TOOL_ID, self.code, self.api.events.PY_RETURN)
            self.installed = True
            return True
        except BaseException:
            self._error("install_failure")
            self.close()
            return False

    def _on_return(self, code, instruction_offset, return_value):
        # CPython documents the callee as frame 1 in the registered callback.
        frame = None
        try:
            frame = sys._getframe(1)
            self.return_count += 1
            if (not self.installed or self.closed or code is not self.code
                    or frame.f_code is not self.code or frame.f_globals is not self.namespace
                    or self.return_count != 1):
                self._error("return_identity")
                return
            self._project(frame)
        except BaseException:
            self._error("collector_failure")
        finally:
            del frame

    def _project(self, frame):
        try:
            value = self.projector(frame)
            if not valid_boundary(value):
                self._error("projection_incomplete")
                return
            self.values = value
        except BaseException:
            self._error("collector_failure")

    def capture_failure(self, error):
        """Only the exact terminal traceback frame is admitted; never alter error."""
        self.failure_count += 1
        if not self.closed or self.return_count != 0 or self.failure_count != 1:
            self._error("failure_count")
            return
        terminal = None
        try:
            terminal = error.__traceback__
            for _ in range(64):
                if terminal is None:
                    break
                if terminal.tb_next is None:
                    frame = terminal.tb_frame
                    if frame.f_code is self.code and frame.f_globals is self.namespace:
                        self._project(frame)
                    else:
                        self._error("failure_identity")
                    return
                terminal = terminal.tb_next
            self._error("failure_traceback")
        except BaseException:
            self._error("collector_failure")
        finally:
            del terminal

    def close(self):
        if self.closed:
            return
        self.closed = True
        clean, released = True, not self.owned
        local_clear, callback_clear = not self.local_requested, not self.registered
        if self.owned:
            if self.local_requested:
                try:
                    self.api.set_local_events(TOOL_ID, self.code, 0)
                    local_clear = self.api.get_local_events(TOOL_ID, self.code) == 0
                except BaseException:
                    clean = False
            if self.registered:
                try:
                    previous = self.api.register_callback(TOOL_ID, self.api.events.PY_RETURN, None)
                    callback_clear = previous is self.callback
                    if not callback_clear:
                        self.api.register_callback(TOOL_ID, self.api.events.PY_RETURN, previous)
                except BaseException:
                    clean = False
            try:
                clean = clean and local_clear and callback_clear
                clean = clean and self.api.get_events(TOOL_ID) == 0
                clean = clean and self.api.get_local_events(TOOL_ID, self.code) == 0
                if clean:
                    self.api.free_tool_id(TOOL_ID)
                    released = self.api.get_tool(TOOL_ID) is None
                clean = clean and released
            except BaseException:
                clean = False
        self.cleanup = {"complete": clean, "leaseReleased": released}
        if not clean:
            self._error("cleanup_failure")

    def snapshot(self, failed):
        counts_valid = (self.return_count, self.failure_count) == ((0, 1) if failed else (1, 0))
        complete = (self.installed and self.closed and self.cleanup["complete"]
                    and counts_valid and self.values.get("complete") is True and not self.errors)
        return {"complete": bool(complete), "returns": self.return_count, "failures": self.failure_count,
                "errors": list(self.errors), "cleanup": dict(self.cleanup),
                "boundary": dict(self.values) if complete else {"complete": False}}
