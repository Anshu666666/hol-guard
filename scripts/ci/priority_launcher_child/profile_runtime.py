"""Copied into an owned diagnostic venv; no product arguments are recorded."""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import sys
import threading
import time
from types import FrameType
from typing import Any

MODULES_BEFORE = tuple(sys.modules)

MAX_CALLBACKS = 500_000
MAX_RECORDS = 1024
MAX_DEPTH = 128
MAX_THREADS = 4
MAX_BYTES = 262_144


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("child_duplicate_key")
        value[key] = item
    return value


class Profile:
    """Only closed frame identities; callback failures never escape to product."""

    def __init__(self, config: dict[str, Any], *, clock: Any = time.perf_counter_ns) -> None:
        self.clock = clock
        self.config = config
        self.modules = config["modules"]
        self.frames = {(x["file"], x["qualname"], x["line"]): x["id"] for x in config["frames"]}
        self.selected = {(x["file"], x["qualname"]) for x in config["frames"]}
        self.module_names = set(self.modules.values())
        self.records: list[dict[str, Any]] = []
        self.lock = threading.RLock()
        self.stacks: dict[int, list[tuple[int, int]]] = {}
        self.thread_ids: dict[int, int] = {}
        self.callback_count = 0
        self.callback_ns = 0
        self.active_callbacks = 0
        self.callback_threads: set[int] = set()
        self.live_worker_hooks: set[int] = set()
        self.frozen = False
        self.faults: list[str] = []
        self.enabled = False
        self.hook = self.event
        self.main_thread = threading.get_ident()
        thread_type: Any = threading.Thread
        self.thread_bootstrap_code = thread_type._bootstrap_inner.__code__
        self.previous_main = sys.getprofile()
        self.previous_future = threading.getprofile()
        self.setup_started = clock()
        self.setup_finished = self.setup_started
        self.restore_complete = False
        self.closed = False
        self.current_worker_threads = 0
        self.thread_census_complete = False

    def fault(self, kind: str) -> None:
        if kind not in self.faults and len(self.faults) < 16:
            self.faults.append(kind)
        self.enabled = False

    def start(self) -> bool:
        if self.previous_main is not None or self.previous_future is not None:
            self.fault("preexisting_profile")
            return False
        try:
            threading.setprofile(self.hook)
            self.enabled = True
            sys.setprofile(self.hook)
            self.setup_finished = self.clock()
            return True
        except BaseException:
            self.fault("activation_failed")
            self.restore()
            return False

    def restore(self) -> None:
        self.enabled = False
        good = True
        for getter, setter, previous in (
            (sys.getprofile, sys.setprofile, self.previous_main),
            (threading.getprofile, threading.setprofile, self.previous_future),
        ):
            try:
                current = getter()
                if current is self.hook:
                    setter(previous)
                elif current is not previous:
                    good = False
            except BaseException:
                good = False
        self.restore_complete = good
        if not good:
            self.fault("restoration_failed")

    def event(self, frame: FrameType, event: str, _argument: object) -> None:
        started: int | None = None
        admitted = False
        try:
            ident = threading.get_ident()
            with self.lock:
                stopped = not self.enabled or self.closed
                if not stopped:
                    if ident not in self.callback_threads and len(self.callback_threads) == MAX_THREADS:
                        self.fault("thread_limit")
                        stopped = True
                    else:
                        self.callback_threads.add(ident)
                if not stopped:
                    self.active_callbacks += 1
                    admitted = True
                    if ident != self.main_thread:
                        self.live_worker_hooks.add(ident)
            if stopped:
                if sys.getprofile() is self.hook:
                    sys.setprofile(None)
                    with self.lock:
                        self.live_worker_hooks.discard(ident)
                return
            current: int = self.clock()
            started = current
            with self.lock:
                if not self.enabled or self.closed:
                    return
                self.callback_count += 1
                if self.callback_count > MAX_CALLBACKS:
                    self.fault("callback_limit")
                    return
                if event in {"call", "return"}:
                    self._record(frame, event, current)
                # Observe the original thread's return; do not join or stop it.
                if event == "return" and frame.f_code is self.thread_bootstrap_code and sys.getprofile() is self.hook:
                    sys.setprofile(None)
                    self.live_worker_hooks.discard(ident)
        except BaseException:
            self.fault("capture_failed")
        finally:
            if started is not None:
                try:
                    ended = self.clock()
                    if ended < started:
                        self.fault("clock_order")
                    else:
                        with self.lock:
                            if not self.frozen:
                                self.callback_ns += ended - started
                except BaseException:
                    self.fault("clock_failed")
            if admitted:
                with self.lock:
                    self.active_callbacks -= 1

    def _record(self, frame: FrameType, event: str, started: int) -> None:
        code: Any = frame.f_code
        key = (code.co_filename, code.co_qualname, code.co_firstlineno)
        stage = self.frames.get(key)
        if stage == "import_load":
            # This one whitelisted importlib local is never exported raw.
            name = frame.f_locals.get("name")
            stage = "import:" + name if type(name) is str and name in self.module_names else None
        if stage is None and code.co_name == "<module>":
            module = self.modules.get(code.co_filename)
            if module is not None:
                stage = "module:" + module
        if stage is None:
            if (code.co_filename, code.co_qualname) in self.selected and key not in self.frames:
                self.fault("frame_identity_changed")
            return
        ident = threading.get_ident()
        if ident not in self.thread_ids:
            if len(self.thread_ids) == MAX_THREADS:
                self.fault("thread_limit")
                return
            self.thread_ids[ident] = len(self.thread_ids)
            self.stacks[ident] = []
        stack = self.stacks[ident]
        if event == "call":
            if len(self.records) == MAX_RECORDS or len(stack) == MAX_DEPTH:
                self.fault("record_or_depth_limit")
                return
            index = len(self.records)
            row = {
                "index": index,
                "stage": stage,
                "thread": self.thread_ids[ident],
                "thread_kind": "main" if ident == self.main_thread else "worker",
                "parent": stack[-1][0] if stack else None,
                "start_ns": started,
                "end_ns": None,
                "termination": "missing",
            }
            self.records.append(row)
            stack.append((index, id(frame)))
        elif stack and stack[-1][1] == id(frame):
            index, _ = stack.pop()
            self.records[index]["end_ns"] = started
            # sys.setprofile cannot distinguish normal return from unwind.
            self.records[index]["termination"] = "profile_return_or_unwind"
        else:
            self.fault("stack_mismatch")

    def document(self) -> dict[str, Any]:
        pending = sum(len(stack) for stack in self.stacks.values())
        return {
            "schema": "hol-guard.priority-child-profile.v1",
            "pid": os.getpid(),
            "parent_pid": os.getppid(),
            "argv_sha256": hashlib.sha256(encoded(sys.orig_argv)).hexdigest(),
            "isolated_flag": bool(sys.flags.isolated),
            "configuration_sha256": self.config["configuration_sha256"],
            "records": [dict(row) for row in self.records],
            "callback_count": self.callback_count,
            "callback_ns": self.callback_ns,
            "setup_ns": self.setup_finished - self.config.get("bootstrap_started_ns", self.setup_started),
            "module_roster_before": self.config.get("modules_before_bootstrap", sorted(MODULES_BEFORE)),
            "module_roster_after_setup": self.config["module_roster_after_setup"],
            "faults": list(self.faults),
            "open_spans": pending,
            "callbacks_in_flight_at_snapshot": self.active_callbacks,
            "callback_threads_seen": len(self.callback_threads),
            "worker_hooks_not_retired": len(self.live_worker_hooks),
            "profile_restored": self.restore_complete,
            "current_worker_threads_at_snapshot": self.current_worker_threads,
            "thread_census_complete": self.thread_census_complete,
            "observation_complete": not self.faults
            and pending == 0
            and self.restore_complete
            and self.active_callbacks == 0
            and not self.live_worker_hooks
            and self.thread_census_complete
            and self.current_worker_threads == 0,
            "qualification_eligible": False,
            "return_events_prove_success": False,
        }

    def finish(self) -> None:
        try:
            current: int = self.clock()
            started = current
            with self.lock:
                if self.closed:
                    return
                self.closed = True
                self.restore()
                try:
                    # No thread names, arguments, waits or joins. Include a new
                    # worker whose first callback has not admitted under our lock.
                    current_threads = threading.enumerate()
                    self.current_worker_threads = min(
                        MAX_THREADS, sum(item.ident != self.main_thread for item in current_threads)
                    )
                    self.thread_census_complete = len(current_threads) <= MAX_THREADS
                    if not self.thread_census_complete:
                        self.fault("thread_census_limit")
                except BaseException:
                    self.fault("thread_census_failed")
                self.frozen = True
                value = self.document()
            value["finish_prewrite_ns"] = self.clock() - started
            data = encoded(value) + b"\n"
            if len(data) > MAX_BYTES:
                self.fault("report_byte_limit")
                value = self.document()
                value["records"] = []
                value["records_withheld"] = True
                value["finish_prewrite_ns"] = self.clock() - started
                data = encoded(value) + b"\n"
            if len(data) > MAX_BYTES:
                return
            path = os.path.join(self.config["output"], str(os.getpid()) + ".json")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
            # Write/export-close cost cannot be included in its own preimage.
            footer = (
                encoded(
                    {
                        "schema": "hol-guard.priority-child-export.v1",
                        "pid": os.getpid(),
                        "report_sha256": hashlib.sha256(data).hexdigest(),
                        "finish_through_report_export_ns": self.clock() - started,
                    }
                )
                + b"\n"
            )
            descriptor = os.open(path + ".done", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(footer)
        except BaseException:
            # Missing/partial sidecar or footer is rejected by the parent.
            self.fault("export_failed")


def activate(config_path: str, expected_sha256: str, started_ns: int, modules_before: tuple[str, ...]) -> None:
    """Called only after the tiny sitecustomize exact invocation admission."""
    profile: Profile | None = None
    try:
        with open(config_path, "rb") as stream:
            body = stream.read(1_048_577)
        if len(body) > 1_048_576 or hashlib.sha256(body).hexdigest() != expected_sha256:
            return
        config = json.loads(body, object_pairs_hook=pairs)
        if (
            bool(sys.flags.isolated) != ("-I" in sys.orig_argv[1:2])
            or sys.executable != config["executable"]
            or os.getppid() != config["parent_pid"]
            or sys.orig_argv not in config["argv"]
            or list(sys.version_info[:3]) != config["python"]
        ):
            return
        config["configuration_sha256"] = expected_sha256
        config["bootstrap_started_ns"] = started_ns
        config["modules_before_bootstrap"] = sorted(modules_before)
        config["module_roster_after_setup"] = sorted(sys.modules)
        profile = Profile(config)
        atexit.register(profile.finish)
        profile.start()
    except BaseException:
        if profile is not None:
            profile.fault("setup_failed")
            profile.restore()
