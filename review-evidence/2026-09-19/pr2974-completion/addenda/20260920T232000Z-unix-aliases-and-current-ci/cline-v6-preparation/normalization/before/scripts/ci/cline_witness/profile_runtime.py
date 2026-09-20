"""Exact child-local call/return observer; copied outside the installed wheel."""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import FrameType
from typing import Any

MAX_CALLBACKS = 2_000_000
MAX_OUTPUT = 131072
MAX_CAPTURE_BYTES = 1_048_576


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def snapshot(value: object) -> bytes:
    body = encoded(value)
    if len(body) > MAX_CAPTURE_BYTES:
        raise ValueError("cline_observer_capture_bound")
    return body


def entry_snapshot(arguments: dict[str, Any] | None) -> bytes:
    if arguments is None:
        raise ValueError("cline_observer_missing_entry")
    result = {
        key: arguments.get(key)
        for key in (
            "payload",
            "policy_snapshot",
            "harness",
            "event",
            "source_ref_external_allowed",
            "observe_mode",
            "deadline",
        )
    }
    for key in ("guard_home", "home_dir", "cwd"):
        item = arguments.get(key)
        result[key] = None if item is None else str(item)
    return snapshot(result)


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("cline_observer_duplicate_key")
        value[key] = item
    return value


def private_read(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 <= info.st_size <= maximum
        ):
            raise ValueError("cline_observer_private_file")
        body = os.read(descriptor, maximum + 1)
        if len(body) != info.st_size:
            raise ValueError("cline_observer_file_bound")
        return body
    finally:
        os.close(descriptor)


def write_report(path: Path, value: object) -> None:
    body = encoded(value) + b"\n"
    if len(body) > MAX_OUTPUT:
        raise ValueError("cline_observer_output_bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)


class Profile:
    """Shared original-value capture for legacy profiling or selected methods."""

    snapshot = staticmethod(snapshot)
    entry_snapshot = staticmethod(entry_snapshot)

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.frames = {(row["file"], row["qualname"], row["line"]): row["role"] for row in config["frames"]}
        self.previous = sys.getprofile()
        self.hook = self.event
        self.enabled = False
        self.closed = False
        self.restored = False
        self.restoration_failed = False
        self.callbacks = 0
        self.callbacks_saturated = False
        self.faults: list[str] = []
        self.open_frames: dict[str, int] = {}
        self.counts = {"edge_call": 0, "edge_return_or_unwind": 0, "worker_call": 0, "worker_return_or_unwind": 0}
        self.edge: object = None
        self.arguments: dict[str, Any] | None = None
        self.worker: Any = None
        self.worker_result: object = None
        self.entry_image: bytes | None = None
        self.edge_image: bytes | None = None
        self.worker_result_image: bytes | None = None
        self.method_observation: Any = None

    def fault(self, name: str) -> None:
        if name not in self.faults and len(self.faults) < 8:
            self.faults.append(name)
        self.enabled = False

    def start(self) -> bool:
        if self.previous is not None:
            self.fault("preexisting_profile")
            return False
        try:
            self.enabled = True
            sys.setprofile(self.hook)
            return True
        except BaseException:
            self.fault("activation_failed")
            self.restore()
            return False

    def restore(self) -> None:
        self.enabled = False
        if self.method_observation is not None:
            try:
                self.method_observation.restore()
                self.restored = (
                    self.method_observation.document()["complete"]
                    and sys.getprofile() is self.previous
                )
            except BaseException:
                self.restored = False
                self.fault("method_restoration_failed")
            return
        try:
            current = sys.getprofile()
            if current is self.hook:
                sys.setprofile(self.previous)
            elif current is not self.previous:
                self.restoration_failed = True
        except BaseException:
            self.restoration_failed = True
        self.restored = not self.restoration_failed

    def event(self, frame: FrameType, event: str, argument: object) -> None:
        try:
            if not self.enabled or self.closed:
                return
            # Unrelated imports must not consume the selected-edge population.
            # Keep a bounded all-event count, while inspecting every callback.
            # The existing per-role duplicate checks bound retained events.
            if self.callbacks < MAX_CALLBACKS:
                self.callbacks += 1
            else:
                self.callbacks_saturated = True
            if event not in {"call", "return"}:
                return
            code = frame.f_code
            role = self.frames.get((code.co_filename, code.co_qualname, code.co_firstlineno))
            if role is None:
                return
            key = role + ("_call" if event == "call" else "_return_or_unwind")
            self.counts[key] += 1
            if self.counts[key] != 1:
                self.fault("duplicate_selected_call")
                return
            if event == "call":
                self.open_frames[role] = id(frame)
                if role == "worker":
                    self.worker = frame.f_locals.get("self")
                else:
                    # Seal the entry values now; retain the originals only for
                    # an exact stability check before post-call validation.
                    self.arguments = dict(frame.f_locals)
                    self.entry_image = entry_snapshot(self.arguments)
            elif self.open_frames.pop(role, None) != id(frame):
                self.fault("frame_pair_mismatch")
            elif role == "edge":
                self.edge = argument
                self.edge_image = snapshot(argument)
            else:
                self.worker_result = argument
                self.worker_result_image = snapshot(argument)
        except BaseException:
            self.fault("capture_failed")

    def finish(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.restore()
        result: dict[str, Any] = {
            "schema": "hol-guard.cline-child-edge.v2",
            "configuration_sha256": self.config["configuration_sha256"],
            "pid": os.getpid(),
            "parent_pid": os.getppid(),
            "observed_argv_sha256": hashlib.sha256(encoded(sys.orig_argv)).hexdigest(),
            "registered_argv_sha256": hashlib.sha256(encoded(self.config["argv"][1])).hexdigest(),
            "isolated": bool(sys.flags.isolated),
            "no_user_site": bool(sys.flags.no_user_site),
            "counts": dict(self.counts),
            "callbacks": self.callbacks,
            "callbacks_saturated": self.callbacks_saturated,
            "callback_count_scope": "all_profile_events_saturating",
            "maximum_counted_callbacks": MAX_CALLBACKS,
            "faults": list(self.faults),
            "profile_restored": self.restored,
            "open_frames": len(self.open_frames),
            "observation_complete": False,
            "return_events_prove_success": False,
            "instrumented_functional_evidence": True,
            "headline_timing_eligible": False,
        }
        if self.method_observation is not None:
            result.update(
                schema="hol-guard.cline-child-edge.v3",
                callback_count_scope="selected_methods_only",
                maximum_counted_callbacks=0,
                method_observation=self.method_observation.document(),
            )
        try:
            stable = (
                self.entry_image is not None
                and entry_snapshot(self.arguments) == self.entry_image
                and self.edge_image is not None
                and snapshot(self.edge) == self.edge_image
                and self.worker_result_image is not None
                and snapshot(self.worker_result) == self.worker_result_image
            )
            result["original_values_stable"] = stable
            if not stable:
                raise ValueError("cline_original_values_changed")
            helper = Path(self.config["validation_path"])
            body = helper.read_bytes()
            if len(body) > 65536 or hashlib.sha256(body).hexdigest() != self.config["validation_sha256"]:
                raise ValueError("cline_validation_binding")
            namespace: dict[str, Any] = {"__name__": "_cline_validation", "__file__": str(helper)}
            exec(compile(body, str(helper), "exec"), namespace)
            result["original_edge"] = namespace["validate"](
                self.config, self.arguments, self.edge, self.worker, self.worker_result
            )
            result["observation_complete"] = (
                not self.faults
                and self.restored
                and not self.open_frames
                and all(value == 1 for value in self.counts.values())
                and result["original_edge"]["complete"]
            )
        except BaseException:
            result["validation_fault"] = True
        finally:
            self.arguments = None
            self.edge = self.worker = self.worker_result = None
            self.entry_image = self.edge_image = self.worker_result_image = None
        try:
            write_report(Path(self.config["output"]) / "child.json", result)
        except BaseException:
            # The parent requires this exact report; never alter the original
            # CLI exit/exception when its diagnostic export fails.
            return


def activate(config_path: str, expected_sha256: str) -> None:
    body = private_read(Path(config_path), 1_048_576)
    if hashlib.sha256(body).hexdigest() != expected_sha256:
        return
    config = json.loads(body, object_pairs_hook=pairs)
    output = Path(config["output"])
    if sys.orig_argv == config["observed_argv"][0]:
        if os.getppid() != config["parent_pid"]:
            return
        write_report(
            output / "worker.json",
            {
                "schema": "hol-guard.cline-worker-start.v1",
                "pid": os.getpid(),
                "parent_pid": os.getppid(),
                "configuration_sha256": expected_sha256,
                "observed_argv_sha256": hashlib.sha256(encoded(sys.orig_argv)).hexdigest(),
                "registered_argv_sha256": hashlib.sha256(encoded(config["argv"][0])).hexdigest(),
                "isolated": bool(sys.flags.isolated),
                "no_user_site": bool(sys.flags.no_user_site),
            },
        )
        # Only this already admitted generated worker receives the call wrapper.
        # The nested CLI follows the unchanged profile branch below instead.
        with Path(config["nested_callsite"]["file"]).open("rb") as worker_stream:
            worker_body = worker_stream.read(1_048_577)
        if len(worker_body) > 1_048_576 or hashlib.sha256(worker_body).hexdigest() != config["worker_source_sha256"]:
            return
        helper = Path(config["nested_path"])
        nested_body = private_read(helper, 131072)
        if hashlib.sha256(nested_body).hexdigest() != config["nested_sha256"]:
            return
        namespace: dict[str, Any] = {"__name__": "_hol_guard_cline_nested_run", "__file__": str(helper)}
        exec(compile(nested_body, str(helper), "exec"), namespace)
        process_helper = Path(config["process_path"])
        process_body = private_read(process_helper, 131072)
        if hashlib.sha256(process_body).hexdigest() != config["process_sha256"]:
            return
        process_namespace: dict[str, Any] = {
            "__name__": "_hol_guard_cline_process_observation",
            "__file__": str(process_helper),
        }
        exec(compile(process_body, str(process_helper), "exec"), process_namespace)
        config["configuration_sha256"] = expected_sha256
        namespace["install"](config, write_report, process_namespace["ProcessObservation"])
        return
    if sys.orig_argv != config["observed_argv"][1]:
        return
    worker = json.loads(private_read(output / "worker.json", 4096), object_pairs_hook=pairs)
    if (
        worker.get("configuration_sha256") != expected_sha256
        or type(worker.get("pid")) is not int
        or os.getppid() != worker["pid"]
    ):
        return
    for name, digest in config["sources"].items():
        data = Path(name).read_bytes()
        if len(data) > 1_048_576 or hashlib.sha256(data).hexdigest() != digest:
            return
    config["configuration_sha256"] = expected_sha256
    profile = Profile(config)
    atexit.register(profile.finish)
    if "method_path" in config:
        helper = Path(config["method_path"])
        method_body = private_read(helper, 131072)
        if hashlib.sha256(method_body).hexdigest() != config["method_sha256"]:
            profile.fault("method_helper_binding")
            return
        namespace = {"__name__": "_hol_guard_cline_methods", "__file__": str(helper)}
        exec(compile(method_body, str(helper), "exec"), namespace)
        profile.method_observation = namespace["MethodObservation"](config, profile)
        profile.method_observation.start()
    else:
        profile.start()
