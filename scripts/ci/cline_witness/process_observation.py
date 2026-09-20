"""Observe only the selected worker's original POSIX Popen operations."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import CodeType, FrameType, FunctionType
from typing import Any

SCHEMA = "hol-guard.cline-original-process-operations.v1"
METHODS = ("_communicate", "_check_timeout", "poll", "wait")
CALLERS = ("communicate", "send_signal", "__exit__")
MAX_ROWS = 32
MAX_OUTPUT = 1_048_576
CODE_FIELDS = (
    "co_argcount",
    "co_posonlyargcount",
    "co_kwonlyargcount",
    "co_nlocals",
    "co_stacksize",
    "co_flags",
    "co_code",
    "co_consts",
    "co_names",
    "co_varnames",
    "co_filename",
    "co_name",
    "co_qualname",
    "co_firstlineno",
    "co_linetable",
    "co_exceptiontable",
    "co_freevars",
    "co_cellvars",
)


def constant_image(value: Any) -> Any:
    kind = type(value)
    if kind is CodeType:
        return ["code", [constant_image(getattr(value, name)) for name in CODE_FIELDS]]
    if value is None or value is Ellipsis:
        return ["none" if value is None else "ellipsis"]
    if any(kind is allowed for allowed in (bool, int, str)):
        return [kind.__name__, value]
    if kind is bytes:
        return ["bytes", value.hex()]
    if kind is float:
        return ["float", value.hex()]
    if kind is complex:
        return ["complex", value.real.hex(), value.imag.hex()]
    if kind is tuple:
        return ["tuple", [constant_image(item) for item in value]]
    if kind is frozenset:
        return ["frozenset", sorted((constant_image(item) for item in value), key=repr)]
    raise ValueError("process_code_constant_type")


def number(value: object) -> bool:
    return type(value) is int and -(2**31) <= value < 2**31


def function_image(function: object) -> str:
    if type(function) is not FunctionType:
        raise ValueError("process_function_type")
    image = constant_image(function.__code__)
    return hashlib.sha256(json.dumps(image, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def binding() -> dict[str, Any]:
    if type(subprocess.__file__) is not str:
        raise ValueError("process_source_path")
    path = Path(subprocess.__file__).resolve(strict=True)
    body = path.read_bytes()
    if len(body) > 262144:
        raise ValueError("process_source_bound")
    return {
        "source_path": str(path),
        "source_bytes": len(body),
        "source_sha256": hashlib.sha256(body).hexdigest(),
        "python": list(sys.version_info[:3]),
        "run": function_image(subprocess.run),
        "methods": {name: function_image(getattr(subprocess.Popen, name)) for name in (*METHODS, *CALLERS)},
    }


def output_image(value: object) -> dict[str, Any]:
    if value is None:
        return {"kind": "absent", "bytes": 0, "sha256": None}
    if type(value) is bytes:
        body = value
        kind = "bytes"
    elif type(value) is str:
        if len(value) > MAX_OUTPUT:
            raise ValueError("process_output_bound")
        body = value.encode("utf-8")
        kind = "text_utf8"
    else:
        raise ValueError("process_output_type")
    if len(body) > MAX_OUTPUT:
        raise ValueError("process_output_bound")
    return {"kind": kind, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


class ProcessObservation:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.popen = subprocess.Popen
        self.originals = {name: getattr(self.popen, name) for name in METHODS}
        self.codes = {name: getattr(self.popen, name).__code__ for name in (*METHODS, *CALLERS)}
        self.run_code = subprocess.run.__code__
        self.hooks: dict[str, Any] = {}
        self.installed: list[str] = []
        self.owner: Any = None
        self.owner_pid: int | None = None
        self.active = False
        self.activation_frame: FrameType | None = None
        self.offers = 0
        self.rows: list[dict[str, Any]] = []
        self.faults: list[str] = []
        self.restored = False
        self.restoration_failed = False
        self.after_equal = False
        self.output: dict[str, Any] | None = None

    def fault(self, label: str) -> None:
        try:
            if label not in self.faults and len(self.faults) < 8:
                self.faults.append(label)
        except BaseException:
            return

    def add(self, role: str, outcome: str, value: object = None) -> None:
        if len(self.rows) >= MAX_ROWS:
            self.fault("row_limit")
            return
        if value is not None and not number(value):
            self.fault("status_type")
            return
        self.rows.append({"index": len(self.rows), "role": role, "outcome": outcome, "returncode": value})

    def begin(self) -> None:
        self.offers = min(2, self.offers + 1)
        if self.active or self.offers != 1:
            self.fault("multiple_offers")
        self.active = True
        self.activation_frame = sys._getframe(1)

    def end(self) -> None:
        self.active = False
        self.activation_frame = None

    def role(self, name: str, caller: object) -> str | None:
        if name == "_communicate" and caller is self.codes["communicate"]:
            return "communicate"
        if name == "_check_timeout" and caller is self.codes["_communicate"]:
            return "pipe_timeout_check"
        if name == "poll" and caller is self.codes["send_signal"]:
            return "pre_signal_poll"
        if name == "poll" and caller is self.run_code:
            return "run_completion_poll"
        if name == "wait" and caller is self.codes["_communicate"]:
            return "communicate_process_wait"
        if name == "wait" and caller is self.codes["communicate"]:
            return "communicate_final_wait"
        if name == "wait" and caller is self.run_code:
            return "run_timeout_cleanup_wait"
        if name == "wait" and caller is self.codes["__exit__"]:
            return "context_exit_wait"
        return None

    def observe(self, name: str, instance: object, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        original = self.originals[name]
        selected = False
        role = None
        try:
            # The caller is immediately above our transparent unbound wrapper.
            caller = sys._getframe(2)
            role = self.role(name, caller.f_code)
            if self.active and name == "_communicate" and role == "communicate":
                parent = caller.f_back
                owned_call = parent is not None and parent.f_back is self.activation_frame
                if not owned_call:
                    pass
                elif type(instance) is not self.popen or parent is None or parent.f_code is not self.run_code:
                    self.fault("process_owner")
                elif self.owner is None:
                    self.owner = instance
                    pid = object.__getattribute__(instance, "__dict__").get("pid")
                    if not number(pid) or pid <= 0:
                        self.fault("process_pid")
                    else:
                        self.owner_pid = pid
                    self.add(role, "entered")
                elif self.owner is not instance:
                    self.fault("multiple_processes")
                else:
                    self.fault("multiple_communicates")
            selected = self.active and self.owner is instance
            if selected and role is None:
                self.fault("unexpected_caller")
                selected = False
        except BaseException:
            self.fault("capture_failed")
        try:
            result = original(instance, *args, **kwargs)
        except BaseException as error:
            if selected:
                try:
                    outcome = "timeout" if type(error) is subprocess.TimeoutExpired else "raised"
                    self.add(str(role), outcome)
                except BaseException:
                    self.fault("capture_failed")
            raise
        if selected and name != "_check_timeout":
            try:
                if name == "_communicate":
                    self.add(str(role), "returned")
                else:
                    self.add(str(role), "returned", result)
            except BaseException:
                self.fault("capture_failed")
        return result

    def start(self) -> None:
        try:
            if binding() != self.config["popen_binding"]:
                raise ValueError("process_binding")
            for name in METHODS:
                forwarded = self.forwarder(name)
                self.hooks[name] = forwarded
                setattr(self.popen, name, forwarded)
                self.installed.append(name)
        except BaseException:
            self.fault("installation_failed")
            self.restore()

    def forwarder(self, name: str) -> Any:
        def forwarded(instance: object, *args: Any, **kwargs: Any) -> Any:
            return self.observe(name, instance, args, kwargs)

        return forwarded

    def capture_output(self, result: object, *, raised: bool) -> None:
        try:
            if raised and type(result) is subprocess.TimeoutExpired:
                self.output = {"stdout": output_image(result.output), "stderr": output_image(result.stderr)}
            elif not raised and type(result) is subprocess.CompletedProcess:
                self.output = {"stdout": output_image(result.stdout), "stderr": output_image(result.stderr)}
        except BaseException:
            self.fault("output_capture")

    def restore(self) -> None:
        self.active = False
        self.activation_frame = None
        for name in reversed(self.installed):
            try:
                if getattr(self.popen, name) is self.hooks[name]:
                    setattr(self.popen, name, self.originals[name])
                if getattr(self.popen, name) is not self.originals[name]:
                    self.restoration_failed = True
            except BaseException:
                self.restoration_failed = True
        self.installed.clear()
        self.restored = not self.restoration_failed
        try:
            self.after_equal = binding() == self.config["popen_binding"]
        except BaseException:
            self.after_equal = False
        if not self.restored:
            self.fault("restoration_failed")
        if not self.after_equal:
            self.fault("binding_after")

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "offered_calls": self.offers,
            "owned_process_observed": self.owner is not None,
            "owned_process_pid": self.owner_pid,
            "rows": list(self.rows),
            "maximum_rows": MAX_ROWS,
            "output_metadata": self.output,
            "faults": list(self.faults),
            "methods_restored": self.restored,
            "binding_after_equal": self.after_equal,
            "capture_complete": not self.active and not self.faults and self.restored and self.after_equal,
            "additional_process_operations": 0,
            "raw_output_exported": False,
            "continuous_liveness_proved": False,
        }


def validate(document: object, offered: int, outcome: str) -> None:
    fields = {
        "schema",
        "offered_calls",
        "owned_process_observed",
        "owned_process_pid",
        "rows",
        "maximum_rows",
        "output_metadata",
        "faults",
        "methods_restored",
        "binding_after_equal",
        "capture_complete",
        "additional_process_operations",
        "raw_output_exported",
        "continuous_liveness_proved",
    }
    if type(document) is not dict or set(document) != fields:
        raise ValueError("process_report_schema")
    if (
        document["schema"] != SCHEMA
        or type(document["offered_calls"]) is not int
        or document["offered_calls"] != offered
        or type(document["owned_process_observed"]) is not bool
        or type(document["maximum_rows"]) is not int
        or document["maximum_rows"] != MAX_ROWS
        or document["faults"] != []
        or document["methods_restored"] is not True
        or document["binding_after_equal"] is not True
        or document["capture_complete"] is not True
        or type(document["additional_process_operations"]) is not int
        or document["additional_process_operations"] != 0
        or document["raw_output_exported"] is not False
        or document["continuous_liveness_proved"] is not False
    ):
        raise ValueError("process_report_incomplete")
    rows = document["rows"]
    roles = {
        "communicate",
        "pipe_timeout_check",
        "pre_signal_poll",
        "run_completion_poll",
        "communicate_process_wait",
        "communicate_final_wait",
        "run_timeout_cleanup_wait",
        "context_exit_wait",
    }
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise ValueError("process_row_bound")
    for index, row in enumerate(rows):
        if (
            type(row) is not dict
            or set(row) != {"index", "role", "outcome", "returncode"}
            or type(row["index"]) is not int
            or row["index"] != index
            or type(row["role"]) is not str
            or row["role"] not in roles
            or type(row["outcome"]) is not str
            or row["outcome"] not in {"entered", "returned", "raised", "timeout"}
            or (row["returncode"] is not None and not number(row["returncode"]))
            or (row["returncode"] is not None and row["outcome"] != "returned")
            or (row["outcome"] == "entered" and (index != 0 or row["role"] != "communicate"))
            or (row["role"] == "pipe_timeout_check" and row["outcome"] not in {"timeout", "raised"})
        ):
            raise ValueError("process_row_schema")
    if bool(rows) != document["owned_process_observed"]:
        raise ValueError("process_owner_rows")
    if rows:
        if not number(document["owned_process_pid"]) or document["owned_process_pid"] <= 0:
            raise ValueError("process_owner_pid")
    elif document["owned_process_pid"] is not None:
        raise ValueError("process_unowned_pid")
    if rows and (rows[0]["role"] != "communicate" or rows[0]["outcome"] != "entered"):
        raise ValueError("process_first_row")
    completed = [row for row in rows if row["role"] == "communicate" and row["outcome"] != "entered"]
    if rows and (len(completed) != 1 or completed[0]["returncode"] is not None):
        raise ValueError("process_communicate_count")
    if rows and outcome in {"returned", "timeout"} and completed[0]["outcome"] != outcome:
        raise ValueError("process_communicate_outcome")
    if outcome in {"returned", "timeout"} and not rows:
        raise ValueError("process_missing_owner")
    for role in roles - {"communicate"}:
        if sum(row["role"] == role for row in rows) > 1:
            raise ValueError("process_duplicate_operation")
    if outcome == "returned" and [row["role"] for row in rows] != [
        "communicate",
        "communicate_process_wait",
        "communicate",
        "communicate_final_wait",
        "run_completion_poll",
        "context_exit_wait",
    ]:
        raise ValueError("process_return_order")
    if outcome == "returned":
        returned_statuses = [row["returncode"] for row in rows if row["role"] != "communicate"]
        if (
            any(row["outcome"] != "returned" for row in rows[1:])
            or any(not number(status) for status in returned_statuses)
            or len(set(returned_statuses)) != 1
        ):
            raise ValueError("process_return_consistency")
    if outcome == "timeout":
        roles_seen = [row["role"] for row in rows]
        if roles_seen not in [
            ["communicate", reason, "communicate", "pre_signal_poll", "run_timeout_cleanup_wait", "context_exit_wait"]
            for reason in ("pipe_timeout_check", "communicate_process_wait")
        ] or [row["outcome"] for row in rows] != ["entered", "timeout", "timeout", "returned", "returned", "returned"]:
            raise ValueError("process_timeout_order")
        if not number(rows[-1]["returncode"]) or rows[-2]["returncode"] != rows[-1]["returncode"]:
            raise ValueError("process_timeout_cleanup")
    output = document["output_metadata"]
    if offered == 0 and (rows or output is not None):
        raise ValueError("process_zero_offer")
    if offered == 1 and outcome in {"returned", "timeout"}:
        if type(output) is not dict or set(output) != {"stdout", "stderr"}:
            raise ValueError("process_output_schema")
        for member in output.values():
            if type(member) is not dict or set(member) != {"kind", "bytes", "sha256"}:
                raise ValueError("process_output_member")
            if type(member["bytes"]) is not int or not 0 <= member["bytes"] <= MAX_OUTPUT:
                raise ValueError("process_output_size")
            if type(member["kind"]) is not str:
                raise ValueError("process_output_kind")
            if member["kind"] == "absent":
                if member["bytes"] != 0 or member["sha256"] is not None:
                    raise ValueError("process_absent_output")
            elif member["kind"] in {"bytes", "text_utf8"}:
                digest = member["sha256"]
                if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError("process_output_digest")
            else:
                raise ValueError("process_output_kind")
    elif output is not None:
        raise ValueError("process_unavailable_output")


def normal_delivery(nested: dict[str, Any]) -> bool:
    """A strict child verdict is separate from successful original delivery."""
    return (
        nested["selected_calls"] == 1
        and nested["outcome"] == "returned"
        and type(nested["returncode"]) is int
        and nested["returncode"] == 0
        and nested["process_observation"]["owned_process_observed"] is True
        and any(
            row["role"] == "run_completion_poll"
            and row["outcome"] == "returned"
            and type(row["returncode"]) is int
            and row["returncode"] == 0
            for row in nested["process_observation"]["rows"]
        )
    )
