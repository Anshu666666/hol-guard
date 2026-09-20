"""Observe only existing calls in the exact supervisor-recovery fixture."""

from __future__ import annotations

import hashlib
import signal
import subprocess
from collections.abc import Callable
from types import ModuleType
from typing import Any, cast

from ci.native_runtime.mac_recovery_record import decode


class Capture:
    def __init__(self, runtime: str, state: str) -> None:
        self.runtime, self.state = runtime, state
        self.rows: list[dict[str, Any]] = []
        self.faults = 0
        self.overflow = False
        self.owner: int | None = None
        self.restored = False
        self.restoration_failed = False
        self.test_outcome = "unobserved"
        self.call_ordinal = 0
        self.native_loss = False

    def safe(self, action: Callable[[], None]) -> None:
        try:
            action()
        except BaseException:
            self.faults += 1

    def append(self, row: dict[str, Any]) -> None:
        if len(self.rows) >= 512:
            self.overflow = True
            return
        self.rows.append({"index": len(self.rows), **row})

    def observe_state(self, value: object) -> None:
        if type(value) is not dict:
            return
        fields = ("generation", "process_id", "owner_process_id")
        if not all(name in value for name in fields):
            return
        numbers = {name: value[name] for name in fields}
        for key, number in numbers.items():
            limit = 2**64 if key == "generation" else 2**32
            if type(number) is not int or not 0 < number < limit:
                raise ValueError("original_state_scalar")
        self.owner = numbers["owner_process_id"]
        self.append({"kind": "original_state_decode", **numbers})

    def role(self, command: object) -> str | None:
        if type(command) not in (tuple, list):
            return None
        command = cast(tuple[object, ...] | list[object], command)
        if not all(type(item) is str for item in command):
            return None
        if tuple(command) == (self.runtime, "rule-contract", "--json"):
            return "rule_contract"
        for mode, role in (("resident-client", "policy_push"), ("hook-client", "hook")):
            if tuple(command) == (self.runtime, mode, "--stdin", self.state):
                return role
        if tuple(command) == (self.runtime, "resident-stop", "--state-dir", self.state):
            return "original_stop"
        return None

    def run(self, original: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        selected: list[str] = []
        self.safe(lambda: selected.extend([role] if args and (role := self.role(args[0])) else []))
        role = selected[0] if selected else None
        ordinal = self.call_ordinal
        if role:
            self.call_ordinal += 1
            self.safe(lambda: self.append({"kind": "call_offered", "role": role, "ordinal": ordinal}))
        try:
            result = original(*args, **kwargs)
        except BaseException:
            if role:
                self.safe(lambda: self.append({"kind": "call_raised", "role": role, "ordinal": ordinal}))
            raise
        if role:
            self.safe(lambda: self.returned(role, ordinal, kwargs, result))
        return result

    def returned(self, role: str, ordinal: int, kwargs: dict[str, Any], result: object) -> None:
        if type(result) is not subprocess.CompletedProcess:
            raise ValueError("original_result_type")
        row: dict[str, Any] = {"kind": "call_returned", "role": role, "ordinal": ordinal}
        if type(result.returncode) is not int:
            raise ValueError("original_returncode_type")
        row["returncode"] = result.returncode
        for name, value in (("input", kwargs.get("input")), ("stdout", result.stdout), ("stderr", result.stderr)):
            if value is None:
                row[name] = None
                continue
            if type(value) is str:
                value = value.encode("utf-8")
            if type(value) is not bytes or len(value) > 1048576:
                raise ValueError("original_stream_bound")
            row[name] = {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        if type(result.stderr) is bytes:
            row["native_failure"] = decode(result.stderr)
            if row["native_failure"] is not None and row["native_failure"]["additional_observation_lost"]:
                self.native_loss = True
        else:
            row["native_failure"] = None
        self.append(row)

    def kill(self, original: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        selected = (
            len(args) == 2
            and type(args[0]) is int
            and args[0] == self.owner
            and (args[1] is signal.SIGTERM or (type(args[1]) is int and args[1] == 0))
        )
        try:
            result = original(*args, **kwargs)
        except BaseException as error:
            if selected:
                kinds: dict[type[BaseException], str] = {
                    ProcessLookupError: "not_found",
                    PermissionError: "permission",
                    OSError: "os_error",
                }
                kind = kinds.get(type(error), "unregistered")
                self.safe(
                    lambda: self.append(
                        {"kind": "owner_probe", "signal": 15 if args[1] is signal.SIGTERM else 0, "result": kind}
                    )
                )
            raise
        if selected:
            self.safe(
                lambda: self.append(
                    {"kind": "owner_probe", "signal": 15 if args[1] is signal.SIGTERM else 0, "result": "returned"}
                )
            )
        return result

    def document(self) -> dict[str, Any]:
        return {
            "schema": "hol-guard-macos-supervisor-observation.v1",
            "rows": self.rows,
            "capture_faults": self.faults,
            "overflow": self.overflow,
            "native_observation_lost": self.native_loss,
            "aliases_restored": self.restored,
            "original_test_outcome": self.test_outcome,
            "observation_complete": self.faults == 0
            and not self.overflow
            and not self.native_loss
            and self.restored
            and self.test_outcome != "unobserved",
            "extra_process_probes": 0,
            "extra_policy_pushes": 0,
            "diagnostic_timing_only": True,
            "serving_child_internal_cause_available": False,
            "complete_descendant_cleanup_proved": False,
        }


class Proxy:
    def __init__(self, original: ModuleType, replacements: dict[str, Callable[..., Any]]) -> None:
        self.original, self.replacements = original, replacements

    def __getattr__(self, name: str) -> Any:
        if name in self.replacements:
            return self.replacements[name]
        return getattr(self.original, name)
