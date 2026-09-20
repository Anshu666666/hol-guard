"""Bounded constructor-thread observations; never read publisher state."""

from __future__ import annotations

import math
import threading
import time
from contextvars import ContextVar
from typing import Any

CURRENT: ContextVar[Capture | None] = ContextVar("workspace_constructor", default=None)
PARENTS = {
    "service_constructor": None,
    "http_constructor": "service_constructor",
    "request_services": "http_constructor",
    "hook_worker_constructor": "request_services",
    "publisher_wait": "hook_worker_constructor",
}
MAX_ROWS = 32


def finite(value: Any) -> float:
    if (type(value) is not int and type(value) is not float) or not math.isfinite(value):
        raise ValueError("constructor_clock_shape")
    return float(value)


def error_kind(error: BaseException) -> str:
    ancestry = type.__getattribute__(type(error), "__mro__")
    for cls, label in (
        (KeyboardInterrupt, "interrupt"),
        (SystemExit, "exit"),
        (TimeoutError, "timeout"),
        (OSError, "os_error"),
        (ValueError, "value_error"),
        (RuntimeError, "runtime_error"),
        (Exception, "exception"),
    ):
        if any(parent is cls for parent in ancestry):
            return label
    return "base_exception"


class Capture:
    def __init__(self, session: Any, *, clock: Any = time.monotonic) -> None:
        self.session = session
        self.clock = clock
        self.started = finite(clock())
        self.thread = threading.get_ident()
        self.rows: list[dict[str, Any]] = []
        self.stack: list[int] = []
        self.lost = False
        self.overflow = False
        self.replacements = 0
        self.replacement_outcome = "not_called"
        self.store: Any = None
        self.service: Any = None
        self.http: Any = None
        self.worker: Any = None
        self.publisher: Any = None
        self.factory_handoffs = 0
        self.accepted: float | None = None
        self.acceptance_calls = 0

    def fault(self) -> None:
        self.lost = True

    def active(self) -> bool:
        return CURRENT.get() is self and threading.get_ident() == self.thread

    def stamp(self) -> float:
        result = finite(self.clock()) - self.started
        if result < 0:
            raise ValueError("constructor_clock_order")
        return result

    def call(self, stage: str, site: str, original: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        row: dict[str, Any] | None = None
        old_depth = len(self.stack)
        try:
            parent = self.stack[-1] if self.stack else None
            if (
                not self.active()
                or stage not in PARENTS
                or site == "unknown"
                or (self.rows[parent]["stage"] if parent is not None else None) != PARENTS[stage]
                or any(item["stage"] == stage for item in self.rows)
            ):
                raise ValueError("constructor_call_identity")
            if len(self.rows) >= MAX_ROWS:
                self.overflow = True
                raise ValueError("constructor_row_bound")
            row = {
                "id": len(self.rows),
                "stage": stage,
                "site": site,
                "parent": parent,
                "entry_seconds": self.stamp(),
                "exit_seconds": None,
                "outcome": "pending",
                "returned": None,
                "error": None,
            }
            self.rows.append(row)
            self.stack.append(row["id"])
        except Exception:
            self.fault()
        try:
            result = original(*args, **kwargs)
        except BaseException as error:
            try:
                if row is not None:
                    row.update(outcome="exception", error=error_kind(error))
            except Exception:
                self.fault()
            raise
        else:
            try:
                if row is not None:
                    if result is None:
                        returned = "none"
                    elif result is True:
                        returned = "true"
                    elif result is False:
                        returned = "false"
                    else:
                        returned = "other"
                    row.update(outcome="return", returned=returned)
                    if (stage == "publisher_wait" and type(result) is not bool) or (
                        stage != "publisher_wait" and result is not None
                    ):
                        self.fault()
            except Exception:
                self.fault()
            return result
        finally:
            try:
                if row is not None:
                    row["exit_seconds"] = self.stamp()
                    if row["exit_seconds"] < row["entry_seconds"]:
                        self.fault()
            except Exception:
                self.fault()
            del self.stack[old_depth:]

    def replacement(self, original: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        self.replacements += 1
        if self.replacements != 1 or threading.get_ident() != self.thread:
            self.fault()
            return original(*args, **kwargs)
        token = CURRENT.set(self)
        try:
            result = original(*args, **kwargs)
        except BaseException:
            self.replacement_outcome = "exception"
            raise
        else:
            self.replacement_outcome = "return"
            return result
        finally:
            CURRENT.reset(token)

    def adopt(self, publisher: Any, store: Any) -> None:
        if not self.active() or self.store is not store or self.publisher is not None or self.factory_handoffs:
            raise ValueError("constructor_factory_identity")
        if not self.stack or self.rows[self.stack[-1]]["stage"] != "hook_worker_constructor":
            raise ValueError("constructor_factory_parent")
        self.publisher = publisher
        self.factory_handoffs += 1

    def acceptance(self, result: Any) -> None:
        self.acceptance_calls += 1
        if not self.active() or self.publisher is None or self.acceptance_calls != 1:
            raise ValueError("constructor_acceptance_identity")
        self.accepted = finite(result)
        if self.accepted < self.started:
            raise ValueError("constructor_acceptance_order")

    def freeze(self) -> dict[str, Any]:
        return {
            "schema": "hol-guard.workspace-constructor-phases.v1",
            "clock_origin": "constructor_dispatch_monotonic",
            "origin_monotonic": self.started,
            "accepted_monotonic": self.accepted,
            "acceptance_calls": self.acceptance_calls,
            "replacement_calls": self.replacements,
            "replacement_outcome": self.replacement_outcome,
            "factory_handoffs": self.factory_handoffs,
            "rows": [dict(row) for row in self.rows],
            "active_calls": len(self.stack),
            "lost": self.lost,
            "overflow": self.overflow,
            "observation_complete": not self.lost and not self.overflow and not self.stack,
            "publisher_state_sampled": False,
            "constructor_thread_only": True,
            "background_publisher_observed_by_this_collector": False,
            "observer_overhead_included": True,
        }
