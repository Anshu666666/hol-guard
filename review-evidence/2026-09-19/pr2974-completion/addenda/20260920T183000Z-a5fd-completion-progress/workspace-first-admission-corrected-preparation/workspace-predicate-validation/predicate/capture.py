"""Finite records around unchanged calls; no lock spans an original call."""

from __future__ import annotations

import contextvars
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from .projection import error_kind, outcome, snapshot
from .reasons import marker

CURRENT: contextvars.ContextVar[tuple[Any, int, int | None] | None] = contextvars.ContextVar(
    "workspace_predicate_call", default=None
)
MAX_ROWS = 1024
MAX_BYTES = 1024 * 1024


class Capture:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.worker = session.daemon._server.hook_worker
        self.publisher = self.worker.policy_snapshot_publisher
        self.store = session.store
        self.publisher_instance = 0
        self.factory_handoffs = 0
        self.worker_handoffs = 0
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.rows: list[dict[str, Any]] = []
        self.active: set[int] = set()
        self.lost = False
        self.overflow = False
        self.frozen = False
        self.awaits = 0

    def adopt_publisher(self, publisher: Any, store: Any) -> None:
        # Only the original owned replacement factory return supplies these
        # objects. Inspect stored fields; do not call a getter or readiness probe.
        if (
            self.factory_handoffs != 0
            or publisher is self.publisher
            or store is self.store
            or vars(publisher).get("store") is not store
        ):
            raise ValueError("replacement_publisher_identity")
        self.publisher, self.store = publisher, store
        self.publisher_instance = 1
        self.factory_handoffs = 1

    def owns_worker(self, worker: Any) -> bool:
        if worker is self.worker and (
            self.factory_handoffs == 0
            or (
                vars(worker).get("store") is self.store
                and vars(worker).get("policy_snapshot_publisher") is self.publisher
            )
        ):
            return True
        if (
            self.factory_handoffs == 1
            and self.worker_handoffs == 0
            and vars(worker).get("store") is self.store
            and vars(worker).get("policy_snapshot_publisher") is self.publisher
        ):
            self.worker = worker
            self.worker_handoffs = 1
            return True
        return False

    def fault(self) -> None:
        self.lost = True

    def state(self) -> dict[str, Any] | None:
        publisher = self.publisher
        before = time.monotonic() - self.started
        if not publisher._condition.acquire(blocking=False):
            self.fault()
            return None
        try:
            if type(publisher._epoch) is not int or not 0 <= publisher._epoch < 2**63:
                raise ValueError("epoch_shape")
            if type(publisher._acked) is not bool or type(publisher._closed) is not bool:
                raise ValueError("state_shape")
            result: dict[str, Any] = {
                "publisher_instance": self.publisher_instance,
                "acked": publisher._acked,
                "closed": publisher._closed,
                "epoch": publisher._epoch,
                "database_marker": marker(vars(publisher).get("_database_policy_fingerprint")),
                "binding": snapshot(
                    {
                        key: publisher._snapshot.get(key)
                        for key in ("generation", "policy_digest", "runtime_identity", "mode")
                    }
                    if type(publisher._snapshot) is dict
                    else publisher._snapshot,
                    full_digest=False,
                ),
            }
        finally:
            publisher._condition.release()
        result["binding"] = {
            key: result["binding"].get(key)
            for key in ("kind", "generation", "policy_digest", "runtime_identity", "mode")
        }
        return {**result, "before_seconds": before, "after_seconds": time.monotonic() - self.started}

    def begin(self, stage: str, site: str, details: dict[str, Any]) -> int | None:
        before = self.state()
        if not self.lock.acquire(blocking=False):
            self.fault()
            return None
        try:
            if self.frozen or len(self.rows) >= MAX_ROWS:
                self.overflow = True
                return None
            parent = CURRENT.get()
            owned_parent = parent is not None and parent[0] is self
            await_id = parent[2] if parent is not None and owned_parent else None
            if stage == "await_ack":
                self.awaits += 1
                await_id = self.awaits
            index = len(self.rows)
            self.rows.append(
                {
                    "id": index,
                    "parent": parent[1] if parent is not None and owned_parent else None,
                    "await": await_id,
                    "stage": stage,
                    "site": site,
                    "entry_seconds": time.monotonic() - self.started,
                    "exit_seconds": None,
                    "before": before,
                    "after": None,
                    "arguments": details,
                    "outcome": "in_flight",
                    "returned": None,
                }
            )
            self.active.add(index)
            return index
        finally:
            self.lock.release()

    def call(
        self,
        stage: str,
        site: str,
        original: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        details: dict[str, Any] | None = None,
        project: Callable[[Any], Any] = outcome,
    ) -> Any:
        row_id = None
        token = None
        try:
            row_id = self.begin(stage, site, details or {})
            if row_id is not None:
                token = CURRENT.set((self, row_id, self.rows[row_id]["await"]))
        except Exception:
            self.fault()
        result = None
        failure = None
        try:
            result = original(*args, **kwargs)
            return result
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                if row_id is not None:
                    # Copy returned objects at this boundary, before forwarding.
                    returned = project(result) if failure is None else {"exception": error_kind(failure)}
                    after = self.state()
                    if not self.lock.acquire(blocking=False):
                        self.fault()
                    else:
                        try:
                            if self.frozen:
                                self.fault()
                            else:
                                self.rows[row_id].update(
                                    exit_seconds=time.monotonic() - self.started,
                                    after=after,
                                    returned=returned,
                                    outcome="return" if failure is None else "exception",
                                )
                                self.active.discard(row_id)
                        finally:
                            self.lock.release()
            except Exception:
                self.fault()
            finally:
                if token is not None:
                    try:
                        CURRENT.reset(token)
                    except Exception:
                        self.fault()

    def clock_return(self, site: str, value: float) -> None:
        # The value is the original local alias return; no replacement clock call.
        parent = CURRENT.get()
        if parent is not None and parent[0] is not self:
            self.fault()
            return
        if not self.lock.acquire(blocking=False):
            self.fault()
            return
        try:
            if self.frozen or len(self.rows) >= MAX_ROWS:
                self.overflow = True
                return
            self.rows.append(
                {
                    "id": len(self.rows),
                    "parent": parent[1] if parent else None,
                    "await": parent[2] if parent else None,
                    "stage": "original_clock",
                    "site": site,
                    "original_monotonic": value,
                }
            )
        finally:
            self.lock.release()

    def freeze(self) -> dict[str, Any]:
        with self.lock:
            self.frozen = True
            report = {
                "schema": "hol-guard.workspace-predicates.v3",
                "rows": self.rows.copy(),
                "origin": "owned_dispatch_monotonic",
                "original_clock_origin": "absolute_monotonic_not_publication_or_lifecycle_origin",
                "state_scope": "lock_read_interval_not_commit_instant",
                "await_calls": self.awaits,
                "factory_handoffs": self.factory_handoffs,
                "worker_handoffs": self.worker_handoffs,
                "publisher_instances": self.publisher_instance + 1,
                "lost": self.lost,
                "overflow": self.overflow,
                "active_calls": len(self.active),
                "observation_complete": not self.lost and not self.overflow and not self.active,
                "additional_probe_calls": 0,
                "headline_timing_eligible": False,
            }
            if len(json.dumps(report, allow_nan=False).encode()) > MAX_BYTES:
                return {**report, "rows": [], "overflow": True, "observation_complete": False}
            return report
