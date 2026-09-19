"""Bounded timing observation for the existing materialization diagnostic."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import TYPE_CHECKING, ParamSpec, TypeVar

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module

if TYPE_CHECKING:
    import pytest

    from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher

_P = ParamSpec("_P")
_R = TypeVar("_R")


@dataclass
class _Call:
    stage: str
    started: float
    finished: float | None = None


class MaterializationDiagnostic:
    """Delegate every call unchanged and export only bounded stage timings."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, publisher: NativePolicySnapshotPublisher) -> None:
        self._calls: list[_Call] = []
        self._origin: float | None = None
        self._worker_ident: int | None = None
        self._truncated = False
        monkeypatch.setattr(publisher, "_publish_once", self._observe("publication", publisher._publish_once))
        for stage, name in (
            ("build", "build_policy_snapshot_v3"),
            ("pending", "_write_v3_snapshot_file"),
            ("cache", "_write_v3_snapshot_cache"),
            ("generation", "_write_v3_generation_state"),
            ("cleanup", "_clear_v3_snapshot_pending"),
        ):
            monkeypatch.setattr(snapshot_module, name, self._observe(stage, getattr(snapshot_module, name)))

    def _observe(self, stage: str, original: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(original)
        def observed(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            prior_worker_ident = self._worker_ident
            if stage == "publication":
                self._worker_ident = threading.get_ident()
            elif self._worker_ident != threading.get_ident():
                return original(*args, **kwargs)
            call = None
            try:
                if len(self._calls) >= 32:
                    self._truncated = True
                else:
                    started = time.monotonic()
                    if self._origin is None:
                        self._origin = started
                    call = _Call(stage, started)
                    self._calls.append(call)
                return original(*args, **kwargs)
            finally:
                if call is not None:
                    call.finished = time.monotonic()
                if stage == "publication":
                    self._worker_ident = prior_worker_ident

        return observed

    def snapshot(self) -> dict[str, object]:
        calls = tuple((call.stage, call.started, call.finished) for call in tuple(self._calls))
        now = time.monotonic()
        origin = self._origin if self._origin is not None else now
        return {
            "truncated": self._truncated,
            "steps": [
                {
                    "stage": stage,
                    "start_ms": round((started - origin) * 1_000, 3),
                    "elapsed_ms": round(((finished if finished is not None else now) - started) * 1_000, 3),
                    "complete": finished is not None,
                }
                for stage, started, finished in calls
            ],
        }
