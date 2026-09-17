"""Observe initial HTTP framing atomically with socket reads.

The stdlib HTTP parser retains syntax and size validation. This reader only
transfers completed framing out of the slow-header watchdog before the parser
can consume its buffered bytes. It is used only when headers were incomplete at
worker handoff; subsequent body and keepalive reads use the original socket.
"""

from __future__ import annotations

import io
import selectors
import socket
import threading
from collections.abc import Callable
from contextlib import suppress
from typing import Any, final


@final
class _InitialFraming:
    def __init__(self) -> None:
        self._tail = b""

    def complete(self, chunk: bytes) -> bool:
        combined = self._tail + chunk
        self._tail = combined[-2:]
        return b"\n\r\n" in combined or b"\n\n" in combined


@final
class InitialHeaderReader(io.RawIOBase):
    """A bounded initial-framing observer; it owns no socket admission permit."""

    def __init__(
        self,
        request: socket.socket,
        *,
        pending: dict[int, tuple[socket.socket, float]],
        lock: threading.Lock,
        monotonic: Callable[[], float],
    ) -> None:
        super().__init__()
        self._request = request
        self._pending = pending
        self._lock = lock
        self._monotonic = monotonic
        self._framing = _InitialFraming()
        self._initial = True
        self._expired = False
        self._selector: selectors.BaseSelector | None = None
        self._probe: socket.socket | None = None
        if request.gettimeout() is None:
            raise ValueError("initial header reader requires an admitted nonblocking endpoint")
        try:
            self._probe = request.dup()
            self._probe.setblocking(False)
        except BaseException:
            self._close_observer()
            raise

    def readable(self) -> bool:  # pyright: ignore[reportImplicitOverride]
        return True

    def readinto(self, target: Any) -> int:  # pyright: ignore[reportExplicitAny, reportImplicitOverride]
        if self.closed:
            raise ValueError("read of closed initial header reader")
        if self._expired:
            raise TimeoutError("initial HTTP header deadline exhausted")
        view = memoryview(target)
        if not view:
            return 0
        while self._initial:
            deadline = 0.0
            count: int | None = None
            with self._lock:
                entry = self._pending.get(id(self._request))
                if entry is None:
                    self._initial = False
                else:
                    deadline = entry[1]
                    remaining = deadline - self._monotonic()
                    if remaining <= 0:
                        self._expire()
                    probe = self._probe
                    if probe is None:
                        raise OSError("initial header observer is closed")
                    with suppress(BlockingIOError, InterruptedError):
                        count = probe.recv_into(view)
                    if count is not None and self._monotonic() >= deadline:
                        self._expire()
                    if count is not None and (count == 0 or self._framing.complete(bytes(view[:count]))):
                        # Receipt and observation share the expiration lock.
                        # The watchdog can never see already-consumed complete
                        # headers as an empty, still-unclassified socket.
                        _ = self._pending.pop(id(self._request), None)
                        self._initial = False
            if not self._initial:
                self._close_observer()
            if count is not None:
                return count
            if self._initial:
                self._wait_for_data(deadline)
        return self._request.recv_into(view)

    def _wait_for_data(self, deadline: float) -> None:
        probe = self._probe
        if probe is None:
            raise OSError("initial header observer is closed")
        if self._selector is None:
            self._selector = selectors.DefaultSelector()
            _ = self._selector.register(probe, selectors.EVENT_READ)
        # Readiness waits never hold the classification lock. The next read
        # checks the original absolute deadline again; no byte resets it.
        _ = self._selector.select(timeout=max(0.0, deadline - self._monotonic()))

    def _close_observer(self) -> None:
        selector, self._selector = self._selector, None
        probe, self._probe = self._probe, None
        try:
            if selector is not None:
                selector.close()
        finally:
            if probe is not None:
                probe.close()

    def _expire(self) -> None:
        _ = self._pending.pop(id(self._request), None)
        self._initial = False
        self._expired = True
        self._close_observer()
        raise TimeoutError("initial HTTP header deadline exhausted")

    def close(self) -> None:  # pyright: ignore[reportImplicitOverride]
        try:
            self._close_observer()
        finally:
            super().close()
