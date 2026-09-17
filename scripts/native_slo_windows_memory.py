"""Current Windows memory for one explicitly selected process tree.

This is a sampled sum of WorkingSetSize and, separately, PrivateUsage commit
bytes. It is neither peak working set nor a unique physical-memory total.
"""

from __future__ import annotations

import math
import sys
import time
from dataclasses import dataclass
from typing import Any

_MAX_PROCESSES = 4096
_MAX_TOTAL = 2**63 - 1
_SAMPLE_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class WindowsTreeMemory:
    rss_bytes: int
    private_commit_bytes: int
    processes: int
    threads: int
    handles: int


def _psutil() -> Any:
    # Already locked in the qualification development environment. Production
    # daemon capacity policy does not gain a new dependency through this script.
    import psutil

    return psutil


def _deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError("memory sample deadline exceeded")


def _number(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_TOTAL:
        raise ValueError("invalid process memory counter")
    return value


def _identity(process: Any) -> tuple[float, int]:
    created, parent = process.create_time(), process.ppid()
    if not isinstance(created, (float, int)) or isinstance(created, bool) or not math.isfinite(created) or created <= 0:
        raise ValueError("invalid process creation identity")
    if type(parent) is not int or not 0 <= parent < 2**32:
        raise ValueError("invalid process parent identity")
    return float(created), parent


def _inventory(api: Any, pid: int, created: float, deadline: float) -> dict[int, tuple[float, int]]:
    _deadline(deadline)
    root = api.Process(pid)
    processes = [root, *root.children(recursive=True)]
    if not 1 <= len(processes) <= _MAX_PROCESSES:
        raise ValueError("process tree exceeds memory sample bound")
    identities: dict[int, tuple[float, int]] = {}
    for process in processes:
        _deadline(deadline)
        child = process.pid
        if type(child) is not int or not 0 < child < 2**32 or child in identities:
            raise ValueError("invalid or duplicate process identity")
        identities[child] = _identity(process)
    if root.pid != pid or identities[pid][0] != created:
        raise ValueError("memory sample root changed")
    reached = {pid}
    for child in identities:
        chain: set[int] = set()
        current = child
        while current not in reached:
            _deadline(deadline)
            if current in chain or current not in identities:
                raise ValueError("memory sample ancestry changed")
            chain.add(current)
            parent = identities[current][1]
            if parent not in identities or identities[parent][0] > identities[current][0]:
                raise ValueError("memory sample ancestry changed")
            current = parent
        reached.update(chain)
    _deadline(deadline)
    return identities


def sample_windows_tree_memory(pid: int) -> WindowsTreeMemory | None:
    """Return unavailable on denied, changed, oversized or late inventories.

    The root's creation identity remains fixed across both bounded attempts.
    Fresh Process objects bypass cached creation times during revalidation.
    No command lines, paths, process IDs or API errors leave the collector.
    """
    if sys.platform != "win32" or type(pid) is not int or not 0 < pid < 2**32:
        return None
    try:
        api = _psutil()
    except ImportError:
        return None
    deadline = time.monotonic() + _SAMPLE_SECONDS
    try:
        created = _identity(api.Process(pid))[0]
    except (api.Error, OSError, ValueError, TypeError, AttributeError, OverflowError):
        return None
    for _ in range(2):
        try:
            identities = _inventory(api, pid, created, deadline)
            rss = private = threads = handles = 0
            for child, identity in identities.items():
                _deadline(deadline)
                process = api.Process(child)
                if _identity(process) != identity or not process.is_running():
                    raise ValueError("memory sample identity changed")
                memory = process.memory_info()
                rss = _number(rss + _number(memory.rss))
                private = _number(private + _number(memory.private))
                threads = _number(threads + _number(process.num_threads()))
                handles = _number(handles + _number(process.num_handles()))
                if _identity(api.Process(child)) != identity:
                    raise ValueError("memory sample identity changed")
            if identities != _inventory(api, pid, created, deadline) or rss <= 0 or threads <= 0:
                raise ValueError("memory sample inventory changed or empty")
            _deadline(deadline)
            return WindowsTreeMemory(rss, private, len(identities), threads, handles)
        except (api.Error, OSError, ValueError, TypeError, AttributeError, OverflowError):
            continue
    return None
