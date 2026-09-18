"""Terminal-only phase timings for one explicitly observed Claude bridge call."""

from __future__ import annotations

import json
import math
import sys
import time
from collections.abc import Callable
from functools import wraps

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge

MARKER = "CLAUDE_BRIDGE_PHASE_OBSERVATION "
_PHASES = (
    ("daemon", "_post_to_loopback_daemon"),
    ("recovery", "_run_recovery_command"),
    ("fallback", "_run_local_fallback"),
)


def observe_bridge_main(main: Callable[..., object], **options: object) -> object:
    originals = {name: getattr(bridge, name) for _, name in _PHASES}
    events: list[dict[str, object]] = []
    deadlines: list[float] = []
    observation_failed = False
    overflow = False

    def instrument(phase: str, original: Callable[..., object]) -> Callable[..., object]:
        @wraps(original)
        def measured(*args: object, **kwargs: object) -> object:
            nonlocal observation_failed, overflow
            started: float | None = None
            try:
                started = time.monotonic()
            except Exception:
                observation_failed = True
            outcome = "raised"
            try:
                result = original(*args, **kwargs)
                outcome = "returned"
                return result
            finally:
                try:
                    finished = time.monotonic()
                    deadline = kwargs.get("deadline")
                    valid_deadline = isinstance(deadline, (int, float)) and math.isfinite(deadline)
                    if len(events) < 8:
                        if valid_deadline:
                            deadlines.append(float(deadline))
                        events.append({
                            "phase": phase,
                            "outcome": outcome,
                            "elapsed_ms": max(0, int((finished - started) * 1000))
                            if started is not None else None,
                            "incoming_remaining_ms": max(0, int((float(deadline) - started) * 1000))
                            if valid_deadline and started is not None else None,
                        })
                    else:
                        overflow = True
                except Exception:
                    observation_failed = True
        return measured

    try:
        for phase, name in _PHASES:
            setattr(bridge, name, instrument(phase, originals[name]))
        return main(**options)
    finally:
        for _, name in _PHASES:
            setattr(bridge, name, originals[name])
        try:
            report = {
                "events": events,
                "observation_failed": observation_failed,
                "overflow": overflow,
                "shared_deadline": bool(deadlines) and len(deadlines) == len(events)
                and all(value == deadlines[0] for value in deadlines),
            }
            sys.stderr.write(MARKER + json.dumps(report, sort_keys=True) + "\n")
        except Exception:
            pass
