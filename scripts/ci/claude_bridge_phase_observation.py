"""Terminal-only phase timings for one explicitly observed Claude bridge call."""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path

_PHASES = (
    ("daemon", "_post_to_loopback_daemon"),
    ("recovery", "_run_recovery_command"),
    ("fallback", "_run_local_fallback"),
)


def admission_flags() -> dict[str, object]:
    native = os.environ.get("HOL_GUARD_NATIVE")
    return {
        "native_mode": (
            native if native in ("off", "auto", "force", "shadow") else "unset" if native is None else "other"
        ),
        "test_mode": os.environ.get("HOL_GUARD_TEST_MODE") == "1",
        "python_oracle": os.environ.get("HOL_GUARD_PYTHON_ORACLE") == "1",
        "native_diagnostic": os.environ.get("HOL_GUARD_NATIVE_DIAGNOSTIC") == "1",
    }


def observe_bridge_main(
    main: Callable[..., object], *, observation_path: str, **options: object
) -> object:
    from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge

    originals = {name: getattr(bridge, name) for _, name in _PHASES}
    events: list[dict[str, object]] = []
    deadlines: list[float] = []
    observation_failed = False
    overflow = False
    admission = admission_flags()

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
                "admission": admission,
                "observation_failed": observation_failed,
                "overflow": overflow,
                "shared_deadline": bool(deadlines) and len(deadlines) == len(events)
                and all(value == deadlines[0] for value in deadlines),
            }
            with Path(observation_path).open("x", encoding="utf-8") as destination:
                destination.write(json.dumps(report, sort_keys=True) + "\n")
        except Exception:
            pass
