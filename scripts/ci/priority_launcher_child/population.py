"""A predeclared explanatory subset using only the original producer helpers."""

from __future__ import annotations

from typing import Any


def measure_selected(session: Any, producer: Any, registrations: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = [(harness, event) for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")]
    if [(item.harness, item.event) for item in registrations] != expected:
        raise ValueError("child_population_registration_order")
    original: list[dict[str, Any]] = []
    for launcher in registrations:
        if producer.registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
            raise RuntimeError("child_population_registration_changed")
        before = producer._route_snapshot(session)
        for case in ("benign", "block"):
            observation = producer.observe_priority_launcher(session, launcher, sample=-1, case=case)
            original.append(
                {
                    "harness": launcher.harness,
                    "event": launcher.event,
                    "case": case,
                    "latency_ms": observation.latency_ms,
                    "allowed": observation.allowed,
                }
            )
        after = producer._route_snapshot(session, expected=sum(before.values()) + 2)
        producer._require_native_count(before, after, 2)
    # The unchanged helper performs its original rounding/barrier to 16.
    concurrent = producer._concurrent_series(session, registrations[1], 1)
    return {
        "schema": "hol-guard.priority-child-population.v1",
        "preflights": original,
        "preflight_count": 8,
        "concurrent_route": "claude-code.PostToolUse",
        "concurrent_count": len(concurrent),
        "concurrent_helper_invocations": 1,
        "qualification_eligible": False,
    }, {"claude_post_c16": concurrent}
