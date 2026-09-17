"""Measure the command actually registered by an installed harness adapter."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import (
    claude_managed_settings_path,
    command_handler_argv,
    is_guard_hook_handler,
)
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_benchmark_oracle import synthetic_payload
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import is_allowed, route_counts, route_delta
from scripts.native_slo_contract import clear_proof_environment, summarize
from scripts.native_slo_launcher_failure import LauncherAuthorityFailureError
from scripts.native_slo_session import AdapterSession


def registered_claude_argv(settings: Path, event: str) -> tuple[str, ...]:
    """Read the installed configuration, rather than reconstructing a launcher."""

    configuration = json.loads(settings.read_text(encoding="utf-8"))
    groups = configuration.get("hooks", {}).get(event, [])
    commands: set[tuple[str, ...]] = set()
    for group in groups:
        if not isinstance(group, dict):
            continue
        for handler in group.get("hooks", []):
            if isinstance(handler, dict) and is_guard_hook_handler(handler):
                argv = command_handler_argv(handler)
                if argv:
                    commands.add(argv)
    if len(commands) != 1:
        raise RuntimeError("installed launcher registration missing or ambiguous")
    return commands.pop()


def _observe_launcher(session: AdapterSession, argv: tuple[str, ...], *, sample: int, case: str) -> float:
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment["HOME"] = str(session.root)
    request = synthetic_payload(sample, case=case)
    request["guard_remaining_ms"] = 4_000
    encoded = json.dumps(request, separators=(",", ":"))
    metrics = session.daemon._server.hook_worker.metrics
    before = route_counts(metrics.snapshot())
    # Include executable/interpreter startup, stdin, transport, stdout and exit.
    started = time.perf_counter()
    completed = run_isolated_hook_process(
        argv,
        input_text=encoded,
        cwd=session.workspace,
        environment=environment,
        timeout_seconds=10.0,
        output_limit=2 * 1024 * 1024,
    )
    elapsed_ms = (time.perf_counter() - started) * 1_000.0
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.containment_failed
        or completed.output_limit_exceeded
    ):
        raise RuntimeError("installed launcher did not complete within its contract")
    try:
        response = json.loads(completed.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("installed launcher did not return harness JSON") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("installed launcher did not return a harness object")
    after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
    route = route_delta(before, after)
    if route != "native_resident":
        raise LauncherAuthorityFailureError(
            before=before,
            after=after,
            route=route,
            response=response,
            completed=completed,
            sample=sample,
            case=case,
            elapsed_ms=elapsed_ms,
        )
    if case == "benign":
        if not is_allowed("PostToolUse", response):
            raise RuntimeError("installed launcher benign fixture failed")
    elif response.get("reason_code") != "output_secret_match" or response.get("model_output_action") != "block":
        raise RuntimeError("installed launcher credential fixture failed")
    return elapsed_ms


def measure_registered_launcher(
    session: AdapterSession, *, iterations: int, samples_sink: list[float] | None = None
) -> dict[str, object]:
    """Install into a private home, then measure its registered PostToolUse argv.

    This first launcher tranche is Claude Code. Other harnesses are explicitly
    unmeasured here; their HTTP route corpus remains independent evidence.
    """

    if iterations <= 0:
        raise ValueError("launcher iterations must be positive")
    context = HarnessContext(home_dir=session.root, workspace_dir=session.workspace, guard_home=session.guard_home)
    ClaudeCodeHarnessAdapter().install(context)
    argv = registered_claude_argv(claude_managed_settings_path(context), "PostToolUse")
    for case in ("benign", "secret"):
        _observe_launcher(session, argv, sample=-1, case=case)
    values = [_observe_launcher(session, argv, sample=index, case="benign") for index in range(iterations)]
    if samples_sink is not None:
        samples_sink.extend(values)
    return {
        "boundary": "INSTALLED_LAUNCHER",
        "evidence_class": "smoke",
        "harness": "claude-code",
        "event": "PostToolUse",
        "configuration": "registered_argv",
        "process_startup_included": True,
        "stdout_and_exit_checked": True,
        "cases_validated": ["benign", "secret"],
        "latency": summarize(values),
        "remaining_routes": "not_measured",
        "qualification_complete": False,
    }
