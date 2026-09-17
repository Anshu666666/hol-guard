#!/usr/bin/env python3
"""Attribute installed worker posture reads before native evaluation.

This component harness invokes the real _review_native_edge method, supplies
synthetic acknowledged/missing snapshot bindings, and stops at the first native
transport call. It neither fabricates a decision nor measures a complete hook.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path


class NativeBoundaryError(Exception):
    def __init__(self, observe_mode: bool) -> None:
        self.observe_mode = observe_mode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000 or not 1 <= args.runs <= 20:
        parser.error("samples must be 1..10000 and runs 1..20")
    if any(key in os.environ for key in ("HOL_GUARD_NATIVE_BINARY", "HOL_GUARD_NATIVE", "HOL_GUARD_TEST_MODE")):
        raise RuntimeError("Remove native/test overrides before measuring installed posture")
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

    distribution = importlib.metadata.distribution("hol-guard")
    installed_root = Path(distribution.locate_file("codex_plugin_scanner")).resolve()
    if not Path(config.__file__).resolve().is_relative_to(installed_root) or "site-packages" not in str(installed_root):
        raise RuntimeError("The selected interpreter did not import the installed wheel")

    class Host(HookWorkerNativeMixin):
        binding = None

        def _native_policy_snapshot(self, *_args, **_kwargs):
            return self.binding

        def _review_raw_hook_native(self, **kwargs):
            raise NativeBoundaryError(kwargs["observe_mode"])

    host = Host()
    cases = (
        ("ack_observe_watch", "observe", "watch", True),
        ("ack_observe_protected_before_new_ack", "observe", "protected", True),
        ("ack_enforce_protected", "enforce", "protected", True),
        ("ack_enforce_watch_before_new_ack", "enforce", "watch", True),
        ("missing_ack_protected", None, "protected", True),
        ("missing_ack_watch", None, "watch", True),
        ("missing_ack_missing_files", None, None, False),
    )
    observations = []
    original_load = config.load_guard_config
    original_open = Path.open
    counts = {"config_load_calls": 0, "home_config_opens": 0, "workspace_config_opens": 0}
    config_cpu_ns = 0
    with tempfile.TemporaryDirectory(prefix="guard-posture-component-") as temporary:
        root = Path(temporary)
        guard_home = root / "guard"
        workspace = root / "workspace"
        guard_home.mkdir()
        workspace.mkdir()
        home_config = guard_home / "config.toml"
        workspace_config = workspace / ".hol-guard.toml"

        def loaded(*load_args, **load_kwargs):
            nonlocal config_cpu_ns
            counts["config_load_calls"] += 1
            start = time.process_time_ns()
            try:
                return original_load(*load_args, **load_kwargs)
            finally:
                config_cpu_ns += time.process_time_ns() - start

        def opened(path, *open_args, **open_kwargs):
            if path == home_config:
                counts["home_config_opens"] += 1
            elif path in (workspace_config, workspace / ".ai-plugin-scanner-guard.toml"):
                counts["workspace_config_opens"] += 1
            return original_open(path, *open_args, **open_kwargs)

        config.load_guard_config = loaded
        Path.open = opened
        try:
            for name, snapshot_mode, posture, workspace_present in cases:
                if posture is None:
                    home_config.unlink(missing_ok=True)
                else:
                    mode = "observe" if posture == "watch" else "enforce"
                    home_config.write_text(f'mode = "{mode}"\nprotection_posture = "{posture}"\n')
                if workspace_present:
                    workspace_config.write_text('security_level = "strict"\n')
                else:
                    workspace_config.unlink(missing_ok=True)
                host.binding = {"mode": snapshot_mode} if snapshot_mode is not None else None
                for run in range(args.runs):
                    before = dict(counts)
                    before_config_cpu = config_cpu_ns
                    cpu, wall, observed = [], [], set()
                    for _ in range(args.samples):
                        cpu_start = time.process_time_ns()
                        wall_start = time.perf_counter_ns()
                        try:
                            host._review_native_edge(
                                payload={"tool_name": "Bash", "tool_input": {"command": "pwd"}},
                                harness="claude-code",
                                event_name="PreToolUse",
                                default_harness="claude-code",
                                home_dir=root,
                                guard_home=guard_home,
                                workspace=workspace,
                                deadline=None,
                            )
                        except NativeBoundaryError as boundary:
                            observed.add(boundary.observe_mode)
                        else:
                            raise RuntimeError("The component did not stop at the native boundary")
                        wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)
                        cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
                    if len(observed) != 1:
                        raise RuntimeError("Posture changed within a stable component fixture")
                    observation = {
                        "case": name,
                        "run": run,
                        "samples": args.samples,
                        "cpu_median_ms": statistics.median(cpu),
                        "wall_median_ms": statistics.median(wall),
                        "config_cpu_total_ms": (config_cpu_ns - before_config_cpu) / 1_000_000,
                        "counts": {key: counts[key] - before[key] for key in counts},
                        "observe_mode": observed.pop(),
                    }
                    observations.append(observation)
                    print(json.dumps(observation), flush=True)
        finally:
            config.load_guard_config = original_load
            Path.open = original_open
    report = {
        "schema": "guard-posture-config-component-v1",
        "boundary": "installed _review_native_edge entry until first native transport call",
        "installed_wheel": True,
        "environment_overrides": False,
        "snapshot_binding": "synthetic acknowledged mode or missing binding; authentication is not exercised",
        "native_decision": "not invoked; sentinel ends component before native transport",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "observations": observations,
        "limitations": [
            "No resident acknowledgement, request/response, availability transformation, or process-tree timing",
            "Stable fixture repetitions do not qualify concurrent posture/update transitions",
            "Config timing is nested within total component timing and must not be added to it",
            "Synthetic configs contain no user paths, commands, policies, or credentials",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
