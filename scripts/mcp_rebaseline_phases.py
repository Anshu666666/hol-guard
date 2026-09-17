"""Scoped diagnostic wrappers around actual MCP helpers; never replace work."""

from __future__ import annotations

import contextlib
import functools
import threading
import time
from collections import Counter
from typing import Any
from unittest.mock import patch

MAX_ROWS = 100000


class Phases:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.counts: Counter[str] = Counter()
        self.local = threading.local()
        self.dropped = 0
        self.scope = "setup"
        self.bindings: list[str] = []

    @contextlib.contextmanager
    def span(self, name: str):
        stack = getattr(self.local, "stack", None)
        if stack is None:
            self.local.stack = stack = []
        frame = [0, 0]
        stack.append(frame)
        wall, cpu = time.perf_counter_ns(), time.thread_time_ns()
        failed = False
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            elapsed, used = time.perf_counter_ns() - wall, time.thread_time_ns() - cpu
            stack.pop()
            if stack:
                stack[-1][0] += elapsed
                stack[-1][1] += used
            self.counts[name] += 1
            row = {
                "scope": self.scope,
                "phase": name,
                "wall_ns": elapsed,
                "thread_cpu_ns": used,
                "exclusive_wall_ns": max(0, elapsed - frame[0]),
                "exclusive_thread_cpu_ns": max(0, used - frame[1]),
                "failed": failed,
            }
            if len(self.rows) < MAX_ROWS:
                self.rows.append(row)
            else:
                self.dropped += 1

    def wrapper(self, function: Any, name: str):
        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any):
            selected = name
            if name == "child_frame_wait":
                selected = (
                    "child_response_wait"
                    if kwargs.get("required")
                    else ("quiet_frame_wait" if kwargs.get("timeout_seconds", 0) > 0 else "child_frame_poll")
                )
            elif name == "catalog_drain":
                selected = "final_quiet_barrier" if kwargs.get("quiet_seconds", 0) > 0 else "catalog_drain"
            with self.span(selected):
                value = function(*args, **kwargs)
            if name.startswith("serialization") and isinstance(value, (str, bytes)):
                self.counts[f"{name}.output_bytes"] += len(value.encode("utf-8") if isinstance(value, str) else value)
            if name == "hash.sha256" and args and isinstance(args[0], (bytes, bytearray, memoryview)):
                self.counts["hash.sha256.input_bytes"] += len(args[0])
            return value

        return wrapped

    @contextlib.contextmanager
    def install(self, runtime: Any, risk: Any, store_class: Any):
        cls = runtime.RuntimeMcpGuardProxy
        with contextlib.ExitStack() as stack:

            def bind(owner: Any, symbol: str, name: str, *, optional: bool = False) -> None:
                if not hasattr(owner, symbol):
                    if optional:
                        return
                    raise RuntimeError(f"missing diagnostic boundary: {symbol}")
                self.bindings.append(f"{owner.__name__}.{symbol}")
                stack.enter_context(patch.object(owner, symbol, self.wrapper(getattr(owner, symbol), name)))

            for symbol, name in (
                ("_start_process", "child_startup_and_launch_identity"),
                ("_capture_tools_catalog", "catalog_capture"),
                ("_resolve_tool_call_authority", "authority_composite"),
                ("_drain_child_messages", "catalog_drain"),
                ("_next_child_output_frame", "child_frame_wait"),
                ("_forward_message", "forwarding_composite"),
            ):
                bind(cls, symbol, name)
            bind(runtime, "_tool_catalog_fingerprint", "catalog_fingerprint")
            for symbol, name in (
                ("evaluate_tool_call", "policy_evaluation_composite"),
                ("build_tool_call_hash", "request_identity"),
                ("allow_tool_call", "receipt_and_inventory_composite"),
            ):
                original = getattr(risk, symbol)
                wrapped = self.wrapper(original, name)
                for owner in (runtime, risk):
                    stack.enter_context(patch.object(owner, symbol, wrapped))
                    self.bindings.append(f"{owner.__name__}.{symbol}")
            bind(risk, "tool_call_risk_categories", "classification_categories")
            bind(risk, "tool_call_risk_signals", "classification_signals")
            bind(
                risk, "_tool_call_risk_signals_for_categories", "classification_signals_from_categories", optional=True
            )
            bind(store_class, "resolve_policy_decision_lookup_with_memory_pattern", "policy_store_lookup")
            for symbol in ("record_inventory_artifact", "add_receipt", "add_event", "upsert_policy"):
                bind(store_class, symbol, f"persistence.{symbol}")
            modules = [runtime, risk]
            try:
                from codex_plugin_scanner.guard.proxy import tool_catalog

                modules.append(tool_catalog)
            except ImportError:
                pass  # The frozen baseline has no immutable ToolCatalog module.
            for module in modules:
                original_json = module.json

                class JsonProxy:
                    dumps: Any = None
                    loads: Any = None

                    def __getattr__(self, attribute: str, original: Any = original_json):
                        return getattr(original, attribute)

                proxy = JsonProxy()
                proxy.dumps = self.wrapper(original_json.dumps, "serialization.json_dumps")
                proxy.loads = self.wrapper(original_json.loads, "serialization.json_loads")
                stack.enter_context(patch.object(module, "json", proxy))
                if hasattr(module, "sha256"):
                    bind(module, "sha256", "hash.sha256")
            try:
                from codex_plugin_scanner.guard.proxy import framing
            except ImportError:
                framing = None
            if framing is not None:
                bind(framing, "encoded_line", "serialization.frame_encode", optional=True)
            yield self
