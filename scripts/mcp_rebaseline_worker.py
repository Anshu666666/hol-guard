"""One isolated source-selected MCP run; the controller owns bounded capture."""

from __future__ import annotations

import argparse
import contextlib
import os
import resource
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.mcp_rebaseline_phases import Phases
from scripts.mcp_rebaseline_trace import (
    CHILD,
    TRACES,
    catalog_result,
    digest,
    encoded,
    messages,
    trace_identity,
    validate_tool_response,
)

MAX_RESULT_BYTES = 16 * 1024 * 1024


def run(
    source: Path,
    *,
    calls: int,
    diagnostic: bool,
    selected: list[str],
    journal: Callable[[dict[str, Any]], None] = lambda record: None,
) -> dict[str, Any]:
    sys.path.insert(0, str(source / "src"))
    imported_at, imported_cpu = time.perf_counter_ns(), time.process_time_ns()
    from codex_plugin_scanner.guard import mcp_tool_calls
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.proxy import runtime_mcp
    from codex_plugin_scanner.guard.store import GuardStore

    imported = {
        "wall_ns": time.perf_counter_ns() - imported_at,
        "process_cpu_ns": time.process_time_ns() - imported_cpu,
    }
    if not Path(runtime_mcp.__file__).resolve().is_relative_to((source / "src").resolve()):
        raise RuntimeError("wrong production source imported")
    if runtime_mcp._TOOLS_CALL_PREWRITE_QUIET_SECONDS != 0.005:
        raise RuntimeError("quiet barrier changed from frozen acceptance")
    phases = Phases()
    reports: list[dict[str, Any]] = []

    class ObservedProxy(runtime_mcp.CodexMcpGuardProxy):
        def _handle_message(self, **kwargs: Any):
            message = kwargs["message"]
            phases.scope = f"{trace.name}/{message['id']}"
            journal(
                {"kind": "request_begin", "trace": trace.name, "request_id": message["id"], "method": message["method"]}
            )
            started, cpu = time.perf_counter_ns(), time.process_time_ns()
            try:
                response, event = super()._handle_message(**kwargs)
            except BaseException as error:
                observations.append(
                    {
                        "request_id": message["id"],
                        "method": message["method"],
                        "wall_ns": time.perf_counter_ns() - started,
                        "process_cpu_ns": time.process_time_ns() - cpu,
                        "failure_type": type(error).__name__,
                    }
                )
                journal({"kind": "request", "trace": trace.name, **observations[-1]})
                raise
            elapsed, used = time.perf_counter_ns() - started, time.process_time_ns() - cpu
            row: dict[str, Any] = {
                "request_id": message["id"],
                "method": message["method"],
                "wall_ns": elapsed,
                "process_cpu_ns": used,
                "response_sha256": digest(response),
                "response_bytes": len(encoded(response)),
            }
            # Preserve an actual response/event digest before the oracle can fail.
            row["event_sha256"] = digest(event)
            if isinstance(event, dict):
                row["decision"] = event.get("decision")
                row["policy_action"] = event.get("policy_action")
            observations.append(row)
            try:
                if message["method"] == "tools/call":
                    row.update(validate_tool_response(message, response, event, trace))
                elif not isinstance(response, dict) or response.get("id") != message["id"] or "error" in response:
                    raise ValueError("initialization/catalog response failed")
                elif message["method"] == "tools/list":
                    generation = sum(row["method"] == "tools/list" for row in observations)
                    if response.get("result") != catalog_result(trace, generation):
                        raise ValueError("catalog content or generation differs from frozen child")
                    row["catalog_result_sha256"] = digest(response["result"])
            finally:
                journal({"kind": "request", "trace": trace.name, **row})
            return response, event

    scope = phases.install(runtime_mcp, mcp_tool_calls, GuardStore) if diagnostic else contextlib.nullcontext()
    with scope:
        for trace in TRACES:
            if selected and trace.name not in selected:
                continue
            observations: list[dict[str, Any]] = []
            approvals: list[dict[str, int]] = []
            trace_report: dict[str, Any] = {
                **trace_identity(trace, calls),
                "observations": observations,
                "approvals": approvals,
                "status": "started",
            }
            reports.append(trace_report)
            journal({"kind": "trace_begin", **trace_identity(trace, calls)})
            with tempfile.TemporaryDirectory(prefix="mcp-rebaseline-") as temporary:
                root = Path(temporary)
                for name in ("home", "workspace", "guard"):
                    (root / name).mkdir()
                context = HarnessContext(
                    home_dir=root / "home", workspace_dir=root / "workspace", guard_home=root / "guard"
                )
                phases.scope = f"{trace.name}/setup"
                started, cpu = time.perf_counter_ns(), time.process_time_ns()
                store = GuardStore(context.guard_home)
                config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
                trace_report["configuration"] = {
                    "mode": config.mode,
                    "default_action": config.default_action,
                    "security_level": config.security_level,
                }
                proxy = ObservedProxy(
                    server_name="synthetic",
                    command=[
                        sys.executable,
                        "-u",
                        "-c",
                        CHILD,
                        str(trace.catalog_size),
                        str(trace.child_delay_ms),
                        str(int(bool(trace.approval_delay_ms))),
                    ],
                    context=context,
                    store=store,
                    config=config,
                    source_scope="project",
                    config_path=str(root / "workspace" / ".mcp.json"),
                )
                trace_report["construction"] = {
                    "wall_ns": time.perf_counter_ns() - started,
                    "process_cpu_ns": time.process_time_ns() - cpu,
                }

                def approve(
                    request: object,
                    *,
                    delay_ms: int = trace.approval_delay_ms,
                    records: list[dict[str, int]] = approvals,
                ) -> dict[str, Any]:
                    if not isinstance(request, dict) or request.get("method") != "elicitation/create":
                        raise ValueError("unexpected approval protocol")
                    begin, used = time.perf_counter_ns(), time.process_time_ns()
                    with phases.span("synthetic_approval_callback") if diagnostic else contextlib.nullcontext():
                        time.sleep(delay_ms / 1000)
                    records.append(
                        {"wall_ns": time.perf_counter_ns() - begin, "process_cpu_ns": time.process_time_ns() - used}
                    )
                    return {"action": "accept", "content": {"decision": "approve"}}

                started, cpu = time.perf_counter_ns(), time.process_time_ns()
                try:
                    result = proxy.run_session(messages(trace, calls), inline_approval_callback=approve)
                    if result["return_code"] != 0 or len(observations) != len(messages(trace, calls)):
                        raise ValueError("incomplete session or child failure")
                    if len(approvals) != (calls if trace.approval_delay_ms else 0):
                        raise ValueError("approval callback count changed")
                    trace_report["status"] = "passed"
                except Exception as error:
                    trace_report["status"] = "failed"
                    trace_report["failure_type"] = type(error).__name__
                    trace_report["failure_detail"] = str(error)[:1024]
                finally:
                    trace_report["session"] = {
                        "wall_ns": time.perf_counter_ns() - started,
                        "process_cpu_ns": time.process_time_ns() - cpu,
                    }
    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    scale = 1 if sys.platform == "darwin" else 1024
    return {
        "schema": "hol-guard.mcp-source-run.v1",
        "status": "passed" if all(r["status"] == "passed" for r in reports) else "failed",
        "diagnostic": diagnostic,
        "import": imported,
        "traces": reports,
        "phases": phases.rows,
        "phase_counts": dict(phases.counts),
        "phase_rows_dropped": phases.dropped,
        "phase_bindings": phases.bindings,
        "quiet_seconds": runtime_mcp._TOOLS_CALL_PREWRITE_QUIET_SECONDS,
        "self_cpu_seconds": own.ru_utime + own.ru_stime,
        "waited_child_cpu_seconds": children.ru_utime + children.ru_stime,
        "self_peak_rss_bytes": own.ru_maxrss * scale,
        "largest_waited_child_peak_rss_bytes": children.ru_maxrss * scale,
        "network_wait": {"status": "not_exercised", "reason": "synthetic_local_stdio_only"},
        "human_wait": {"status": "synthetic_callback_only", "real_human_latency_measured": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--calls", type=int, default=13)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--traces", nargs="*", default=[])
    args = parser.parse_args()
    if not 1 <= args.calls <= 100 or set(args.traces) - {trace.name for trace in TRACES}:
        parser.error("invalid bounded trace selection")
    journal_fd = os.open(args.output.with_suffix(".journal.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    retained = 0

    def journal(record: dict[str, Any]) -> None:
        nonlocal retained
        data = encoded(record) + b"\n"
        retained += len(data)
        if retained > 2 * 1024 * 1024:
            raise ValueError("request journal byte bound")
        view = memoryview(data)
        while view:
            written = os.write(journal_fd, view)
            if written <= 0:
                raise OSError("request journal write incomplete")
            view = view[written:]

    try:
        result = run(
            args.source.resolve(), calls=args.calls, diagnostic=args.diagnostic, selected=args.traces, journal=journal
        )
    except Exception as error:
        result = {
            "schema": "hol-guard.mcp-source-run.v1",
            "status": "failed",
            "failure_type": type(error).__name__,
            "failure_detail": str(error)[:1024],
        }
    finally:
        os.close(journal_fd)
    data = encoded(result)
    if len(data) > MAX_RESULT_BYTES:
        data = encoded({"status": "failed", "failure_type": "evidence_byte_bound", "result_bytes": len(data)})
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
