"""Bounded Linux CLI process groups; exact bytes and reaped-tree CPU retained."""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scripts.scanner_pilot_protocol import COMMAND_SECONDS, BudgetExceededError, captured, environment

MAX_CAPTURE = 8 * 1024 * 1024


class AttemptFailedError(RuntimeError):
    def __init__(self, code: str, evidence: dict[str, Any]):
        super().__init__(code)
        self.code, self.evidence = code, evidence


def _cpu() -> float:
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _alive(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def run_command(command: list[str], root: Path, *, timeout: float = COMMAND_SECONDS) -> dict[str, Any]:
    if sys.platform != "linux" or not 0 < timeout <= COMMAND_SECONDS:
        raise ValueError("scanner_process_platform_or_deadline")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    failure = None
    process = None
    before, start = _cpu(), time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with selectors.DefaultSelector() as selector:
            for name in streams:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "command_deadline"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        retained = streams[key.data]
                        retained.extend(chunk[: max(0, MAX_CAPTURE - sum(map(len, streams.values())))])
                        if sum(map(len, streams.values())) >= MAX_CAPTURE:
                            failure = "capture_byte_bound"
                            break
                if failure:
                    break
            if not failure:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except BudgetExceededError:
        failure = "controller_deadline"
    except subprocess.TimeoutExpired:
        failure = "command_deadline"
    except (OSError, ValueError):
        failure = "process_io_failed"
    except BaseException:
        failure = "process_interrupted"
    finally:
        if process is not None:
            # A normal source CLI reaps its Git/Rust children. Surviving group
            # members invalidate CPU completeness even if the CLI exited zero.
            try:
                if process.poll() is None or _alive(process.pid):
                    failure = failure or "descendant_cleanup_required"
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                if _alive(process.pid):
                    failure = "containment_unconfirmed"
            except (OSError, subprocess.TimeoutExpired):
                failure = "containment_unconfirmed"
            finally:
                for name in streams:
                    stream = getattr(process, name)
                    if stream is not None:
                        stream.close()
    elapsed, cpu = time.perf_counter_ns() - start, (_cpu() - before) * 1000
    return {
        "returncode": None if process is None else process.returncode,
        "failure": failure,
        "full_cli_wall_ms": elapsed / 1e6,
        "full_cli_process_tree_cpu_ms": cpu if failure is None and cpu >= 0 else None,
        "cpu_scope": "reaped_cli_git_and_native_descendants",
        "stdout": captured(bytes(streams["stdout"])),
        "stderr": captured(bytes(streams["stderr"])),
    }


def full_cli(
    source_root: Path,
    target: Path,
    workflow: str,
    *,
    extra_args: tuple[str, ...] = (),
    expected_exit: int = 0,
    default_bounds: bool = False,
    native_pilot_binary: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    import base64

    if native_pilot_binary is None:
        code = "import sys;sys.argv[0]='hol-guard';from codex_plugin_scanner.cli import main;raise SystemExit(main())"
    else:
        code = (
            "import sys;from pathlib import Path;from secret_scan_native_pilot import cli_main;"
            "binary=Path(sys.argv.pop(1));sys.argv[0]='hol-guard';raise SystemExit(cli_main(binary))"
        )
    command = [sys.executable, "-c", code]
    if native_pilot_binary is not None:
        command.append(str(native_pilot_binary))
    command.extend(["secrets", "scan", str(target), "--json"])
    if not default_bounds:
        command.extend(["--max-findings", "10000"])
    if workflow in {"staged", "history"}:
        command.append("--" + workflow)
    command.extend(extra_args)
    result = run_command(command, source_root)
    if result["failure"] or result["returncode"] != expected_exit:
        raise AttemptFailedError(result["failure"] or "unexpected_cli_exit", result)
    try:
        stdout = base64.b64decode(result["stdout"]["base64"])
        public = json.loads(stdout) if stdout else None
        if public is not None and not isinstance(public, dict):
            raise ValueError("not_object")
        if native_pilot_binary is not None:
            rows = [
                line.removeprefix(b"GUARD_REGEX_PILOT_STATS=")
                for line in base64.b64decode(result["stderr"]["base64"]).splitlines()
                if line.startswith(b"GUARD_REGEX_PILOT_STATS=")
            ]
            if len(rows) != 1:
                raise ValueError("stats_missing")
            stats = json.loads(rows[0])
            expected = {
                "native_files",
                "python_fallback_files",
                "requests",
                "input_bytes",
                "response_bytes",
                "cleanup_failures",
            }
            if (
                set(stats) != expected
                or any(type(v) is not int or v < 0 for v in stats.values())
                or stats["cleanup_failures"]
            ):
                raise ValueError("stats_invalid")
            result.update({"native_pilot_" + key: value for key, value in stats.items()})
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        raise AttemptFailedError("cli_result_invalid", result) from error
    result["cli_exit"] = result["returncode"]
    return result, public
