"""Retain bounded command output, WNOWAIT ownership and observed ancestry."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

from common import MAX_FILE, REPORT, ROOT, SOURCE, file_identity, require, sha256, write_json
from darwin_process import census, identity, key

spec = importlib.util.spec_from_file_location("_intel_current_exit_observer",
                                             SOURCE / "scripts/native_qualification_process.py")
require(spec is not None and spec.loader is not None, "Missing current process observer")
observer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = observer
spec.loader.exec_module(observer)
MAX_HISTORY = 4 * 1024 * 1024
MAX_SNAPSHOT = 1024 * 1024
MAX_INLINE_STREAMS = 16 * 1024 * 1024


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def capture_command(name: str, argv: list[str], *, environment: dict[str, str],
                    timeout: float, cwd: Path) -> dict:
    require(name and all(c.isalnum() or c in "-_" for c in name), "Unsafe command name")
    argv, environment = list(argv), dict(environment)
    quarantine = ROOT / "unsafe-continuation.json"
    require(not quarantine.exists(), "Earlier cleanup is unproven; refusing another command")
    stdout_path, stderr_path = (ROOT / "raw-commands" / (name + suffix)
                                for suffix in (".stdout", ".stderr"))
    receipt = REPORT / (name + "-capture.json")
    started = time.monotonic_ns()
    row = {"name": name, "argv": list(argv), "cwd": str(cwd), "environment": environment,
           "timeout_seconds": timeout, "started_monotonic_ns": started, "state": "started",
           "returncode": None, "timed_out": False, "capture_complete": False}
    write_json(receipt, {"command": row})
    baseline = {}
    baseline_keys = set()
    tracked: dict[tuple, dict] = {}
    history: list[dict] = []
    errors: list[str] = []
    process = leader = exit_observation = None
    history_bytes = 0
    history_incomplete = False

    def history_failure(reason: str) -> None:
        nonlocal history_incomplete
        if not history_incomplete:
            errors.append(reason)
        history_incomplete = True

    def sample() -> dict[int, dict]:
        nonlocal history_bytes
        current = census()
        if leader is not None:
            held = current.get(leader["pid"])
            require(held is not None and key(held) == key(leader), "Original unreaped leader changed")
            tracked[key(held)] = held
            changed = True
            while changed:
                changed = False
                for item in current.values():
                    parent = current.get(item["ppid"])
                    inherited = parent is not None and key(parent) in tracked
                    in_group = item["pgid"] == leader["pid"]
                    if (inherited or in_group) and key(item) not in tracked:
                        require((item["start_seconds"], item["start_microseconds"])
                                >= (leader["start_seconds"], leader["start_microseconds"]),
                                "Older process in owned ancestry")
                        tracked[key(item)] = item
                        changed = True
        # Retention exhaustion must never prevent fresh cleanup census or group signals.
        if not history_incomplete:
            payload = {"owned_uid_census": [current[pid] for pid in sorted(current)],
                       "tracked_identities": [list(value) for value in sorted(tracked)]}
            encoded = compact(payload)
            stamp = time.monotonic_ns()
            digest = sha256(encoded)
            same = bool(history and history[-1]["sha256"] == digest)
            record = {"sha256": digest, "snapshot": payload, "sample_monotonic_ns": [stamp]}
            added = len(str(stamp)) + 1 if same else len(compact(record)) + 1
            if len(encoded) > MAX_SNAPSHOT or history_bytes + added > MAX_HISTORY:
                history_failure("Process history byte bound reached; later cleanup census remains active")
            elif same:
                history[-1]["sample_monotonic_ns"].append(stamp)
                history_bytes += added
            else:
                history.append(record)
                history_bytes += added
        return current

    def cleanup() -> dict:
        nonlocal exit_observation
        result = {"signals": [], "safe_to_continue": False, "complete_descendant_certificate": False,
                  "scope": "Exact unreaped leader, original group and descendants observed by libproc"}
        if process is None:
            result["safe_to_continue"] = True
            return result
        if leader is None:
            result["reason"] = "The new direct child could not be bound to an owned kernel identity"
            return result
        try:
            for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                current = sample()
                if not any(item["pgid"] == process.pid and item["status"] != 5
                           for item in current.values()):
                    break
                held = identity(process.pid)
                require(held is not None and key(held) == key(leader), "Leader changed before group signal")
                try:
                    os.killpg(process.pid, sig)
                    result["signals"].append({"signal": sig.name, "sent": True})
                except ProcessLookupError:
                    result["signals"].append({"signal": sig.name, "sent": False})
                end = time.monotonic() + grace
                while time.monotonic() < end:
                    current = sample()
                    if not any(item["pgid"] == process.pid and item["status"] != 5
                               for item in current.values()):
                        break
                    time.sleep(0.1)
            current = sample()
            live_group = [item for item in current.values()
                          if item["pgid"] == process.pid and item["status"] != 5]
            escaped = [item for item in current.values()
                       if key(item) in tracked and item["pgid"] != process.pid and item["status"] != 5]
            unexplained = [item for item in current.values()
                           if key(item) not in baseline_keys and key(item) not in tracked and item["status"] != 5]
            result.update(live_original_group=live_group, live_observed_descendants_outside_group=escaped,
                          new_unattributed_owned_user_processes=unexplained)
            exit_observation = observer.observe_probe_exit(process.pid)
            result["direct_exit_observation"] = vars(exit_observation) if exit_observation else None
            # Never signal an escaped/unattributed PID by a guessed or recycled identity.
            result["safe_to_continue"] = not live_group and not escaped and not unexplained and exit_observation is not None
            if exit_observation is not None:
                row["returncode"] = process.wait(timeout=1)
                result["direct_child_reaped_after_final_group_and_ancestry_census"] = True
            if not result["safe_to_continue"]:
                result["reason"] = "Owned process retirement or ancestry census is incomplete"
        except BaseException:
            result["safe_to_continue"] = False
            result["error"] = traceback.format_exc()
        return result

    try:
        baseline = census()
        require(len(compact(baseline)) <= MAX_SNAPSHOT, "Initial census byte bound")
        baseline_keys = {key(value) for value in baseline.values()}
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            leader = identity(process.pid)
            require(leader is not None and leader["ppid"] == os.getpid()
                    and leader["pgid"] == process.pid, "New process did not own its session group")
            row["leader"] = leader
            while True:
                sample()
                if history_incomplete:
                    break
                exit_observation = observer.observe_probe_exit(process.pid)
                if exit_observation is not None:
                    row["observed_exit_before_cleanup"] = vars(exit_observation)
                    break
                if max(stdout_path.stat().st_size, stderr_path.stat().st_size) > MAX_FILE:
                    errors.append("Original command output exceeded its declared capture bound")
                    break
                if (time.monotonic_ns() - started) / 1e9 >= timeout:
                    row["timed_out"] = True
                    break
                time.sleep(0.1)
            row["cleanup"] = cleanup()
    except BaseException:
        errors.append(traceback.format_exc())
        row["cleanup"] = cleanup()
    finally:
        row.update(ended_monotonic_ns=time.monotonic_ns(), errors=errors, state="finished",
                   history_complete=not history_incomplete)
        row.setdefault("cleanup", {"safe_to_continue": False})
        # This small terminal receipt precedes every optional large/hash operation.
        write_json(receipt, {"command": row, "retention_stage": "terminal-before-original-readback"})
        if not row["cleanup"]["safe_to_continue"]:
            write_json(quarantine, {"name": name, "cleanup": row["cleanup"], "errors": errors})
        try:
            originals = {}
            for label, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path.exists():
                    row[label] = file_identity(path, maximum=512 * 1024 * 1024, honor_deadline=False)
            total = sum(row.get(label, {}).get("bytes", MAX_INLINE_STREAMS + 1)
                        for label in ("stdout", "stderr"))
            if total <= MAX_INLINE_STREAMS:
                for label, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                    raw = path.read_bytes()
                    require(len(raw) == row[label]["bytes"] and sha256(raw) == row[label]["sha256"],
                            "Original stream changed during inline retention")
                    originals[label] = {"base64": base64.b64encode(raw).decode("ascii"), **row[label]}
            else:
                errors.append("Inline stream bound exceeded; complete originals remain in raw-command archive")
            row["capture_complete"] = not errors and not row["timed_out"] and total <= MAX_INLINE_STREAMS
            payload = {"command": row, "original_streams": originals,
                       "baseline": [baseline[pid] for pid in sorted(baseline)], "history": history,
                       "tracked": [value for _, value in sorted(tracked.items())],
                       "history_compact_bytes": history_bytes,
                       "raw_original_archive": "complete-original-command-streams.tar.gz",
                       "no_complete_escaped_descendant_certificate": True}
            # Compact serialization preserves the measured history and 32 MiB member bounds.
            encoded = compact(payload)
            require(len(encoded) <= MAX_FILE, "Final capture member bound")
            temporary = receipt.with_name(receipt.name + ".full")
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(receipt)
        except BaseException:
            errors.append(traceback.format_exc())
            row["capture_complete"] = False
            write_json(receipt, {"command": row, "retention_stage": "failed",
                                "original_stream_paths": [str(stdout_path), str(stderr_path)]})
    return row
