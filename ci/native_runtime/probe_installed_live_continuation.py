"""Run one installed Codex bridge action with an external genuine approval.

The owning orchestrator starts an already enrolled daemon, supplies an owned
status path, approves the real pending request and contains this process. This
probe never enrolls, signs an approval, writes policy or seeds operation rows.
Its installed/runtime checks do not replace independent native receipt binding.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import codex_plugin_scanner
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from codex_plugin_scanner.guard.native_approval_protocol import (
    decode_native_approval_v4_result,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

_SCHEMA = "guard.installed-live-continuation.v1"
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{8,128}")
_HEX40 = re.compile(r"[a-f0-9]{40}")
_HEX64 = re.compile(r"[a-f0-9]{64}")


def installed_context() -> dict[str, object]:
    if "site-packages" not in Path(codex_plugin_scanner.__file__).resolve().parts:
        raise ValueError("installed_package_required")
    status = native_runtime_status()
    if (
        status.mode not in {"auto", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or "native-command-program-v1" not in status.capabilities.features
    ):
        raise ValueError("installed_native_required")
    source = status.capabilities.build_sha
    runtime = status.identity.sha256
    rules = status.capabilities.rule_digest
    if (
        not isinstance(source, str)
        or not isinstance(runtime, str)
        or not isinstance(rules, str)
        or not _HEX40.fullmatch(source)
        or not _HEX64.fullmatch(runtime)
        or not _HEX64.fullmatch(rules)
    ):
        raise ValueError("installed_identity_invalid")
    return {
        "installedRuntimeAvailable": True,
        "sourceSha": source,
        "runtimeSha256": runtime,
        "ruleDigest": rules,
    }


def run_waiting_action(
    *,
    guard_home: Path,
    home: Path,
    workspace: Path,
    emit: Callable[[dict[str, object]], None],
    identity: dict[str, object] | None = None,
) -> dict[str, object]:
    """Observe the real response without changing it, then execute fixed pwd once."""
    for directory in (guard_home, home, workspace):
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError("existing_directory_required")
    if not (guard_home / "daemon-state.json").is_file():
        raise ValueError("existing_daemon_required")
    executable = shutil.which("pwd")
    if executable is None or Path(executable).resolve() not in {
        Path("/bin/pwd").resolve(),
        Path("/usr/bin/pwd").resolve(),
    }:
        raise ValueError("fixed_action_unavailable")
    pending: str | None = None
    pending_changed = False
    receipt: dict[str, object] | None = None
    admitted = dict(identity or {})
    original_output = bridge._bridge_output
    original_browser = resume.open_browser_url
    original_post = resume._daemon_json_post
    original_stdin = sys.stdin

    def observed_output(response: dict[str, object], **kwargs: Any) -> str:
        nonlocal pending, pending_changed
        observed = resume.pending_pretool_approval(response, event_name="PreToolUse")
        if observed is not None and _REQUEST_ID.fullmatch(observed[0]):
            if pending is not None and pending != observed[0]:
                pending_changed = True
            pending = observed[0]
            emit(
                {
                    "schema": _SCHEMA,
                    "phase": "pending",
                    "requestId": pending,
                    "actionCount": 0,
                    "completed": False,
                }
            )
        return original_output(response, **kwargs)

    def observed_post(**kwargs: Any) -> dict[str, object] | None:
        nonlocal receipt
        receipt = None
        response = original_post(**kwargs)
        # This observes the shipped authenticated transport. It cannot create
        # a consumed authority object or substitute for the parent's Store join.
        if (
            pending is not None
            and kwargs.get("path") == f"/v1/requests/{pending}/live-decision"
            and kwargs.get("state_path") == guard_home / "daemon-state.json"
            and type(response) is dict
            and response.get("completed") is True
            and response.get("action") == "allow"
        ):
            try:
                decoded = decode_native_approval_v4_result(
                    {
                        "schema": "guard-native-approval-result.v4",
                        "version": 4,
                        "authority": "rust",
                        "receipt": response.get("nativeApprovalReceipt"),
                    },
                    phase="consumed",
                )
            except Exception:
                # An observation failure must neither replace the authenticated
                # transport result nor permit this probe's fixed action.
                decoded = None
            if decoded is not None:
                value = decoded["receipt"]
                if isinstance(value, dict):
                    receipt = dict(value)
        return response

    output = io.StringIO()
    try:
        bridge._bridge_output = observed_output
        resume._daemon_json_post = observed_post
        # Headless execution leaves review to the owning orchestrator.
        resume.open_browser_url = lambda _url: False
        sys.stdin = io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "pwd"},
                    "cwd": str(workspace),
                }
            )
        )
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = bridge.main(
                state_path=guard_home / "daemon-state.json",
                start_command=[],
                fallback_command=[sys.executable, "-I", "-c", "raise SystemExit(1)"],
                query=urlencode({"guard-home": str(guard_home), "home": str(home)}),
                hook_timeouts={"PreToolUse": 30},
            )
    finally:
        sys.stdin = original_stdin
        bridge._bridge_output = original_output
        resume.open_browser_url = original_browser
        resume._daemon_json_post = original_post
    allowed = code == 0 and json.loads(output.getvalue()) == resume.allow_pretool_response()
    receipt_bound = False
    if allowed and pending is not None and receipt is not None and not pending_changed:
        current = installed_context()
        now_ms = time.time_ns() // 1_000_000
        issued = receipt.get("issued_at_ms")
        expires = receipt.get("expires_at_ms")
        receipt_bound = (
            admitted == current
            and admitted.get("installedRuntimeAvailable") is True
            and receipt.get("request_id") == pending
            and receipt.get("harness") == "codex"
            and receipt.get("runtime_binary_identity") == admitted.get("runtimeSha256")
            and receipt.get("rule_digest") == admitted.get("ruleDigest")
            and isinstance(issued, int)
            and isinstance(expires, int)
            and issued <= now_ms < expires
        )
    record: dict[str, object] = {
        "schema": _SCHEMA,
        "phase": "complete",
        "requestId": pending,
        "actionCount": 0,
        "completed": False,
        "bridgeAllowed": allowed,
        "actualPendingObserved": pending is not None,
        "nativeReceiptIndependentlyBound": False,
        "nativeReceiptObserved": receipt is not None,
        "nativeReceiptBoundToInstalledContext": receipt_bound,
        "nativeReceiptSha256": (
            hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if receipt_bound
            else None
        ),
    }
    if not allowed or pending is None or not receipt_bound:
        return record
    # Fixed argv only. No shell, user-provided command or command output is retained.
    completed = subprocess.run(
        [executable],
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    record["actionCount"] = 1
    record["completed"] = completed.returncode == 0 and completed.stdout.rstrip(b"\r\n") == os.fsencode(
        workspace.resolve()
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-home", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    args = parser.parse_args()
    identity: dict[str, object] = {}
    record: dict[str, object]
    failure = "installed_admission_failed"
    try:
        identity = installed_context()
        failure = "owned_status_unavailable"
        # Exclusive creation prevents replacement of an existing caller file.
        fd = os.open(args.status, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as status:

            def emit(record: dict[str, object]) -> None:
                status.seek(0)
                status.write(json.dumps({**identity, **record}, sort_keys=True) + "\n")
                status.truncate()
                status.flush()
                os.fsync(status.fileno())

            emit(
                {
                    "schema": _SCHEMA,
                    "phase": "started",
                    "actionCount": 0,
                    "completed": False,
                }
            )
            try:
                record = run_waiting_action(
                    guard_home=args.guard_home,
                    home=args.home,
                    workspace=args.workspace,
                    emit=emit,
                    identity=identity,
                )
            except Exception:
                record = {
                    "schema": _SCHEMA,
                    "phase": "failed",
                    "completed": False,
                    "actionCount": None,
                    "failure": "probe_operation_failed",
                }
            emit(record)
    except Exception:
        record = {
            "schema": _SCHEMA,
            "phase": "failed",
            "completed": False,
            "actionCount": None,
            "failure": failure,
        }
    print(json.dumps({**identity, **record}, sort_keys=True))
    return 0 if record.get("completed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
