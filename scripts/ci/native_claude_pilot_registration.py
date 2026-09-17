"""Explicit experimental registration in the qualification fixture's private home."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Protocol

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import claude_managed_settings_path, command_handler_argv
from scripts.ci.prepare_native_claude_launcher import prepare
from scripts.native_slo_priority_launchers import RegisteredLauncher, registered_launcher

EVENTS = ("PreToolUse", "PostToolUse")
ARMS = ("optimized_python", "native_pilot")
LIMIT = 1_000_000


class FixtureContext(Protocol):
    root: Path
    workspace: Path
    guard_home: Path


def _require(condition: bool) -> None:
    if not condition:
        raise RuntimeError("claude_pilot_registration_invalid")


def _read(path: Path) -> bytes:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400)
    _require(metadata.st_nlink == 1 and 0 < metadata.st_size <= LIMIT)
    with path.open("rb") as handle:
        value = handle.read(LIMIT + 1)
    _require(len(value) == metadata.st_size and len(value) <= LIMIT)
    return value


def _replace(path: Path, expected: bytes, value: bytes) -> None:
    _require(_read(path) == expected and 0 < len(value) <= LIMIT)
    temporary = path.with_name(f".pilot-{secrets.token_hex(12)}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            _require(handle.write(value) == len(value))
            handle.flush()
            os.fsync(handle.fileno())
        _require(_read(path) == expected)
        os.replace(temporary, path)
        _require(_read(path) == value)
    finally:
        temporary.unlink(missing_ok=True)


class PilotRegistration:
    """No public install API: the experiment creates and owns this fixture.

    Production ownership/repair does not recognize the pilot yet. Only this
    private experiment swaps the exact two canonical handlers and restores the
    initial installed bytes. Other event groups and matcher/timeout fields are
    preserved byte-for-byte in the decoded configuration.
    """

    def __init__(self, session: FixtureContext) -> None:
        self.session = session
        context = HarnessContext(home_dir=session.root, workspace_dir=session.workspace, guard_home=session.guard_home)
        self.path = claude_managed_settings_path(context)
        _require(self.path == session.root / ".claude" / "settings.json")
        _require(not self.path.exists())
        result = ClaudeCodeHarnessAdapter().install(context)
        _require(result.get("active") is True)
        self.original = _read(self.path)
        self.current = self.original
        self.python = {event: registered_launcher(self.path, "claude-code", event) for event in EVENTS}
        _require(all(not launcher.environment for launcher in self.python.values()))
        # Measure the adapter's installed command, never a reconstructed CLI.
        _require(all(Path(launcher.argv[0]).is_absolute() for launcher in self.python.values()))
        repeated = ClaudeCodeHarnessAdapter().install(context)
        _require(repeated.get("active") is True and _read(self.path) == self.original)
        self.native = {
            event: prepare(guard_home=session.guard_home, home=session.root, workspace=session.workspace, event=event)
            for event in EVENTS
        }
        document: dict[str, Any] = json.loads(self.original)
        candidate = copy.deepcopy(document)
        hooks = candidate["hooks"]
        for event in EVENTS:
            groups = hooks[event]
            _require(len(groups) == 1 and len(groups[0]["hooks"]) == 1)
            handler = groups[0]["hooks"][0]
            _require(command_handler_argv(handler) == self.python[event].argv)
            handler["command"], handler["args"] = self.native[event][0], list(self.native[event][1:])
        self.candidate = (json.dumps(candidate, ensure_ascii=False, indent=2) + "\n").encode()
        self.documents = {"optimized_python": document, "native_pilot": candidate}

    def activate(self, arm: str, event: str) -> RegisteredLauncher:
        _require(arm in ARMS and event in EVENTS)
        expected = self.original if arm == "optimized_python" else self.candidate
        _replace(self.path, self.current, expected)
        self.current = expected
        return self.readback(arm, event)

    def readback(self, arm: str, event: str) -> RegisteredLauncher:
        _require(arm in ARMS and event in EVENTS)
        encoded = _read(self.path)
        _require(encoded == (self.original if arm == "optimized_python" else self.candidate))
        document = json.loads(encoded)
        _require(document == self.documents[arm])
        group = document["hooks"][event][0]
        handler = group["hooks"][0]
        argv = command_handler_argv(handler)
        wanted = self.python[event].argv if arm == "optimized_python" else self.native[event]
        _require(argv == wanted)
        assert argv is not None
        digest = hashlib.sha256(json.dumps({"group": group, "handler": handler}, sort_keys=True).encode()).hexdigest()
        return RegisteredLauncher("claude-code", event, argv, (), digest, self.path)

    def restore(self) -> None:
        _replace(self.path, self.current, self.original)
        self.current = self.original
        for event in EVENTS:
            _require(registered_launcher(self.path, "claude-code", event) == self.python[event])
