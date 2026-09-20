from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.launcher_campaign_controller import ARM_SECONDS, STDERR_LIMIT, STDOUT_LIMIT, collect
from scripts.ci.launcher_campaign_worker import configuration


@contextmanager
def owned(code: str) -> Iterator[subprocess.Popen[bytes]]:
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    try:
        yield process
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=5)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def test_collect_real_owned_output_exactly_once_without_kill() -> None:
    killed = []
    with owned("import os;os.write(1,b'original-output');os.write(2,b'original-error')") as process:
        stdout, stderr, failure = collect(process, lambda: killed.append(True), wall_seconds=5)
    assert (stdout, stderr, failure) == (b"original-output", b"original-error", None)
    assert killed == []
    assert ARM_SECONDS == 4800


@pytest.mark.parametrize(
    "descriptor,limit,label", [(1, STDOUT_LIMIT, "stdout_limit"), (2, STDERR_LIMIT, "stderr_limit")]
)
def test_stream_bound_retains_exact_bounded_prefix_and_kills_owned_group(
    descriptor: int, limit: int, label: str
) -> None:
    killed = []
    code = f"import os,time;os.write({descriptor},b'x'*{limit + 65536});time.sleep(5)"
    with owned(code) as process:

        def kill() -> None:
            killed.append(True)
            os.killpg(process.pid, signal.SIGKILL)

        stdout, stderr, failure = collect(process, kill, wall_seconds=5)
    assert failure == label and killed == [True]
    assert (stdout if descriptor == 1 else stderr) == b"x" * limit


def test_original_child_exit_does_not_remove_inherited_pipe_deadline() -> None:
    code = "import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(5)'])"
    killed = []
    with owned(code) as process:

        def kill() -> None:
            killed.append(True)
            os.killpg(process.pid, signal.SIGKILL)

        stdout, stderr, failure = collect(process, kill, wall_seconds=0.2)
        assert process.poll() == 0
    assert failure == "wall_time" and killed == [True] and stdout == stderr == b""


def test_failed_kill_does_not_erase_original_partial_capture() -> None:
    def unavailable() -> None:
        raise PermissionError("do not export")

    with owned("import os,time;os.write(1,b'partial');time.sleep(5)") as process:
        stdout, stderr, failure = collect(process, unavailable, wall_seconds=0.2)
    assert (stdout, stderr, failure) == (b"partial", b"", "wall_time_kill_failed")


def inputs() -> dict[str, Any]:
    return {
        "schema": "hol-guard.launcher-worker-input.v1",
        "arm": "baseline",
        "block": 0,
        "host_sha256": "a" * 64,
        "host_class_sha256": "b" * 64,
        "wheel": "/private/selected.whl",
        "python": "/private/venv/bin/python",
        "providers": "/private/providers",
        "contract": {},
    }


def test_actual_configuration_bytes_and_digest_are_bound(tmp_path: Path) -> None:
    value = inputs()
    body = json.dumps(value).encode()
    path = tmp_path / "configuration.json"
    path.write_bytes(body)
    assert configuration(path, hashlib.sha256(body).hexdigest()) == value
    with pytest.raises(ValueError, match="binding"):
        configuration(path, "a" * 64)


@pytest.mark.parametrize("mutation", ["duplicate", "extra", "relative", "schema"])
def test_ambiguous_or_changed_configuration_is_refused(tmp_path: Path, mutation: str) -> None:
    value = inputs()
    if mutation == "extra":
        value["extra"] = True
    elif mutation == "relative":
        value["wheel"] = "relative.whl"
    elif mutation == "schema":
        value["schema"] = "other"
    body = json.dumps(value).encode()
    if mutation == "duplicate":
        body = body[:-1] + b',"arm":"candidate"}'
    path = tmp_path / "configuration.json"
    path.write_bytes(body)
    with pytest.raises(ValueError):
        configuration(path, hashlib.sha256(body).hexdigest())


def test_configuration_refuses_fifo_and_symlink_before_read(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="file"):
        configuration(fifo, "a" * 64)
    target = tmp_path / "target"
    target.write_bytes(b"{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        configuration(link, "a" * 64)


@pytest.mark.parametrize("kind", ["complete", "leftover", "kill_failure", "spawn_failure", "initial_nonempty"])
def test_host_flow_preserves_root_cleanup_and_never_promotes_emergency_cleanup(
    tmp_path: Path, monkeypatch, kind: str
) -> None:
    from types import SimpleNamespace

    from scripts.ci import launcher_campaign_controller as module

    root = tmp_path / "groups"
    root.mkdir()
    python = tmp_path / "python"
    python.write_bytes(b"modeled-owned-interpreter")
    python.chmod(0o755)
    events: list[str] = []
    state = {"live": kind == "initial_nonempty"}
    original_open = os.open
    original_fstat = os.fstat

    def descriptor_open(path, flags: int, *args, **kwargs) -> int:
        if path == "cgroup.kill":
            return original_open(os.devnull, os.O_WRONLY)
        return original_open(path, flags, *args, **kwargs)

    def group_metadata(descriptor: int) -> Any:
        original = original_fstat(descriptor)
        return SimpleNamespace(st_uid=0, st_mode=original.st_mode)

    def drop(_descriptor: int, uid: int, gid: int, _libc: Any) -> None:
        assert (uid, gid) == (1001, 1001)
        events.append("placed_then_drop_before_exec")
        state["live"] = True

    def kill(_descriptor: int) -> None:
        events.append("kill_owned_group")
        if kind == "kill_failure":
            raise OSError("private failure")
        state["live"] = False

    class Process:
        stdout = None
        stderr = None

        def wait(self, *, timeout: float) -> int:
            assert timeout in {1.0, 2.0}
            events.append("wait")
            if kind not in {"leftover", "kill_failure"}:
                state["live"] = False
            return 0

    def spawn(command: list[str], **kwargs: Any) -> Any:
        events.append("spawn_offer")
        assert command[0:3] == [str(python), "-I", "-c"]
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        assert len(kwargs["pass_fds"]) == 1
        if kind == "spawn_failure":
            raise OSError("private spawn failure")
        kwargs["preexec_fn"]()
        return Process()

    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1, no_site=1)))
    monkeypatch.setattr(module.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(module.os, "listdir", lambda _path: ["single"])
    monkeypatch.setattr(module.os, "open", descriptor_open)
    monkeypatch.setattr(module.os, "fstat", group_metadata)
    monkeypatch.setattr(module, "group_empty", lambda _fd: not state["live"])
    monkeypatch.setattr(module, "drop_worker_identity", drop)
    monkeypatch.setattr(module, "kill_group", kill)
    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module, "collect", lambda _process, _kill: (b"private original", b"", None))
    report = module.run(python, tmp_path / "configuration", "a" * 64, 1001, 1001)
    assert report["outer_wall_seconds"] == 4800
    assert report["private_body_is_export_approved"] is False
    assert "private failure" not in json.dumps(report)
    if kind == "complete":
        assert report["worker_reaped"] is report["group_empty_before_cleanup"] is report["cleanup_complete"] is True
        assert report["emergency_group_kill_used"] is False
    elif kind in {"leftover", "kill_failure"}:
        assert report["group_empty_before_cleanup"] is False
        assert report["emergency_group_kill_used"] is True
        assert report["cleanup_complete"] is (kind == "leftover")
    else:
        assert report["worker_launched"] is False and report["fault"] is not None
        assert "placed_then_drop_before_exec" not in events
        assert report["cleanup_complete"] is True
    if kind == "initial_nonempty":
        assert "spawn_offer" not in events
    else:
        assert events.count("spawn_offer") == 1
