"""Bounded falsification controls for the actual receiver-fill and stderr helpers.

The guarded caller supplies the source-admitted lifecycle-support module.
Only module-local providers are replaced, and their exact identities return.
No native process, receiver thread, host socket or test deadline is started.
"""

from __future__ import annotations

import errno
import io
import traceback
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch

_PAYLOAD = b"controlled diagnostic backpressure"
_PATH = "/owned/phase.sock"


class _FillSocket:
    def __init__(self, owner: "_FillProvider", index: int, plan: dict[str, Any]) -> None:
        self.owner, self.index, self.plan = owner, index, plan
        self.closed = False
        self.close_calls = 0
        self.send_count = 0

    def __enter__(self) -> "_FillSocket":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.close_calls += 1
        self.closed = True
        if self.plan.get("failure") == "close":
            raise OSError(errno.EIO, "controlled close failure")

    def fileno(self) -> int:
        return -1 if self.closed else 100 + self.index

    def setblocking(self, value: bool) -> None:
        assert value is False
        self.owner.operation(self.index, "setblocking")

    def connect(self, value: str) -> None:
        assert value == _PATH
        self.owner.operation(self.index, "connect")

    def getsockopt(self, level: int, option: int) -> int:
        assert (level, option) == (self.owner.constants.SOL_SOCKET, self.owner.constants.SO_SNDBUF)
        self.owner.operation(self.index, "getsockopt")
        return 32768

    def send(self, payload: bytes, flags: int) -> int:
        assert not self.closed and payload == _PAYLOAD
        assert flags == self.owner.constants.MSG_DONTWAIT | self.owner.constants.MSG_NOSIGNAL
        self.owner.operation(self.index, "send")
        actions = self.plan.get("actions", ("ok", "block"))
        action = actions[self.send_count] if self.send_count < len(actions) else self.plan.get("repeat")
        assert action is not None, "unexpected extra send"
        self.send_count += 1
        self.owner.sends.append((self.index, action))
        if action == "block":
            raise BlockingIOError(errno.EAGAIN, "controlled refusal")
        if action == "wrong_errno":
            raise BlockingIOError(errno.EINPROGRESS, "controlled wrong errno")
        if action == "partial":
            return len(payload) - 1
        assert action == "ok"
        return len(payload)


class _FillProvider:
    def __init__(self, support: ModuleType, plans: list[dict[str, Any]], queue: Any = b"512\n") -> None:
        self.plans, self.queue = plans, queue
        self.created: list[_FillSocket] = []
        self.sends: list[tuple[int, str]] = []
        self.operations: list[tuple[int, str]] = []
        self.queue_reads: list[int] = []
        real = support.socket
        self.constants = SimpleNamespace(
            AF_UNIX=real.AF_UNIX,
            SOCK_DGRAM=real.SOCK_DGRAM,
            MSG_DONTWAIT=real.MSG_DONTWAIT,
            MSG_NOSIGNAL=real.MSG_NOSIGNAL,
            SOL_SOCKET=real.SOL_SOCKET,
            SO_SNDBUF=real.SO_SNDBUF,
        )
        self.socket = SimpleNamespace(**vars(self.constants), socket=self.create)

    def operation(self, index: int, name: str) -> None:
        self.operations.append((index, name))
        if self.plans[index].get("failure") == name:
            raise OSError(errno.EIO, "controlled " + name + " failure")

    def create(self, family: int, kind: int) -> _FillSocket:
        assert (family, kind) == (self.constants.AF_UNIX, self.constants.SOCK_DGRAM)
        index = len(self.created)
        assert index < len(self.plans), "unexpected extra filler"
        self.operation(index, "create")
        result = _FillSocket(self, index, self.plans[index])
        self.created.append(result)
        return result

    def fstat(self, descriptor: int) -> Any:
        index = descriptor - 100
        assert 0 <= index < len(self.created) and not self.created[index].closed
        self.operation(index, "fstat")
        inode = self.plans[index].get("inode", index + 1)
        return SimpleNamespace(st_dev=7, st_ino=inode)

    def path(self, value: str) -> Any:
        assert value == "/proc/sys/net/unix/max_dgram_qlen"
        owner = self

        class QueueStream(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                assert size == 129
                owner.queue_reads.append(size)
                return super().read(size)

        def opened(mode: str) -> QueueStream:
            assert mode == "rb"
            if isinstance(owner.queue, BaseException):
                raise owner.queue
            return QueueStream(owner.queue)

        return SimpleNamespace(open=opened)


@contextmanager
def _providers(support: ModuleType, **replacements: Any) -> Any:
    originals = {name: getattr(support, name) for name in replacements}
    try:
        with patch.multiple(support, **replacements):
            yield
    finally:
        assert all(getattr(support, name) is value for name, value in originals.items())


def _fill(
    support: ModuleType,
    plans: list[dict[str, Any]],
    *,
    queue: Any = b"512\n",
    body_error: BaseException | None = None,
) -> dict[str, Any]:
    provider = _FillProvider(support, plans, queue)
    evidence: dict[str, Any] = {}
    yielded = False
    caught: BaseException | None = None
    with _providers(
        support, socket=provider.socket, os=SimpleNamespace(fstat=provider.fstat), Path=provider.path
    ):
        try:
            with support.fill_owned_receiver(SimpleNamespace(path=_PATH), evidence) as admitted:
                assert admitted is evidence
                yielded = True
                assert evidence["fresh_first_send_refused"] is True
                assert evidence["all_fillers_closed"] is False
                assert len(provider.created) >= 2 and all(not item.closed for item in provider.created)
                identities = {(row["socket_device"], row["socket_inode"]) for row in evidence["senders"]}
                assert len(identities) == len(evidence["senders"])
                assert evidence["senders"][-1]["attempts"] == 1
                if body_error is not None:
                    raise body_error
        except BaseException as exc:
            caught = exc
    assert all(item.closed and item.close_calls == 1 for item in provider.created)
    assert evidence["all_fillers_closed"] is True
    assert evidence["total_attempts"] == sum(stage == "send" for _, stage in provider.operations)
    assert evidence["accepted"] == sum(action == "ok" for _, action in provider.sends)
    assert evidence["total_attempts"] <= 1024 and len(provider.created) <= 16
    return {"provider": provider, "evidence": evidence, "yielded": yielded, "caught": caught}


def _success(support: ModuleType) -> dict[str, Any]:
    result = _fill(
        support, [{"actions": ("ok", "block")}, {"actions": ("ok", "block")}, {"actions": ("block",)}]
    )
    assert result["caught"] is None and result["yielded"]
    evidence = result["evidence"]
    assert evidence["total_attempts"] == 5 and evidence["accepted"] == 2
    assert [row["blocked_on_first_send"] for row in evidence["senders"]] == [False, False, True]
    assert [row["accepted"] for row in evidence["senders"]] == [1, 1, 0]
    assert evidence["queue_limit"] == 512 and evidence["queue_limit_error"] is None
    assert all(row["send_buffer_bytes"] == 32768 for row in evidence["senders"])
    assert evidence["operation_failure"] is evidence["terminal_error"] is None
    assert evidence["terminal_errno"] is None
    assert evidence["terminal_stage"] is evidence["terminal_sender_index"] is None
    assert evidence["payload_bytes"] == len(_PAYLOAD)
    return evidence


def _refusal(support: ModuleType, name: str) -> dict[str, Any]:
    plans = {
        "first_sender_refusal": [{"actions": ("block",)}],
        "send_cap": [{"actions": ("ok",), "repeat": "ok"}],
        "socket_cap": [{"actions": ("ok", "block")} for _ in range(16)],
        "reused_identity": [{"actions": ("ok", "block")}, {"inode": 1}],
        "partial_send": [{"actions": ("partial",)}],
        "wrong_block_errno": [{"actions": ("wrong_errno",)}],
    }
    result = _fill(support, plans[name])
    assert isinstance(result["caught"], AssertionError) and not result["yielded"]
    evidence = result["evidence"]
    assert evidence["fresh_first_send_refused"] is False
    if name == "send_cap":
        assert evidence["total_attempts"] == evidence["accepted"] == 1024
        assert len(result["provider"].created) == 1
    elif name == "socket_cap":
        assert evidence["total_attempts"] == 32 and evidence["accepted"] == 16
        assert len(result["provider"].created) == 16
    elif name == "reused_identity":
        assert evidence["total_attempts"] == 2 and len(result["provider"].created) == 2
    else:
        assert evidence["total_attempts"] == 1 and evidence["accepted"] == 0
    if name == "wrong_block_errno":
        assert evidence["senders"][0]["blocked_errno"] == errno.EINPROGRESS
    return evidence


def _operation_error(support: ModuleType, stage: str) -> dict[str, Any]:
    plans = [{"actions": ("ok", "block")}, {"actions": ("block",), "failure": stage}]
    if stage == "close":
        plans = [{"actions": ("ok", "block"), "failure": "close"}, {"actions": ("block",)}]
    result = _fill(support, plans)
    assert isinstance(result["caught"], OSError) and result["caught"].errno == errno.EIO
    assert result["yielded"] is (stage == "close")
    evidence = result["evidence"]
    assert evidence["terminal_error"] == "OSError"
    assert evidence["terminal_errno"] == errno.EIO
    expected_stage = {
        "create": "socket_create",
        "setblocking": "set_nonblocking",
        "connect": "connect",
        "fstat": "socket_identity",
        "getsockopt": "send_buffer_metadata",
        "send": "send",
        "close": "owned_cleanup",
    }[stage]
    assert evidence["terminal_stage"] == expected_stage
    assert evidence["terminal_sender_index"] == (None if stage == "close" else 1)
    if stage == "close":
        assert evidence["operation_failure"] is None
    else:
        assert evidence["operation_failure"] == {
            "stage": expected_stage,
            "sender_index": 1,
            "error": "OSError",
            "errno": errno.EIO,
        }
    return evidence


def _body_failure(support: ModuleType) -> dict[str, Any]:
    error = RuntimeError("controlled body failure")
    result = _fill(support, [{"actions": ("ok", "block")}, {"actions": ("block",)}], body_error=error)
    assert result["yielded"] and result["caught"] is error
    assert result["evidence"]["terminal_error"] == "RuntimeError"
    assert result["evidence"]["terminal_errno"] is None
    assert result["evidence"]["terminal_stage"] == "control_body"
    assert result["evidence"]["terminal_sender_index"] == 1
    assert result["evidence"]["operation_failure"] == {
        "stage": "control_body", "sender_index": 1, "error": "RuntimeError", "errno": None
    }
    return result["evidence"]


def _failure_during_cleanup(support: ModuleType) -> dict[str, Any]:
    result = _fill(support, [
        {"actions": ("ok", "block"), "failure": "close"},
        {"failure": "connect"},
    ])
    assert not result["yielded"]
    assert isinstance(result["caught"], OSError) and result["caught"].errno == errno.EIO
    assert result["caught"].strerror == "controlled close failure"
    evidence = result["evidence"]
    assert evidence["operation_failure"] == {
        "stage": "connect", "sender_index": 1, "error": "OSError", "errno": errno.EIO
    }
    assert evidence["terminal_stage"] == "owned_cleanup"
    assert evidence["terminal_sender_index"] is None
    assert evidence["terminal_error"] == "OSError" and evidence["terminal_errno"] == errno.EIO
    return evidence


def _queue_metadata(support: ModuleType, mode: str) -> dict[str, Any]:
    values = {
        "unavailable": FileNotFoundError(errno.ENOENT, "unavailable"),
        "invalid": b"bad",
        "oversize": b"9" * 129,
    }
    result = _fill(support, [{"actions": ("ok", "block")}, {"actions": ("block",)}], queue=values[mode])
    assert result["yielded"] and result["caught"] is None
    evidence = result["evidence"]
    assert evidence["queue_limit"] is None
    assert evidence["queue_limit_error"] == ("FileNotFoundError" if mode == "unavailable" else "ValueError")
    assert evidence["queue_limit_errno"] == (errno.ENOENT if mode == "unavailable" else None)
    assert result["provider"].queue_reads == ([] if mode == "unavailable" else [129])
    return evidence


def _stderr(support: ModuleType, mode: str) -> dict[str, Any]:
    sequences: dict[str, list[Any]] = {
        "eof": [b"a", b"bc", b""],
        "boundary": [b"x" * 4096, b""],
        "overflow": [b"x" * 4097],
        "would_block": [BlockingIOError(errno.EAGAIN, "controlled")],
        "read_error": [OSError(errno.EIO, "controlled")],
        "setblocking_error": [],
        "close_error": [b""],
    }
    queue = list(sequences[mode])
    reads: list[int] = []
    closes: list[int] = []

    def blocking(descriptor: int, enabled: bool) -> None:
        assert (descriptor, enabled) == (91, False)
        if mode == "setblocking_error":
            raise OSError(errno.EIO, "controlled")

    def read(descriptor: int, size: int) -> bytes:
        assert descriptor == 91 and 0 < size <= 4097
        reads.append(size)
        assert queue, "unexpected read after terminal observation"
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert len(item) <= size
        return item

    def close(descriptor: int) -> None:
        assert descriptor == 91
        closes.append(descriptor)
        if mode == "close_error":
            raise OSError(errno.EIO, "controlled")

    with _providers(support, os=SimpleNamespace(set_blocking=blocking, read=read, close=close)):
        result = support.retain_native_stderr(91)
    assert not queue and closes == [91]
    assert result["complete"] is (mode in {"eof", "boundary"})
    assert result["descriptor_closed"] is (mode != "close_error")
    assert result["overflow"] is (mode == "overflow")
    assert result["would_block"] is (mode == "would_block")
    assert result["error_errno"] == (errno.EIO if mode in {"read_error", "setblocking_error"} else None)
    assert result.get("close_errno") == (errno.EIO if mode == "close_error" else None)
    expected = {"eof": b"abc", "boundary": b"x" * 4096, "overflow": b"x" * 4097}.get(mode, b"")
    expected_reads = {
        "eof": [4097, 4096, 4094],
        "boundary": [4097, 1],
        "overflow": [4097],
        "would_block": [4097],
        "read_error": [4097],
        "setblocking_error": [],
        "close_error": [4097],
    }
    assert reads == expected_reads[mode]
    assert bytes.fromhex(result["content_hex"]) == expected and result["bytes"] == len(expected)
    return result | {"read_request_sizes": reads}


def run_controls(support: ModuleType) -> dict[str, Any]:
    cases: list[tuple[str, Any]] = [
        ("used_refusal_fresh_success_then_fresh_refusal", lambda: _success(support))
    ]
    cases.extend(
        (name, lambda name=name: _refusal(support, name))
        for name in (
            "first_sender_refusal",
            "send_cap",
            "socket_cap",
            "reused_identity",
            "partial_send",
            "wrong_block_errno",
        )
    )
    cases.extend(
        ("operation_" + stage, lambda stage=stage: _operation_error(support, stage))
        for stage in ("create", "setblocking", "connect", "fstat", "getsockopt", "send", "close")
    )
    cases.append(("body_failure_identity_and_cleanup", lambda: _body_failure(support)))
    cases.append(("operation_failure_survives_cleanup_error", lambda: _failure_during_cleanup(support)))
    cases.extend(
        ("queue_" + mode, lambda mode=mode: _queue_metadata(support, mode))
        for mode in ("unavailable", "invalid", "oversize")
    )
    cases.extend(
        ("stderr_" + mode, lambda mode=mode: _stderr(support, mode))
        for mode in (
            "eof", "boundary", "overflow", "would_block",
            "read_error", "setblocking_error", "close_error",
        )
    )
    assert len(cases) == 26
    results: list[dict[str, Any]] = []
    for name, operation in cases:
        try:
            evidence = operation()
            results.append({"case": name, "passed": True, "evidence": evidence})
        except BaseException as exc:
            results.append({
                "case": name,
                "passed": False,
                "error": type(exc).__name__,
                "traceback": traceback.format_exc(),
            })
    return {
        "schema": "pr2974.native_backpressure.controls.v1",
        "passed": all(row["passed"] for row in results),
        "cases": results,
    }
