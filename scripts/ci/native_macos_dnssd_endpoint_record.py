"""Admit a fixed read-only snapshot; never infer shared OFDs or daemon acceptance."""

from __future__ import annotations

import hashlib
import re
from typing import Any

CONTEXTS = {"standalone": 0, "native_dlopen": 1, "python": 2}
UUID = re.compile(r"[0-9a-f]{32}")
KEYS = {
    "kind", "sequence", "context", "configured", "loader_flags", "fd", "pid", "ppid",
    "uid", "euid", "gid", "egid", "main_thread", "thread_rc", "thread_id", "mask_rc",
    "blocked_signals", "pipe_rc", "pipe_errno", "pipe_kind", "images_ok", "images",
    "stat_before", "stat_after", "fd_flags", "status_flags", "socket_type", "local", "peer",
}


def integer(value: Any, minimum: int = -(2**31), maximum: int = 2**31 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def decimal(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None and int(value) < 2**64


def _status(row: Any, keys: set[str]) -> None:
    if not isinstance(row, dict) or set(row) != keys or not integer(row.get("rc")) or not integer(row.get("errno"), 0):
        raise ValueError("snapshot status")


def _stat(row: Any) -> None:
    _status(row, {"rc", "errno", "dev", "ino", "mode"})
    if row["rc"] not in (-1, 0) or not decimal(row["dev"]) or not decimal(row["ino"]) or not integer(row["mode"], 0, 2**32 - 1):
        raise ValueError("snapshot stat")


def _address(row: Any) -> dict[str, Any]:
    _status(row, {"rc", "errno", "length", "captured", "hex"})
    if (
        row["rc"] not in (-1, 0) or not integer(row["length"], 0, 2**32 - 1)
        or not integer(row["captured"], 0, 128) or not isinstance(row["hex"], str)
        or re.fullmatch(r"[0-9a-f]{0,256}", row["hex"]) is None or len(row["hex"]) != 2 * row["captured"]
        or (row["rc"] != 0 and row["captured"] != 0)
    ):
        raise ValueError("snapshot address")
    data = bytes.fromhex(row["hex"])
    complete = row["rc"] == 0 and row["errno"] == 0 and row["length"] == len(data) and len(data) >= 2
    family = data[1] if complete else None
    value = data[2:].rstrip(b"\0") if family == 1 else data
    return {
        "rc": row["rc"], "errno": row["errno"], "returned_length": row["length"],
        "captured_bytes": len(data), "complete": complete, "family": family,
        "sockaddr_length_byte": data[0] if complete else None,
        "raw_address_sha256": hashlib.sha256(data).hexdigest(),
        "endpoint_sha256": hashlib.sha256(value).hexdigest(),
        "unix_mdnsresponder_path": complete and family == 1 and value == b"/var/run/mDNSResponder",
    }


def normalize(
    row: Any, context: str, pid: int, flags: int, executable: dict[str, Any],
    observer: dict[str, Any], native: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) != KEYS or context not in CONTEXTS:
        raise ValueError("snapshot fields")
    if (
        row["kind"] != "endpoint_context" or row["sequence"] != 1 or type(row["sequence"]) is not int
        or row["context"] != CONTEXTS[context] or type(row["context"]) is not int
        or type(row["configured"]) is not bool or row["loader_flags"] != (0 if context == "standalone" else flags)
        or type(row["loader_flags"]) is not int or row["pid"] != pid or not integer(row["pid"], 1)
        or not integer(row["ppid"], 1) or not integer(row["fd"], -1)
        or any(not integer(row[key], 0, 2**32 - 1) for key in ("uid", "euid", "gid", "egid"))
        or type(row["main_thread"]) is not int or row["main_thread"] not in (0, 1)
        or not integer(row["thread_rc"]) or not decimal(row["thread_id"])
        or not integer(row["mask_rc"]) or not decimal(row["blocked_signals"])
        or row["pipe_rc"] not in (-1, 0) or type(row["pipe_rc"]) is not int
        or not integer(row["pipe_errno"], 0) or row["pipe_kind"] not in (-1, 0, 1, 2)
        or type(row["pipe_kind"]) is not int or type(row["images_ok"]) is not bool
    ):
        raise ValueError("snapshot binding")
    images = row["images"]
    if (
        not isinstance(images, dict) or set(images) != {"main", "observer", "query", "descriptor", "process", "poll"}
        or any(not isinstance(value, str) or (value != "" and UUID.fullmatch(value) is None) for value in images.values())
    ):
        raise ValueError("snapshot images")
    for name in ("stat_before", "stat_after"):
        _stat(row[name])
    for name in ("fd_flags", "status_flags"):
        _status(row[name], {"rc", "errno"})
        if row[name]["rc"] < -1:
            raise ValueError("snapshot flags")
    _status(row["socket_type"], {"rc", "errno", "length", "value"})
    if row["socket_type"]["rc"] not in (-1, 0) or not integer(row["socket_type"]["length"], 0, 2**32 - 1) or not integer(row["socket_type"]["value"], 0):
        raise ValueError("snapshot socket type")
    local, peer = _address(row["local"]), _address(row["peer"])
    image_binding = (
        row["images_ok"] and all(UUID.fullmatch(value) for value in images.values())
        and images["observer"] == observer.get("uuid") and images["query"] == native.get("dnssd_uuid")
        and (context == "python" or images["main"] == executable.get("uuid"))
    )
    if row["images_ok"] and not image_binding:
        raise ValueError("snapshot loaded image mismatch")
    complete = bool(
        row["configured"] and row["fd"] >= 0 and image_binding
        and row["thread_rc"] == 0 and row["mask_rc"] == 0 and row["pipe_rc"] == 0 and row["pipe_errno"] == 0
        and row["stat_before"] == row["stat_after"] and row["stat_before"]["rc"] == 0
        and row["stat_before"]["errno"] == 0 and row["stat_before"]["mode"] & 0o170000 == 0o140000
        and all(row[name]["rc"] >= 0 and row[name]["errno"] == 0 for name in ("fd_flags", "status_flags"))
        and row["socket_type"]["rc"] == 0 and row["socket_type"]["errno"] == 0
        and row["socket_type"]["length"] == 4 and local["complete"] and peer["complete"]
    )
    result = {key: value for key, value in row.items() if key not in ("local", "peer")}
    return result | {
        "local": local, "peer": peer, "observation_complete": complete,
        "atomic_fd_snapshot_claimed": False, "same_OFD_claimed": False, "daemon_acceptance_claimed": False,
        "mapped_executable_bytes_hashed": False, "internal_thread_census_claimed": False,
    }
