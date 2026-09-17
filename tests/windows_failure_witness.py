"""Test-only finite witnesses; no security writes, retries or product hooks."""

from __future__ import annotations

import ctypes
import json
import struct
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import native_policy_snapshot as api

_STAGES = ("before_key_verification", "after_key_verification", "after_manager", "after_discovery_binding")
_LABELS = ("key", "nested", "grandchild")
_DESCRIPTOR_LIMIT = 65_536
_ACE_LIMIT = 32
_EVENTS = frozenset(
    {
        "ready",
        "shutdown_requested",
        "serve_failed",
        "stopped",
        "recovery_requested",
        "death_observed",
        "locator_publish_failed",
        "retirement_requested",
    }
)
_REASONS = frozenset(
    {
        "explicit_stop",
        "unexpected_exception",
        "serve_loop_returned",
        "requested_shutdown",
        "serve_loop_failed",
        "process_missing",
        "recovery",
        "managed_retirement",
        "transport-failure",
        "authenticated-control-plane-failure",
        "overload",
    }
)


def _emit(report: dict[str, object]) -> None:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > 32_768:
        raise ValueError("windows_witness_size")
    print(encoded, file=sys.stderr, flush=True)


def _bounded_integer(value: object, maximum: int) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def _closed(value: object, vocabulary: frozenset[str]) -> str | None:
    if value is None:
        return None
    return value if type(value) is str and value in vocabulary else "other"


def retry_status_projection(status: object) -> dict[str, object]:
    """Inspect only the original status object, never paths, processes or tokens."""
    value = status if type(status) is dict else {}
    lifecycle = value.get("last_lifecycle_event")
    event = lifecycle if type(lifecycle) is dict else {}
    pid = _bounded_integer(value.get("pid"), 0xFFFFFFFF)
    event_pid = _bounded_integer(event.get("pid"), 0xFFFFFFFF)
    version, cli_version = value.get("daemon_version"), value.get("cli_version")
    return {
        "schema": "hol-guard.windows-bootstrap-status-witness.v1",
        "running": value.get("running") if type(value.get("running")) is bool else None,
        "pid_present": "pid" in value,
        "pid_valid": pid is not None and pid > 0,
        "port_present": "port" in value,
        "port_valid": (_bounded_integer(value.get("port"), 65_535) or 0) > 0,
        "listener_present": "url" in value,
        "daemon_version_present": type(version) is str and 0 < len(version) <= 64,
        "daemon_version_matches_cli": (
            version == cli_version
            if type(version) is type(cli_version) is str and 0 < len(version) <= 64 and 0 < len(cli_version) <= 64
            else None
        ),
        "lifecycle_present": type(lifecycle) is dict,
        "lifecycle_event": _closed(event.get("event"), _EVENTS),
        "lifecycle_reason": _closed(event.get("reason"), _REASONS),
        "lifecycle_pid_matches_status": (
            event_pid == pid if event_pid is not None and event_pid > 0 and pid is not None and pid > 0 else None
        ),
        "cause_proven": False,
    }


@contextmanager
def retry_status_witness(status: object) -> Iterator[None]:
    """Keep the original assertion and exception; emit only if it fails."""
    try:
        yield
    except BaseException:
        with suppress(BaseException):
            _emit(retry_status_projection(status))
        raise


class _NtQueryError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status


def _nt_descriptor(path: Path, *, directory: bool) -> bytes:
    """One documented user-mode query, with the NTFS maximum caller buffer.

    https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject
    The existing open helper receives no repair or creation request. No descriptor
    is written and no failed query is retried or converted into an empty DACL.
    """
    kernel, handle, _information = api._windows_open_handle(path, directory=directory)
    try:
        return _nt_descriptor_for_handle(handle)
    finally:
        api._windows_close_handle(kernel, handle)


def _nt_descriptor_for_handle(handle: Any) -> bytes:
    """Share the same bounded read with the exact-byte preservation oracle."""
    from ctypes import wintypes

    query = api._windows_dll("ntdll").NtQuerySecurityObject
    query.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    query.restype = ctypes.c_int32
    buffer = ctypes.create_string_buffer(_DESCRIPTOR_LIMIT)
    needed = wintypes.ULONG()
    status = int(query(handle, 0x7, buffer, len(buffer), ctypes.byref(needed)))
    if status != 0:
        raise _NtQueryError(status)
    if not 20 <= needed.value <= _DESCRIPTOR_LIMIT:
        raise ValueError("windows_witness_descriptor_size")
    return bytes(buffer.raw[: needed.value])


def _descriptor_components(raw: bytes) -> tuple[bytes, bytes, bytes, int, int]:
    """Parse only bounded self-relative owner/group/DACL components, never SACL."""
    if not 20 <= len(raw) <= _DESCRIPTOR_LIMIT:
        raise ValueError("windows_witness_descriptor_size")
    revision, _reserved, control, owner, group, _sacl, dacl = struct.unpack_from("<BBHLLLL", raw)
    if revision != 1 or not control & 0x8000:
        raise ValueError("windows_witness_descriptor_format")

    def component(offset: int, *, sid: bool) -> bytes:
        if offset < 20 or offset + 8 > len(raw):
            raise ValueError("windows_witness_descriptor_offset")
        if sid:
            if raw[offset] != 1 or raw[offset + 1] > 15:
                raise ValueError("windows_witness_sid")
            size = 8 + 4 * raw[offset + 1]
        else:
            size = struct.unpack_from("<H", raw, offset + 2)[0]
        if size < 8 or offset + size > len(raw):
            raise ValueError("windows_witness_component_size")
        return raw[offset : offset + size]

    return component(owner, sid=True), component(group, sid=True), component(dacl, sid=False), control, revision


def _security_projection(components: Any) -> dict[str, object]:
    control = revision = count = flags = None
    if isinstance(components, tuple) and len(components) == 5:
        control = _bounded_integer(components[3], 0xFFFF)
        revision = _bounded_integer(components[4], 0xFFFFFFFF)
        acl = components[2]
        if type(acl) is bytes and 8 <= len(acl) <= _DESCRIPTOR_LIMIT:
            size, declared_count = struct.unpack_from("<HH", acl, 2)
            if size == len(acl) and declared_count <= _ACE_LIMIT:
                parsed, offset = [], 8
                for _ in range(declared_count):
                    if offset + 4 > len(acl):
                        break
                    _kind, flag, ace_size = struct.unpack_from("<BBH", acl, offset)
                    if ace_size < 4 or offset + ace_size > len(acl):
                        break
                    parsed.append(flag)
                    offset += ace_size
                if len(parsed) == declared_count:
                    count, flags = declared_count, parsed
    return {"control": control, "revision": revision, "ace_count": count, "ace_flags": flags}


def _read_nt(path: Path, *, directory: bool) -> tuple[bytes | None, Any, dict[str, object]]:
    raw = components = None
    result: dict[str, object] = {"status": "unavailable", "ntstatus": None, "descriptor_bytes": None}
    try:
        raw = _nt_descriptor(path, directory=directory)
        result["descriptor_bytes"] = _bounded_integer(len(raw), _DESCRIPTOR_LIMIT)
        result["ntstatus"] = 0
        components = _descriptor_components(raw)
        result["status"] = "observed"
    except _NtQueryError as error:
        result.update(status="query_failed", ntstatus=error.status if -(2**31) <= error.status < 2**31 else None)
    except ValueError:
        result["status"] = "invalid_descriptor"
    except BaseException:
        pass
    result.update(_security_projection(components))
    return raw, components, result


class WindowsParentWitness:
    """At most four stages of three fixed children; private bytes stay local."""

    def __init__(self, objects: list[tuple[Path, bool]], before: list[Any], reader: Callable[..., Any]) -> None:
        self.objects, self.before, self.reader = objects[:3], before[:3], reader
        self.rows: list[dict[str, object]] = []
        self.raw_before: list[bytes | None] = [None] * 3
        self.stages = 0
        self.incomplete = len(objects) != 3 or len(before) != 3

    def capture(self, stage: str) -> None:
        if self.stages >= len(_STAGES) or stage != _STAGES[self.stages]:
            self.incomplete = True
            return
        self.stages += 1
        for index, (path, directory) in enumerate(self.objects):
            try:
                self._capture_child(index, path, directory, stage)
            except BaseException:
                self.incomplete = True
                self.rows.append({"stage": stage, "child": _LABELS[index], "capture": "unavailable"})

    def _capture_child(self, index: int, path: Path, directory: bool, stage: str) -> None:
        raw_before, components_before, nt_before = _read_nt(path, directory=directory)
        current = None
        with suppress(BaseException):
            current = self.reader(path, directory=directory)
        raw_after, components_after, nt_after = _read_nt(path, directory=directory)
        if stage == _STAGES[0]:
            self.raw_before[index] = raw_before
        baseline = self.raw_before[index]
        original = self.before[index]
        get = _security_projection(current[1] if current is not None else None)
        get.update(
            observed=current is not None,
            identity_equal_before=current[0] == original[0] if current is not None else None,
            security_equal_before=current[1] == original[1] if current is not None else None,
            owner_equal_before=current[1][0] == original[1][0] if current is not None else None,
            group_equal_before=current[1][1] == original[1][1] if current is not None else None,
            dacl_equal_before=current[1][2] == original[1][2] if current is not None else None,
            bytes_equal_before=current[2] == original[2] if current is not None and not directory else None,
        )
        self.incomplete |= current is None or components_before is None or components_after is None
        self.incomplete |= any(value["ace_flags"] is None for value in (get, nt_before, nt_after))
        self.rows.append(
            {
                "stage": stage,
                "child": _LABELS[index],
                "get_security_info": get,
                "nt_before_get": nt_before,
                "nt_after_get": nt_after,
                "descriptor_equal_around_get": raw_before == raw_after
                if raw_before is not None and raw_after is not None
                else None,
                "descriptor_equal_before": raw_before == baseline
                if raw_before is not None and baseline is not None
                else None,
                "nt_before_matches_get": components_before == current[1]
                if components_before is not None and current is not None
                else None,
                "nt_after_matches_get": components_after == current[1]
                if components_after is not None and current is not None
                else None,
            }
        )

    def report(self) -> dict[str, object]:
        return {
            "schema": "hol-guard.windows-parent-security-witness.v1",
            "stages_observed": self.stages,
            "complete": self.stages == len(_STAGES) and not self.incomplete,
            "rows": self.rows,
            "cause_proven": False,
            "security_writes_added": False,
        }

    @contextmanager
    def failure_only(self) -> Iterator[None]:
        try:
            yield
        except BaseException:
            with suppress(BaseException):
                _emit(self.report())
            raise
