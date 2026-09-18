"""Observe the original Windows open rejection in private CI startup only."""

from __future__ import annotations

import ctypes
import hashlib
import re
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager, suppress
from pathlib import Path
from types import TracebackType
from typing import cast
from unittest.mock import patch

from scripts import native_slo_failure
from scripts.native_slo_contract import assert_privacy_safe

_OWNERSHIP = threading.Lock()


def _shipped_traceback(error: BaseException) -> list[dict[str, object]]:
    """Retain at most eight shipped code locations, without any frame values."""
    result: list[dict[str, object]] = []
    traceback = error.__traceback__
    examined = 0
    while traceback is not None and examined < 128:
        frame = traceback.tb_frame
        module = frame.f_globals.get("__name__", "")
        if isinstance(module, str) and module.startswith(("scripts.", "codex_plugin_scanner.")):
            origin = Path(frame.f_code.co_filename).stem + "." + frame.f_code.co_name
            origin = origin.replace("secret", "sensitive").replace("token", "credential")
            if re.fullmatch(r"[A-Za-z0-9_.]{1,96}", origin):
                result.append({"origin": origin, "line": traceback.tb_lineno})
                result = result[-8:]
        traceback = traceback.tb_next
        examined += 1
    return result


class WindowsOpenFailureObserver:
    """Capture a thread-local code before the original helper discards it.

    Only the exact exception leaving the owned scope can be exported, once.
    Its identity, message, cause, and propagation are unchanged. One exception
    reference is retained until that export, then released; no frame data is
    serialized. The process-wide seam is restored before measured hook work.
    """

    def __init__(self) -> None:
        self._owner = threading.get_ident()
        self._patch: AbstractContextManager[object] | None = None
        self._owned = False
        self._error: BaseException | None = None
        self._code: int | None = None
        self._detail: dict[str, object] | None = None
        self.identity: dict[str, object] = {
            "schema": "hol-guard.windows-open-failure-observer.v1",
            "installed": False,
        }

    def __enter__(self) -> WindowsOpenFailureObserver:
        from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
        from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

        get_last_error = getattr(ctypes, "get_last_error", None)
        original = getattr(windows_io, "_windows_raise_open_error", None)
        if not callable(get_last_error) or not callable(original) or not _OWNERSHIP.acquire(blocking=False):
            return self
        self._owned = True
        try:
            self.identity["observer_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            self.identity["exporter_sha256"] = hashlib.sha256(
                Path(native_slo_failure.__file__).read_bytes()
            ).hexdigest()
            self.identity["observed_module_sha256"] = hashlib.sha256(Path(windows_io.__file__).read_bytes()).hexdigest()
            read_error = cast(Callable[[], object], get_last_error)
            raise_error = cast(Callable[..., object], original)

            def observed(*args: object, **kwargs: object) -> object:
                # This is the first operation at the original helper seam.
                # Do not look up the thread-local code after cleanup or export.
                code = None
                # Optional diagnostics never replace the original call.
                with suppress(Exception):
                    code = read_error()
                owned_thread = threading.get_ident() == self._owner
                if owned_thread:
                    self._error = None
                    self._code = None
                try:
                    return raise_error(*args, **kwargs)
                except BaseException as error:
                    if owned_thread and type(error) is NativePolicySnapshotError:
                        self._error = error
                        if type(code) is int and 0 <= code <= 0xFFFFFFFF:
                            self._code = code
                    raise

            installed_patch = patch.object(windows_io, "_windows_raise_open_error", observed)
            installed_patch.__enter__()
            self._patch = installed_patch
            self.identity["installed"] = True
        except Exception:
            self.close()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, traceback
        try:
            if exception is not None and exception is self._error and self._code is not None:
                self._detail = assert_privacy_safe(
                    {
                        "category": "NativePolicySnapshotError",
                        "winerror": self._code,
                        "capture_context": "original_windows_open_error_helper",
                        "stack": _shipped_traceback(exception),
                        "observer": dict(self.identity),
                    }
                )
            else:
                self._error = None
        except Exception:
            self._error = None
            self._detail = None
        finally:
            self.close()

    def close(self) -> None:
        try:
            if self._patch is not None:
                self._patch.__exit__(None, None, None)
                self._patch = None
        finally:
            if self._owned:
                self._owned = False
                _OWNERSHIP.release()
            if self._detail is None:
                self._error = None
                self._code = None

    def take_failure(self, error: BaseException) -> dict[str, object] | None:
        """Consume only evidence for the exact exception that escaped startup."""
        try:
            if threading.get_ident() == self._owner and error is self._error:
                return self._detail
            return None
        finally:
            self._error = None
            self._code = None
            self._detail = None

    def failure_evidence(self, error: Exception) -> dict[str, object]:
        detail = native_slo_failure.failure_evidence(error)
        observed = self.take_failure(error)
        if observed is not None:
            detail["windows_open_failure"] = observed
        return assert_privacy_safe(detail)
