"""CI-only, owned-writer checkpoint exception observation with unchanged calls."""

from __future__ import annotations

import threading
from types import FunctionType, TracebackType
from typing import Any

_MAX_RECORDS = 16
_MAX_FRAMES = 8
_MAX_TRACE_DEPTH = 32
_MAX_INTEGER = 2**32 - 1
_BUILTIN_ERRORS = {
    OSError: "OSError",
    PermissionError: "PermissionError",
    FileNotFoundError: "FileNotFoundError",
    FileExistsError: "FileExistsError",
    IsADirectoryError: "IsADirectoryError",
    NotADirectoryError: "NotADirectoryError",
    InterruptedError: "InterruptedError",
    BlockingIOError: "BlockingIOError",
    BrokenPipeError: "BrokenPipeError",
    ConnectionError: "ConnectionError",
    ConnectionAbortedError: "ConnectionAbortedError",
    ConnectionRefusedError: "ConnectionRefusedError",
    ConnectionResetError: "ConnectionResetError",
    TimeoutError: "TimeoutError",
    ProcessLookupError: "ProcessLookupError",
    ChildProcessError: "ChildProcessError",
}
_JOURNAL_FUNCTIONS = (
    "checkpoint_journal",
    "_read_journal_records_locked",
    "_open_journal",
    "_write_all",
    "_rewrite_preview_sidecar",
    "_read_preview_sidecar",
    "_apply_private_file_mode",
)


def _number(value: object) -> int | None:
    if type(value) is int and 0 <= value <= _MAX_INTEGER:
        return value
    return None


class CheckpointObservation:
    """Wrap one exact probe and its installed writer; never modify a result."""

    def __init__(self, probe: Any, writer_module: Any, journal_module: Any) -> None:
        self._probe = probe
        self._writer_module = writer_module
        self._journal_module = journal_module
        self._original_bind = probe.bind_corpus
        self._original_checkpoint = writer_module.checkpoint_journal
        if self._original_checkpoint is not journal_module.checkpoint_journal:
            raise RuntimeError("checkpoint_original_alias_mismatch")
        if type(self._original_bind) is not FunctionType:
            raise RuntimeError("probe_binding_not_original_function")
        self._writer_type = writer_module.RuntimeHookEvidenceWriter
        self._control_thread = threading.current_thread()
        self._writer = None
        self._thread = None
        self._path = None
        self._active = False
        self._ever_bound = False
        self._restored = False
        self._invalid = False
        self._observation_lost = False
        self._checkpoint_calls = 0
        self._checkpoint_successes = 0
        self._checkpoint_failures = 0
        self._records: list[dict[str, object]] = []
        self._code_labels = []
        for name in _JOURNAL_FUNCTIONS:
            function = getattr(journal_module, name)
            if type(function) is not FunctionType:
                raise RuntimeError("journal_function_identity_unavailable")
            self._code_labels.append((function.__code__, name))
        lock = journal_module._journal_lock
        if type(lock) is not FunctionType or type(lock.__wrapped__) is not FunctionType:
            raise RuntimeError("journal_lock_identity_unavailable")
        self._code_labels.append((lock.__wrapped__.__code__, "_journal_lock"))

        def bind(daemon: object) -> object:
            result = self._original_bind(daemon)
            try:
                self._bind(daemon)
            except BaseException:
                self._invalid = True
            return result

        def checkpoint(*args: object, **kwargs: object) -> object:
            owned = False
            try:
                owned = self._owns(args)
                if owned:
                    self._increment("_checkpoint_calls")
            except BaseException:
                self._invalid = True
            try:
                result = self._original_checkpoint(*args, **kwargs)
            except BaseException as error:
                if owned:
                    try:
                        self._increment("_checkpoint_failures")
                        self._record(error)
                    except BaseException:
                        self._observation_lost = True
                raise
            if owned:
                try:
                    self._increment("_checkpoint_successes")
                except BaseException:
                    self._observation_lost = True
            return result

        self._bind_wrapper = bind
        self._checkpoint_wrapper = checkpoint

    def __enter__(self) -> CheckpointObservation:
        if self._active or self._restored or threading.current_thread() is not self._control_thread:
            raise RuntimeError("checkpoint_observer_generation_invalid")
        if (
            self._probe.bind_corpus is not self._original_bind
            or self._writer_module.checkpoint_journal is not self._original_checkpoint
        ):
            raise RuntimeError("checkpoint_observer_seam_changed")
        self._active = True
        try:
            self._writer_module.checkpoint_journal = self._checkpoint_wrapper
            self._probe.bind_corpus = self._bind_wrapper
        except BaseException:
            self._restore()
            raise
        return self

    def _bind(self, daemon: Any) -> None:
        if not self._active or threading.current_thread() is not self._control_thread or self._ever_bound:
            self._invalid = True
            return
        writer = daemon._server.runtime_hook_evidence_writer
        if type(writer) is not self._writer_type:
            self._invalid = True
            return
        thread = writer._thread
        if type(thread) is not threading.Thread or not thread.is_alive():
            self._invalid = True
            return
        self._writer = writer
        self._thread = thread
        self._path = writer._journal_path
        self._ever_bound = True

    def _owns(self, args: tuple[object, ...]) -> bool:
        if not self._active or self._invalid or self._writer is None:
            return False
        if (
            self._writer_module.checkpoint_journal is not self._checkpoint_wrapper
            or self._probe.bind_corpus is not self._bind_wrapper
            or self._writer._thread is not self._thread
            or self._writer._journal_path is not self._path
        ):
            self._invalid = True
            return False
        return threading.current_thread() is self._thread and len(args) == 1 and args[0] is self._path

    def _increment(self, name: str) -> None:
        value = getattr(self, name)
        if value < 65535:
            setattr(self, name, value + 1)
        else:
            self._observation_lost = True

    def _record(self, error: BaseException) -> None:
        if len(self._records) == _MAX_RECORDS:
            self._observation_lost = True
            return
        error_type = type(error)
        category = next(
            (name for candidate, name in _BUILTIN_ERRORS.items() if error_type is candidate),
            None,
        )
        if category is None:
            self._records.append({"category": "unclassified", "metadata_available": False})
            return
        frames: list[dict[str, object]] = []
        trace = error.__traceback__
        traversed = 0
        while trace is not None and traversed < _MAX_TRACE_DEPTH:
            if type(trace) is not TracebackType:
                self._observation_lost = True
                break
            label = next((name for code, name in self._code_labels if code is trace.tb_frame.f_code), None)
            if label is not None:
                if len(frames) == _MAX_FRAMES:
                    self._observation_lost = True
                    break
                frames.append({"function": label, "line": _number(trace.tb_lineno)})
            trace = trace.tb_next
            traversed += 1
        if trace is not None:
            self._observation_lost = True
        self._records.append(
            {
                "category": category,
                "metadata_available": True,
                "errno": _number(error.errno),
                "winerror": _number(getattr(error, "winerror", None)),
                "shipped_frames": frames,
                "surviving_exception_only": True,
                "implicit_context_inspected": False,
            }
        )

    def _restore(self) -> None:
        self._active = False
        if self._probe.bind_corpus is self._bind_wrapper:
            self._probe.bind_corpus = self._original_bind
        elif self._probe.bind_corpus is not self._original_bind:
            self._invalid = True
        if self._writer_module.checkpoint_journal is self._checkpoint_wrapper:
            self._writer_module.checkpoint_journal = self._original_checkpoint
        elif self._writer_module.checkpoint_journal is not self._original_checkpoint:
            self._invalid = True
        self._restored = (
            self._probe.bind_corpus is self._original_bind
            and self._writer_module.checkpoint_journal is self._original_checkpoint
        )

    def __exit__(self, kind: object, error: object, trace: object) -> None:
        del kind, error, trace
        self._restore()

    def report(self) -> dict[str, object]:
        thread = self._thread
        retired = thread is not None and not thread.is_alive()
        return {
            "schema": "hol-guard.windows-checkpoint-cause.v1",
            "scope": "one_owned_installed_default_auto_writer",
            "lifetime": "bind_corpus_until_original_probe_returns_including_cleanup",
            "original_counter_snapshot_atomic_with_observer": False,
            "original_checkpoint_calls": self._checkpoint_calls,
            "original_checkpoint_successes": self._checkpoint_successes,
            "original_checkpoint_failures": self._checkpoint_failures,
            "records": list(self._records),
            "maximum_retained_records": _MAX_RECORDS,
            "observer_bound": self._ever_bound,
            "observer_invalid": self._invalid,
            "additional_observation_lost": self._observation_lost,
            "exact_seams_restored": self._restored,
            "owned_writer_thread_retired": retired,
            "exception_observed": bool(self._records),
            "missing_is_zero": False,
            "historical_failure_cause_identified": False,
            "performance_qualification": False,
        }
