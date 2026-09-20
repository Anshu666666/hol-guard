"""Private fixture redirection and post-cleanup evidence, with original I/O."""

from __future__ import annotations

import functools
import re
import sys
from pathlib import Path
from typing import Any

from .capture import MAX_REPORT_BYTES, Collector, Patches, error_kind, json_bytes
from .daemon import AttachAfterEnter, DaemonCapture

_STOP_FIELDS = {
    "acknowledged",
    "authenticated",
    "generation_present",
    "owner_lock",
    "marker_lock",
    "endpoint",
    "serving_shutdown",
}
_STOP_VALUES = {"true", "false", "free", "busy", "unverified", "absent", "present", "unknown", "verified"}


def stop_projection(value: object) -> dict[str, object]:
    if type(value) is not dict or not set(value) >= _STOP_FIELDS:
        raise ValueError("phase_stop_fields_missing")
    if set(value) - (_STOP_FIELDS | {"schema", "operation", "status", "error", "client_cleanup"}):
        raise ValueError("phase_stop_fields_unknown")
    if (
        value.get("schema") != "hol-guard.native-resident-stop-diagnostic.v1"
        or value.get("operation") != "resident-stop"
    ):
        raise ValueError("phase_stop_schema_invalid")
    if value.get("status") not in {"contained", "already-stopped", "failed", "contained_client_cleanup_failed"}:
        raise ValueError("phase_stop_status_invalid")
    if any(type(value[field]) is not str or value[field] not in _STOP_VALUES for field in _STOP_FIELDS):
        raise ValueError("phase_stop_value_invalid")
    if "error" in value and (
        type(value["error"]) is not str
        or re.fullmatch(r"native_resident_stop_[a-z0-9_]{1,100}", value["error"]) is None
    ):
        raise ValueError("phase_stop_error_invalid")
    if "client_cleanup" in value and value["client_cleanup"] != "failed":
        raise ValueError("phase_stop_client_cleanup_invalid")
    return dict(value)


class FixtureRedirect:
    def __init__(
        self,
        collector: Collector,
        fixture_module: Any,
        *,
        runtime: Path,
        source_root: Path,
        child_script: Path,
        report_path: Path,
    ) -> None:
        self.collector = collector
        self.module = fixture_module
        self.runtime = runtime
        self.source_root = source_root
        self.child_script = child_script
        self.report_path = report_path
        self.patches = Patches(collector)
        self.redirected = 0

    def __enter__(self) -> FixtureRedirect:
        original = self.module._spawn_hook_process
        expected = (
            sys.executable,
            "-u",
            str(Path(self.module.__file__).resolve()),
            "--serve",
            str(self.runtime),
            "none",
            "normal",
        )

        @functools.wraps(original)
        def spawn(argv: Any, *args: Any, **kwargs: Any) -> Any:
            if type(argv) is tuple and argv == expected:
                self.redirected += 1
                if self.redirected == 1:
                    argv = (
                        argv[0],
                        argv[1],
                        str(self.child_script),
                        "--phase-source-root",
                        str(self.source_root),
                        "--phase-report",
                        str(self.report_path),
                        *argv[3:],
                    )
                else:
                    self.collector.fault()
            return original(argv, *args, **kwargs)

        try:
            self.patches.set(self.module, "_spawn_hook_process", spawn)
        except BaseException:
            self.patches.close()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        self.patches.close()


def serve_with_capture(
    original: Any,
    collector: Collector,
    attach: AttachAfterEnter,
    session_class: Any,
    report_path: Path,
    *args: Any,
    **kwargs: Any,
) -> Any:
    patches = Patches(collector)
    stops: list[dict[str, object]] = []
    original_stop = session_class.stop_resident

    @functools.wraps(original_stop)
    def stop(instance: Any, *stop_args: Any, **stop_kwargs: Any) -> Any:
        result: Any = None
        failure: BaseException | None = None
        try:
            result = original_stop(instance, *stop_args, **stop_kwargs)
            return result
        except BaseException as error:
            failure = error
            raise
        finally:

            def retain() -> None:
                if len(stops) >= 4:
                    raise ValueError("phase_stop_count_bound")
                stops.append(
                    {
                        "returned_bool": type(result) is bool,
                        "contained_return": result if type(result) is bool else None,
                        "exception_kind": error_kind(failure),
                        "diagnostic": stop_projection(instance.last_stop_diagnostic),
                    }
                )

            collector.guard(retain)

    def install() -> None:
        try:
            patches.set(session_class, "stop_resident", stop)
            attach.__enter__()
        except BaseException:
            attach.__exit__()
            patches.close()
            raise

    collector.guard(install)
    result: Any = None
    failure: BaseException | None = None
    try:
        result = original(*args, **kwargs)
        return result
    except BaseException as error:
        failure = error
        raise
    finally:
        collector.guard(lambda: attach.__exit__())
        patches.close()

        def export() -> None:
            report = collector.snapshot(original_success=failure is None and result == 0)
            report["serve_returncode"] = result if type(result) is int else None
            report["serve_error_kind"] = error_kind(failure)
            report["session_attachments"] = attach.enter_count
            report["stop_observations"] = stops
            try:
                report["final_stop"] = (
                    stop_projection(attach.session.last_stop_diagnostic) if attach.session is not None else None
                )
            except BaseException as stop_error:
                report["final_stop"] = None
                report["final_stop_error_kind"] = error_kind(stop_error)
                report["observation_complete"] = False
                report["capture_faults"] = int(report["capture_faults"]) + 1
            encoded = json_bytes(report) + b"\n"
            if len(encoded) > MAX_REPORT_BYTES:
                raise ValueError("phase_report_bound")
            with report_path.open("xb") as stream:
                stream.write(encoded)

        collector.guard(export)


def child_main(arguments: list[str]) -> int:
    # Driver-only flags are removed before the original parser sees its exact argv.
    if len(arguments) != 8 or arguments[0] != "--phase-source-root" or arguments[2] != "--phase-report":
        raise ValueError("phase_child_invocation_invalid")
    source_root = Path(arguments[1]).resolve(strict=True)
    report_path = Path(arguments[3]).resolve()
    original_arguments = arguments[4:]
    if original_arguments[0] != "--serve" or original_arguments[2:] != ["none", "normal"]:
        raise ValueError("phase_child_scope_invalid")
    if report_path.exists() or not report_path.parent.is_dir():
        raise ValueError("phase_child_output_not_owned")
    sys.path.insert(0, str(source_root))
    from codex_plugin_scanner.guard import native_hook_edge, native_resident_client
    from codex_plugin_scanner.guard.daemon import server
    from scripts import native_slo_daemon_entrypoint, native_slo_daemon_fixture
    from scripts.native_slo_session import AdapterSession

    collector = Collector("daemon")
    attach = AttachAfterEnter(
        collector,
        AdapterSession,
        lambda owned: DaemonCapture(collector, owned, server, native_hook_edge, native_resident_client),
    )
    original_argv = sys.argv
    sys.argv = [str(Path(native_slo_daemon_fixture.__file__).resolve()), *original_arguments]
    try:
        return native_slo_daemon_entrypoint.main(
            lambda *args, **kwargs: serve_with_capture(
                native_slo_daemon_fixture._serve,
                collector,
                attach,
                AdapterSession,
                report_path,
                *args,
                **kwargs,
            ),
            native_slo_daemon_fixture._emit,
        )
    finally:
        sys.argv = original_argv
