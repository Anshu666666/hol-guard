"""Finite installed Windows config/authority sharing controls, without timing."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

# The driver imports its own helpers, while production resolves from the wheel.
_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))

from scripts.ci.windows_config_lease_evidence import (  # noqa: E402
    digest,
    exception_record,
    require,
    source_binding,
    write_report,
)

PAYLOAD = b'default_action = "block"\n'
CASES = (
    ("unheld_before", False),
    ("authority_exclusive", True),
    ("unheld_after_exclusive", False),
    ("authority_shared", True),
    ("unheld_after_shared", False),
    ("add_file_barrier", True),
    ("unheld_after_add_file", False),
    ("least_access_barrier", False),
    ("unheld_after_least_access", False),
    ("sibling_barrier", False),
    ("unheld_after_sibling", False),
)


def _sharing_rejection(error: BaseException, *, config: bool) -> bool:
    from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError

    cause = error.__cause__ if config and type(error) is GuardConfigSourceError else error
    if not isinstance(cause, OSError) or cause.errno != 32:
        return False
    traceback = cause.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        # The whole installed module is bound to SOURCE_COMMIT before running.
        # Line 218 is the failed CreateFile return; 222 is failed inspection.
        if (
            frame.f_globals.get("__name__") == "codex_plugin_scanner.safe_output_windows"
            and frame.f_code.co_name == "_open_locked_directory"
            and traceback.tb_lineno == 218
        ):
            return True
        traceback = traceback.tb_next
    return False


def capture_case(home: Path, expected_identity: tuple[int, ...], *, conflict: bool) -> dict[str, object]:
    from codex_plugin_scanner.guard.config_source_io import capture_guard_config
    from codex_plugin_scanner.safe_output_windows import _open_locked_directory, _WindowsApi

    record: dict[str, object] = {"expected_conflict": conflict}
    try:
        captured = capture_guard_config(home / "config.toml")
        record["capture"] = {
            "succeeded": True,
            "content_unchanged": captured.content == PAYLOAD,
            "identity_unchanged": captured.identity == expected_identity,
        }
        capture_matches = not conflict and captured.content == PAYLOAD and captured.identity == expected_identity
    except Exception as error:
        record["capture"] = {"succeeded": False, "error": exception_record(error)}
        capture_matches = conflict and _sharing_rejection(error, config=True)
    # A separate open of the known Guard-home object distinguishes that exact
    # directory's conflict from an unknown ancestor in capture's full chain.
    api = _WindowsApi()
    try:
        handle = _open_locked_directory(api, home)
    except Exception as error:
        record["guard_home_open"] = {"succeeded": False, "error": exception_record(error)}
        open_matches = conflict and _sharing_rejection(error, config=False)
    else:
        api.close_handle(handle)
        record["guard_home_open"] = {"succeeded": True}
        open_matches = not conflict
    record["matches_prediction"] = capture_matches and open_matches
    return record


@contextmanager
def directory_barrier(home: Path, *, add_file: bool, detail: dict[str, Any]) -> Iterator[None]:
    from codex_plugin_scanner.guard import native_policy_snapshot as api
    from codex_plugin_scanner.guard.native_policy_snapshot_windows_atomic import _windows_parent_identity
    from codex_plugin_scanner.guard.native_policy_snapshot_windows_io import _windows_open_configuration

    kernel, handle, _ = api._windows_open_handle(home, directory=True, lock=True, add_file=add_file)
    try:
        owner = api._windows_owner_sid()
        api._windows_verify_private_owner(handle, owner_sid=owner)
        api._windows_verify_private_dacl(handle, owner_sid=owner, directory=True)
        identity = _windows_parent_identity(api, kernel, handle)
        configuration = _windows_open_configuration(
            api,
            directory=True,
            create_new=False,
            descriptor=None,
            repair=False,
            lock=True,
            rename_source=False,
            add_file=add_file,
            share_delete=False,
            rename_parent=False,
        )
        detail.update(
            desired_access=configuration.desired_access,
            sharing=configuration.share_mode,
            flags=configuration.flags,
            owner_and_private_dacl_verified=True,
        )
        yield
        detail["handle_identity_unchanged"] = _windows_parent_identity(api, kernel, handle) == identity
        require(detail["handle_identity_unchanged"], "barrier_identity_changed")
        api._windows_verify_private_owner(handle, owner_sid=owner)
        api._windows_verify_private_dacl(handle, owner_sid=owner, directory=True)
        detail["owner_and_private_dacl_still_verified"] = True
    finally:
        api._windows_close_handle(kernel, handle)
        detail["closed"] = True


def run_controls(report: dict[str, Any]) -> None:
    require(os.name == "nt", "actual_windows_required")
    report["control_attempts"] = 1

    from codex_plugin_scanner.guard import native_policy_snapshot as api
    from codex_plugin_scanner.guard.config_source_io import capture_guard_config
    from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock

    temporary = tempfile.TemporaryDirectory(prefix="guard-config-lease-")
    report["cases"] = cases = []
    try:
        home = Path(temporary.name) / "home"
        api._windows_ensure_private_directory(home)
        api._windows_ensure_private_directory(home / "sibling")
        config = home / "config.toml"
        config.write_bytes(PAYLOAD)
        home.rename(home.with_name("moved"))
        home.with_name("moved").rename(home)
        report["unheld_directory_rename_succeeded"] = True
        original = capture_guard_config(config)
        require(original.content == PAYLOAD and original.identity is not None, "initial_capture_invalid")
        assert original.identity is not None
        home_identity = (home.stat().st_dev, home.stat().st_ino)
        for name, conflict in CASES:
            row: dict[str, Any] = {"case": name}
            cases.append(row)
            lease: Any = nullcontext()
            if name.startswith("authority_"):
                lease = hold_command_control_authority_lock(
                    home, timeout_seconds=0.0, shared=name == "authority_shared"
                )
            elif name in {"add_file_barrier", "least_access_barrier"}:
                lease = directory_barrier(home, add_file=name == "add_file_barrier", detail=row)
            elif name == "sibling_barrier":
                lease = api._windows_private_directory_binding(home / "sibling")
            with lease:
                row.update(capture_case(home, original.identity, conflict=conflict))
                if name == "least_access_barrier":
                    try:
                        home.rename(home.with_name("moved"))
                    except OSError as error:
                        row["rename_blocked"] = True
                        row["rename_error"] = exception_record(error)
                    else:
                        row["rename_blocked"] = False
                        require(False, "least_access_lost_directory_barrier")
            if name == "least_access_barrier":
                home.rename(home.with_name("moved"))
                home.with_name("moved").rename(home)
                row["rename_after_release_succeeded"] = True
            require((home.stat().st_dev, home.stat().st_ino) == home_identity, "guard_home_identity_changed")
            require(config.read_bytes() == PAYLOAD, "config_bytes_changed")
        report["control_predictions_matched"] = all(row["matches_prediction"] for row in cases)
        report["config_sha256"] = digest(PAYLOAD)
        report["guard_home_identity_unchanged"] = True
    except Exception as error:
        report["control_failure"] = exception_record(error)
        raise
    finally:
        try:
            temporary.cleanup()
            report["cleanup_confirmed"] = True
        except Exception as error:
            report["cleanup_failure"] = exception_record(error)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver-commit", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report: dict[str, Any] = {
        "schema": "hol-guard.windows-config-lease-diagnostic.v1",
        "qualification": False,
        "headline_timing_eligible": False,
        "historical_failure_cause_established": False,
        "current_default_auto_failure_cause_established": False,
        "runtime_source_changed": False,
        "control_attempts": 0,
        "cleanup_confirmed": False,
        "passed": False,
    }
    try:
        report["before"] = source_binding(arguments.source, _ROOT, arguments.driver_commit, arguments.wheel)
        run_controls(report)
    except Exception as error:
        report["failure"] = exception_record(error)
    finally:
        try:
            report["after"] = source_binding(arguments.source, _ROOT, arguments.driver_commit, arguments.wheel)
            report["bindings_unchanged"] = report.get("before") == report["after"]
        except Exception as error:
            report["binding_failure"] = exception_record(error)
    report["passed"] = bool(
        report.get("control_predictions_matched")
        and report.get("bindings_unchanged")
        and report["cleanup_confirmed"]
        and "failure" not in report
    )
    write_report(arguments.output, report)
    print(f"windows_config_lease_control_passed={str(report['passed']).lower()}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
