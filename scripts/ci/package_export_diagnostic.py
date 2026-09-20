"""One declared installed priority-launcher block, with unchanged producer timers."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import threading
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, cast

BASELINE = "017f1244f1861bc4a74620a669557b78beb6d176"
PLAN_SHA256 = "2fe1e299ec30f0b49e0efd0eadd9f24e746f5a1c34dcbd7b920d02e9d2384c86"
PLAN = {"priority_per_run": 2, "cold_per_run": 2}
ROUTES = (
    ("claude-code", "PreToolUse"),
    ("claude-code", "PostToolUse"),
    ("codex", "PreToolUse"),
    ("codex", "PostToolUse"),
)
PRODUCERS = (
    "scripts/native_slo_priority_launchers.py",
    "scripts/native_slo_daemon_fixture.py",
    "scripts/native_slo_daemon_entrypoint.py",
    "scripts/native_slo_session.py",
    "scripts/native_slo_adapter.py",
    "scripts/native_slo_batch.py",
    "scripts/native_slo_contract.py",
    "scripts/native_probe_receipts.py",
)
PACKAGE_FILES = (
    "codex_plugin_scanner/__init__.py",
    "codex_plugin_scanner/scanner.py",
    "codex_plugin_scanner/guard/adapters/claude_daemon_hook_bridge.py",
    "codex_plugin_scanner/guard/adapters/codex_daemon_hook_bridge.py",
    "codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
    "codex_plugin_scanner/guard/native_runtime.py",
)


class Producer(Protocol):
    observe_priority_launcher: Callable[..., Any]

    def measure_priority_launchers(
        self, session: Any, plan: Mapping[str, int]
    ) -> tuple[dict[str, object], dict[str, list[float]]]: ...


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError("package_export_diagnostic_" + code)


def digest(path: Path, limit: int = 64 * 1024 * 1024) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit, "file_bound")
    return hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(len(result.stdout) <= 1024 * 1024, "git_output_bound")
    return result.stdout.strip()


def source_binding(root: Path, sha: str, tree: str) -> dict[str, object]:
    actual_sha = git(root, "rev-parse", "HEAD")
    actual_tree = git(root, "rev-parse", "HEAD^{tree}")
    clean = not git(root, "status", "--porcelain", "--untracked-files=no")
    require(actual_sha == sha and actual_tree == tree and clean, "source_binding")
    producers: dict[str, str] = {}
    for relative in PRODUCERS:
        require(
            git(root, "rev-parse", f"HEAD:{relative}")
            == git(root, "rev-parse", f"{BASELINE}:{relative}"),
            "producer_changed",
        )
        producers[relative] = digest(root / relative, 1024 * 1024)
    return {
        "source_sha": actual_sha,
        "source_tree": actual_tree,
        "tracked_clean": clean,
        "producer_sha256": producers,
    }


def failure(error: BaseException) -> dict[str, object]:
    try:
        if isinstance(error, Exception):
            return importlib.import_module(
                "scripts.native_slo_failure"
            ).failure_evidence(error)
    except Exception:
        pass
    return {"category": type(error).__name__, "detail_unavailable": True}


class ObservationCapture:
    """Retain original completed observations after the producer's timer returns."""

    def __init__(self, producer: Producer) -> None:
        self.producer = producer
        self.original: Callable[..., Any] = producer.observe_priority_launcher
        self.rows: list[dict[str, object]] = []
        self.recording_faults = 0
        self.overflow = 0
        self.lock = threading.Lock()

    def record(
        self,
        launcher: Any,
        kwargs: Mapping[str, Any],
        result: Any,
        error: BaseException | None,
    ) -> None:
        row: dict[str, object] = {
            "harness": launcher.harness,
            "event": launcher.event,
            "sample": kwargs["sample"],
            "case": kwargs.get("case", "benign"),
            "registration_sha256": launcher.registration_sha256,
            "original_returned": error is None,
        }
        if error is None:
            row.update(
                latency_ms=result.latency_ms, allowed=result.allowed, route=result.route
            )
        else:
            row["failure"] = failure(error)
        with self.lock:
            if len(self.rows) < 88:
                self.rows.append(row)
            else:
                self.overflow += 1

    def observe(self, session: Any, launcher: Any, **kwargs: Any) -> Any:
        result = None
        original_error = None
        try:
            result = self.original(session, launcher, **kwargs)
            return result
        except BaseException as error:
            original_error = error
            raise
        finally:
            try:
                self.record(launcher, kwargs, result, original_error)
            except BaseException:
                with self.lock:
                    self.recording_faults += 1

    def __enter__(self) -> ObservationCapture:
        self.producer.observe_priority_launcher = self.observe
        return self

    def __exit__(self, *_args: object) -> None:
        self.producer.observe_priority_launcher = self.original

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {
                "rows": list(self.rows),
                "recording_faults": self.recording_faults,
                "overflow": self.overflow,
            }


def execute_block(fixture: Any, producer: Producer) -> dict[str, object]:
    report: dict[str, object] = {
        "producer_completed": False,
        "qualification_eligible": False,
    }
    with ObservationCapture(producer) as capture:
        try:
            session = fixture.__enter__()
            report["fixture"] = {
                "startup_ms": session.startup_ms,
                "readiness_ms": session.readiness_ms,
            }
            measured, raw = producer.measure_priority_launchers(session, dict(PLAN))
            report.update(
                measurements=measured, raw_samples_ms=raw, producer_completed=True
            )
        except BaseException as error:
            report["original_failure"] = failure(error)
        finally:
            try:
                fixture.close()
                report["fixture_cleanup_returned"] = True
            except BaseException as error:
                report["fixture_cleanup_returned"] = False
                report["cleanup_failure"] = failure(error)
            process = getattr(fixture, "process", None)
            report["direct_fixture_child_reaped"] = (
                process is not None and process.poll() is not None
            )
            report["fixture_reader_threads_stopped"] = all(
                not item.is_alive() for item in getattr(fixture, "_readers", ())
            )
            captured = capture.snapshot()
            report["observations"] = captured
    captured_rows = cast(list[dict[str, object]], captured["rows"])
    report["completed_original_calls"] = sum(
        row["original_returned"] is True for row in captured_rows
    )
    report["observation_complete"] = (
        report["producer_completed"] is True
        and len(captured_rows) == 88
        and captured["recording_faults"] == 0
        and captured["overflow"] == 0
    )
    return report


def installed_binding(wheel: Path, sha: str) -> tuple[dict[str, object], Path]:
    import codex_plugin_scanner
    from codex_plugin_scanner.guard import native_runtime

    distribution = importlib.metadata.distribution("hol-guard")
    package_root = Path(str(distribution.locate_file(""))).resolve()
    expected_module = package_root / "codex_plugin_scanner/__init__.py"
    require(
        Path(codex_plugin_scanner.__file__).resolve() == expected_module,
        "installed_import",
    )
    require("site-packages" in expected_module.parts, "installed_location")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    require(not direct.get("dir_info", {}).get("editable", False), "editable_install")
    record = distribution.read_text("RECORD")
    require(
        isinstance(record, str) and 0 < len(record) <= 4 * 1024 * 1024, "record_bound"
    )
    status = native_runtime.native_runtime_status()
    require(status.mode == "auto" and status.compatible, "native_default_auto")
    require(
        status.identity is not None and status.capabilities is not None,
        "native_identity",
    )
    assert (
        status.identity is not None
        and status.capabilities is not None
        and record is not None
    )
    runtime = status.identity.path
    require(status.capabilities.build_sha == sha, "native_build_sha")
    require(
        not any("diagnostic" in item for item in status.capabilities.features),
        "native_diagnostic_feature",
    )
    require(digest(runtime) == status.identity.sha256, "native_bytes")
    members = (
        *PACKAGE_FILES,
        runtime.relative_to(package_root).as_posix(),
        runtime.with_name("runtime-manifest.json").relative_to(package_root).as_posix(),
    )
    bound_files: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for relative in members:
            info = archive.getinfo(relative)
            require(info.file_size <= 64 * 1024 * 1024, "wheel_member_bound")
            wheel_hash = hashlib.sha256(archive.read(info)).hexdigest()
            require(
                wheel_hash == digest(package_root / relative),
                "installed_member_mismatch",
            )
            bound_files[relative] = wheel_hash
    return {
        "wheel_sha256": digest(wheel),
        "record_sha256": hashlib.sha256(record.encode()).hexdigest(),
        "package_version": distribution.version,
        "native_runtime_sha256": status.identity.sha256,
        "native_build_sha": status.capabilities.build_sha,
        "native_target": status.capabilities.target,
        "native_features": list(status.capabilities.features),
        "installed_files_sha256": bound_files,
        "noneditable_installed_import": True,
    }, runtime


def stop_evidence(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        encoded = stream.read(16 * 1024 + 1)
    require(len(encoded) <= 16 * 1024, "stop_evidence_bound")
    value = json.loads(encoded)
    require(
        isinstance(value, dict)
        and value.get("schema") == "hol-guard.native-resident-stop-diagnostic.v1",
        "stop_evidence_schema",
    )
    return value


def host_details() -> dict[str, object]:
    import resource

    result: dict[str, object] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "load_average": list(os.getloadavg()),
        "file_descriptor_limit": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "address_space_limit": list(resource.getrlimit(resource.RLIMIT_AS)),
    }
    try:
        value = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        require(len(value) <= 256, "cpu_identity_bound")
        result["cpu_identity"] = value
    except (OSError, subprocess.SubprocessError, RuntimeError):
        result["cpu_identity_unavailable"] = True
    return result


def run(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.package-export-diagnostic.v1",
        "artifact": args.artifact,
        "qualification_eligible": False,
        "expected_launches": 88,
        "sample_plan": dict(PLAN),
        "artifact_order": ["017f_baseline", "lazy_export_child"],
        "scope": "one standalone instrumented block; fixed artifact order; no full-corpus history",
        "timing_boundary": "unchanged original producer; bounded recording after each original timer returns",
        "partial_rows_are_individually_unattributed": True,
        "original_thresholds_ms": {"serial_p95": 50, "serial_p99": 100, "c16_p99": 200},
        "original_sample_minima_met": False,
    }
    stop_path = args.output.with_name(args.output.stem + "-stop.json").resolve()
    previous_stop = os.environ.get("NATIVE_STOP_DIAGNOSTIC_PATH")
    try:
        require(bool(sys.flags.isolated), "isolated_interpreter")
        require(
            sys.platform == "darwin" and platform.machine() == "arm64",
            "declared_platform",
        )
        report["host_before"] = host_details()
        require(digest(args.plan, 16 * 1024) == PLAN_SHA256, "plan_binding")
        report["plan_sha256"] = PLAN_SHA256
        report["source_before"] = source_binding(
            args.source_root, args.expected_source_sha, args.expected_source_tree
        )
        report["driver_before"] = {
            "sha": git(args.driver_root, "rev-parse", "HEAD"),
            "tree": git(args.driver_root, "rev-parse", "HEAD^{tree}"),
            "runner_sha256": digest(Path(__file__)),
        }
        require(
            report["driver_before"]["sha"] == args.expected_driver_sha, "driver_binding"
        )
        require(
            not git(args.driver_root, "status", "--porcelain", "--untracked-files=no"),
            "driver_dirty",
        )
        sys.path.insert(0, str(args.source_root.resolve()))
        clear_proof_environment = importlib.import_module(
            "scripts.native_slo_contract"
        ).clear_proof_environment
        require(not clear_proof_environment(dict(os.environ)), "proof_environment")
        report["installed_before"], runtime = installed_binding(
            args.wheel, args.expected_source_sha
        )
        require(not stop_path.exists(), "stop_evidence_exists")
        os.environ["NATIVE_STOP_DIAGNOSTIC_PATH"] = str(stop_path)
        producer = cast(
            Producer,
            cast(
                object, importlib.import_module("scripts.native_slo_priority_launchers")
            ),
        )
        DaemonFixture = importlib.import_module(
            "scripts.native_slo_daemon_fixture"
        ).DaemonFixture

        report["block"] = execute_block(
            DaemonFixture(runtime, policy="normal"), producer
        )
    except BaseException as error:
        report["driver_failure"] = failure(error)
    finally:
        if previous_stop is None:
            os.environ.pop("NATIVE_STOP_DIAGNOSTIC_PATH", None)
        else:
            os.environ["NATIVE_STOP_DIAGNOSTIC_PATH"] = previous_stop
        for key, operation in (
            ("host_after", host_details),
            (
                "source_after",
                lambda: source_binding(
                    args.source_root,
                    args.expected_source_sha,
                    args.expected_source_tree,
                ),
            ),
            (
                "driver_after",
                lambda: {
                    "sha": git(args.driver_root, "rev-parse", "HEAD"),
                    "tree": git(args.driver_root, "rev-parse", "HEAD^{tree}"),
                    "tracked_clean": not git(
                        args.driver_root,
                        "status",
                        "--porcelain",
                        "--untracked-files=no",
                    ),
                },
            ),
            (
                "installed_after",
                lambda: installed_binding(args.wheel, args.expected_source_sha)[0],
            ),
            ("native_stop", lambda: stop_evidence(stop_path)),
        ):
            try:
                report[key] = operation()
            except BaseException as error:
                report[key + "_failure"] = failure(error)
    block = report.get("block", {})
    stop = report.get("native_stop", {})
    report["complete"] = (
        "driver_failure" not in report
        and not any(key.endswith("_failure") for key in report)
        and block.get("producer_completed") is True
        and block.get("completed_original_calls") == 88
        and block.get("observation_complete") is True
        and block.get("fixture_cleanup_returned") is True
        and block.get("direct_fixture_child_reaped") is True
        and block.get("fixture_reader_threads_stopped") is True
        and stop.get("status") == "contained"
        and stop.get("authenticated") == "verified"
        and report.get("source_before") == report.get("source_after")
        and report.get("installed_before") == report.get("installed_after")
        and report.get("driver_after", {}).get("sha") == args.expected_driver_sha
        and report.get("driver_after", {}).get("tracked_clean") is True
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact", choices=("017f_baseline", "lazy_export_child"), required=True
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--driver-root", type=Path, required=True)
    parser.add_argument("--expected-driver-sha", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = run(args)
    encoded = json.dumps(report, indent=2, allow_nan=False).encode() + b"\n"
    require(len(encoded) <= 1024 * 1024, "report_bound")
    args.output.write_bytes(encoded)
    return 0 if report["complete"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
