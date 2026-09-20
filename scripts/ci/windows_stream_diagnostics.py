"""Run the unchanged Windows contract preflight with one explicit child observer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from contextlib import ExitStack, suppress
from pathlib import Path
from typing import Any
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard import native_hook_edge, native_runtime  # noqa: E402
from scripts import native_slo_corpus_run, native_slo_daemon_fixture  # noqa: E402
from scripts.ci.windows_stream_json_capture import InvalidJsonCapture  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402

ORIGINAL_SOURCE = "2433a8ce570f34f5ad3dbf23f3d7367267aad461"
MAX_REPORT_BYTES = 8 * 1024 * 1024
_ORIGINAL_LF_HASHES = {
    "native_slo_corpus_run.py": "e3929358892cebac728f222a10c6c841400143a0389f7b47ec8755627ff2d41c",
    "native_slo_daemon_fixture.py": "c1d055190f0c139d6d455db91e1c7edd44e66ac68b6f0f3fdfa2005f5479f26c",
    "native_slo_workloads.py": "30de7521f54735b626f6044b65e1aee4487a8a457786a7b7ac3412f49d09c041",
}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def verify_source() -> dict[str, str]:
    for module in (native_slo_corpus_run, native_slo_daemon_fixture):
        location = module.__file__
        require(
            isinstance(location, str)
            and Path(location).resolve(strict=True)
            == (_ROOT / "scripts" / (module.__name__.rsplit(".", 1)[-1] + ".py")).resolve(strict=True),
            "original_fixture_import_changed",
        )
    observed = {
        name: hashlib.sha256((_ROOT / "scripts" / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for name in _ORIGINAL_LF_HASHES
    }
    require(observed == _ORIGINAL_LF_HASHES, "original_fixture_source_changed")
    return observed


def verify_imports() -> None:
    distribution = importlib.metadata.distribution("hol-guard")
    for module in (native_runtime, native_hook_edge):
        relative = module.__name__.replace(".", "/") + ".py"
        expected = Path(str(distribution.locate_file(relative))).resolve(strict=True)
        location = module.__file__
        require(
            isinstance(location, str)
            and Path(location).resolve(strict=True) == expected
            and "site-packages" in expected.parts,
            "installed_import_required",
        )


def write_report(path: Path, report: dict[str, Any]) -> None:
    encoded = json.dumps(report, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    require(len(encoded) <= MAX_REPORT_BYTES, "diagnostic_report_exceeded_bound")
    with path.open("xb") as stream:
        stream.write(encoded)


class FixtureRedirect:
    """Change only the normal fixture entrypoint; preserve original spawn kwargs."""

    def __init__(self, runtime: Path, digest: str, report_path: Path) -> None:
        self.runtime, self.digest, self.report_path = runtime, digest, report_path
        self.original = native_slo_daemon_fixture._spawn_hook_process
        self.stack = ExitStack()
        self.selected_spawns = 0
        self.other_spawns = 0
        self.restored = False

    def spawn(self, argv: Any, **kwargs: Any) -> Any:
        expected = (
            sys.executable,
            "-u",
            str(Path(native_slo_daemon_fixture.__file__).resolve()),
            "--serve",
            str(self.runtime),
            "normal",
            "none",
        )
        if tuple(argv) == expected:
            self.selected_spawns += 1
            require(self.selected_spawns == 1, "duplicate_normal_fixture")
            selected = (
                *argv[:2],
                str(Path(__file__).resolve()),
                "--fixture-report",
                str(self.report_path),
                "--expected-runtime-sha256",
                self.digest,
                *argv[3:],
            )
            return self.original(selected, **kwargs)
        self.other_spawns += 1
        return self.original(argv, **kwargs)

    def __enter__(self) -> FixtureRedirect:
        self.stack.enter_context(patch.object(native_slo_daemon_fixture, "_spawn_hook_process", self.spawn))
        return self

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
        self.restored = native_slo_daemon_fixture._spawn_hook_process is self.original


def serve_captured(
    runtime: Path,
    setup: str,
    policy: str,
    workspace_count: int | None,
    *,
    native_phases: bool,
    report_path: Path,
    expected_digest: str,
) -> int:
    from scripts.native_slo_stream_diagnostic import StreamCapture

    require(setup == "normal" and policy == "none" and workspace_count is None and not native_phases, "fixture_scope")
    verify_imports()
    source = verify_source()
    identity = native_runtime._validate_binary(runtime)
    require(identity is not None and identity.sha256 == expected_digest, "fixture_binary_identity_changed")
    capture = StreamCapture(runtime)
    caller = InvalidJsonCapture(native_hook_edge)
    report: dict[str, Any] = {
        "schema": "hol-guard.windows-stream-fixture-diagnostic.v1",
        "original_source_sha": ORIGINAL_SOURCE,
        "original_source_lf_hashes": source,
        "scope": "original_normal_daemon_fixture_with_explicit_stream_observer",
        "original_fixture_entered": False,
        "original_fixture_returned": False,
        "original_arguments": {
            "setup": setup,
            "policy": policy,
            "workspace_count": workspace_count,
            "native_phases": native_phases,
        },
        "fixture_isolated_flag": bool(sys.flags.isolated),
        "runtime_sha256": expected_digest,
        "observer_cleanup_failed": False,
        "observer_report_failed": False,
        "identity_revalidation_failed": False,
        "requests_or_retries_added": False,
        "deadlines_changed": False,
        "qualification": False,
        "headline_timing_eligible": False,
        "observation_complete": False,
    }
    try:
        capture.__enter__()
        caller.__enter__()
        report["original_fixture_entered"] = True
        try:
            result = native_slo_daemon_fixture._serve(
                runtime, setup, policy, workspace_count, native_phases=native_phases
            )
        except Exception as error:
            with suppress(Exception):
                report["original_fixture_failure"] = failure_evidence(error)
            raise
        report["original_fixture_returned"] = True
        return result
    finally:
        # Original fixture teardown and its closed acknowledgement happen first.
        # These bounded observer operations cannot replace its result or error.
        for observer in (caller, capture):
            try:
                observer.__exit__(None, None, None)
            except Exception:
                report["observer_cleanup_failed"] = True
        try:
            report["stream_capture"] = capture.report()
            report["caller_capture"] = caller.report(report["stream_capture"])
        except Exception:
            report["observer_report_failed"] = True
        try:
            report["identity_revalidation_failed"] = native_runtime._validate_binary(runtime) != identity
        except Exception:
            report["identity_revalidation_failed"] = True
        report["observation_complete"] = bool(
            report.get("stream_capture", {}).get("observation_complete")
            and report.get("caller_capture", {}).get("observation_complete")
            and not report["observer_cleanup_failed"]
            and not report["observer_report_failed"]
            and not report["identity_revalidation_failed"]
        )
        # The controlling driver retains a missing or unreadable report as a failure.
        with suppress(Exception):
            write_report(report_path, report)


def run_probe(expected_build_sha: str, child_report: Path) -> dict[str, Any]:
    require(sys.platform == "win32" and bool(sys.flags.isolated), "isolated_windows_required")
    require(
        not any(name.startswith(("HOL_GUARD_", "GUARD_", "PYTEST_")) or name == "PYTHONPATH" for name in os.environ),
        "environment_override",
    )
    verify_imports()
    original_sources = verify_source()
    status = native_runtime.native_runtime_status()
    identity, capabilities = status.identity, status.capabilities
    require(
        status.mode == "auto" and status.available and status.compatible and status.reason == "native_ready",
        "installed_runtime_not_ready",
    )
    require(identity is not None and capabilities is not None, "installed_identity_missing")
    assert identity is not None and capabilities is not None
    require(capabilities.build_sha == expected_build_sha, "diagnostic_build_mismatch")
    require(native_runtime._validate_binary(identity.path) == identity, "initial_binary_identity_changed")
    redirect = FixtureRedirect(identity.path, identity.sha256, child_report)
    result: dict[str, Any] = {
        "schema": "hol-guard.windows-stream-contract-diagnostic.v1",
        "original_source_sha": ORIGINAL_SOURCE,
        "original_source_lf_hashes": original_sources,
        "scope": "unchanged_full_contract_preflight_once_original_order_normal_fixture_observer_only",
        "original_workload_callable": "native_slo_corpus_run.run_contract_corpus",
        "target_case": "cursor.afterShellExecution.block.256k",
        "target_normal_case_zero_index": 68,
        "original_workload_returned": False,
        "diagnostic_command": "resident-client-stream-diagnostic",
        "ordinary_command": "resident-client-stream",
        "identity": {
            "sha256": identity.sha256,
            "size": identity.size,
            "build_sha": capabilities.build_sha,
            "target": capabilities.target,
            "rule_digest": capabilities.rule_digest,
        },
        "fixture_report_missing": False,
        "identity_revalidation_failed": False,
        "source_revalidation_failed": False,
        "requests_or_retries_added": False,
        "deadlines_changed": False,
        "qualification": False,
        "headline_timing_eligible": False,
        "observation_complete": False,
    }
    try:
        with redirect:
            try:
                result["original_workload_result"] = native_slo_corpus_run.run_contract_corpus(identity.path)
                result["original_workload_returned"] = True
            except Exception as error:
                result["original_workload_failure"] = failure_evidence(error)
    finally:
        try:
            require(child_report.is_file() and child_report.stat().st_size <= MAX_REPORT_BYTES, "fixture_report_bound")
            child = json.loads(child_report.read_bytes())
            require(
                type(child) is dict and child.get("schema") == "hol-guard.windows-stream-fixture-diagnostic.v1",
                "fixture_report_schema",
            )
            require(
                child.get("runtime_sha256") == identity.sha256 and child.get("qualification") is False,
                "fixture_report_binding",
            )
            result["fixture_report"] = child
        except Exception:
            result["fixture_report_missing"] = True
        try:
            result["identity_revalidation_failed"] = native_runtime._validate_binary(identity.path) != identity
        except Exception:
            result["identity_revalidation_failed"] = True
        try:
            result["source_revalidation_failed"] = verify_source() != original_sources
        except Exception:
            result["source_revalidation_failed"] = True
        result["selected_normal_fixture_spawns"] = redirect.selected_spawns
        result["unchanged_other_fixture_spawns"] = redirect.other_spawns
        result["spawn_provider_restored"] = redirect.restored
    result["observation_complete"] = bool(
        result.get("fixture_report", {}).get("observation_complete")
        and redirect.selected_spawns == 1
        and redirect.restored
        and not result["identity_revalidation_failed"]
        and not result["source_revalidation_failed"]
    )
    failure = result.get("original_workload_failure", {})
    diagnostic = failure.get("native_call_diagnostic")
    result["target_case_failed"] = failure.get("case") == result["target_case"]
    result["target_invalid_json_failure_reproduced"] = bool(
        result["target_case_failed"]
        and isinstance(diagnostic, dict)
        and diagnostic.get("edge_decoder_error_value") == "native_request_invalid_json"
    )
    return result


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture-report":
        from scripts.native_slo_daemon_entrypoint import main as original_entrypoint

        require(len(sys.argv) == 9 and sys.argv[3] == "--expected-runtime-sha256", "fixture_arguments")
        report_path, digest = Path(sys.argv[2]), sys.argv[4]
        sys.argv[1:5] = []

        def serve(*args: Any, **kwargs: Any) -> int:
            return serve_captured(*args, **kwargs, report_path=report_path, expected_digest=digest)

        return original_entrypoint(serve, native_slo_daemon_fixture._emit)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    child = args.output.with_name(args.output.stem + "-fixture.json")
    try:
        require(not args.output.exists() and not child.exists(), "diagnostic_output_already_exists")
        result = run_probe(args.expected_source_sha, child)
    except Exception as error:
        result = {
            "schema": "hol-guard.windows-stream-contract-diagnostic.v1",
            "failure": failure_evidence(error),
            "qualification": False,
            "observation_complete": False,
        }
    write_report(args.output, result)
    print(json.dumps({"observation_complete": result["observation_complete"], "qualification": False}))
    return 0 if result["observation_complete"] and result.get("original_workload_returned") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
