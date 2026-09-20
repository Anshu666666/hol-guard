"""Run the unchanged normal installed SLO workload with explicit stream diagnostics."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard import native_runtime as runtime  # noqa: E402
from scripts.bench_guard_native_installed_slo import run_slo  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_stream_diagnostic import StreamCapture  # noqa: E402


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def run_probe(expected_sha: str) -> dict[str, Any]:
    require(sys.platform == "darwin" and bool(sys.flags.isolated), "isolated_macos_required")
    require(
        not any(name.startswith(("HOL_GUARD_", "GUARD_", "PYTEST_")) or name == "PYTHONPATH" for name in os.environ),
        "environment_override",
    )
    distribution = importlib.metadata.distribution("hol-guard")
    expected_module = Path(str(distribution.locate_file("codex_plugin_scanner/guard/native_runtime.py"))).resolve()
    require(
        Path(runtime.__file__).resolve() == expected_module and "site-packages" in expected_module.parts,
        "installed_import_required",
    )
    status = runtime.native_runtime_status()
    require(
        status.mode == "auto" and status.available and status.compatible and status.reason == "native_ready",
        "installed_identity_unavailable",
    )
    identity, capabilities = status.identity, status.capabilities
    require(identity is not None and capabilities is not None, "installed_identity_missing")
    assert identity is not None and capabilities is not None
    require(capabilities.build_sha == expected_sha, "diagnostic_build_mismatch")
    require(runtime._validate_binary(identity.path) == identity, "initial_binary_identity_changed")
    result: dict[str, Any] = {
        "schema": "hol-guard.native-stream-phase-driver.v1",
        "diagnostic_only": True,
        "qualification": False,
        "headline_timing_eligible": False,
        "original_source_sha": "2433a8ce570f34f5ad3dbf23f3d7367267aad461",
        "scope": "unchanged_normal_installed_slo_with_explicit_owned_persistent_client_command",
        "diagnostic_command": "resident-client-stream-diagnostic",
        "ordinary_command": "resident-client-stream",
        "original_workload_parameters": {
            "warm_iterations": 2,
            "cold_iterations": 2,
            "recovery_iterations": 2,
            "readiness_samples": 2,
            "include_capacity": True,
            "launcher_iterations": 2,
        },
        "requests_or_retries_added": False,
        "deadlines_changed": False,
        "workload_returned": False,
        "identity_revalidation_failed": False,
        "capture_cleanup_failed": False,
        "capture_report_failed": False,
        "identity": {
            "sha256": identity.sha256,
            "size": identity.size,
            "build_sha": capabilities.build_sha,
            "target": capabilities.target,
            "rule_digest": capabilities.rule_digest,
        },
        "observation_complete": False,
    }
    capture = StreamCapture(identity.path)
    try:
        with capture:
            try:
                original = run_slo(
                    identity.path,
                    warm_iterations=2,
                    cold_iterations=2,
                    recovery_iterations=2,
                    readiness_samples=2,
                    include_capacity=True,
                    launcher_iterations=2,
                )
                result["original_workload_result"] = original
                result["workload_returned"] = True
            except Exception as error:
                result["original_workload_failure"] = failure_evidence(error)
    except Exception:
        result["capture_cleanup_failed"] = True
    finally:
        try:
            result["capture"] = capture.report()
        except Exception:
            result["capture_report_failed"] = True
            result["capture"] = {"observation_complete": False}
        try:
            result["identity_revalidation_failed"] = runtime._validate_binary(identity.path) != identity
        except Exception:
            result["identity_revalidation_failed"] = True
    result["observation_complete"] = bool(
        result["capture"]["observation_complete"]
        and not result["identity_revalidation_failed"]
        and not result["capture_cleanup_failed"]
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result: dict[str, Any]
    try:
        result = run_probe(args.expected_source_sha)
    except Exception as error:
        result = {
            "schema": "hol-guard.native-stream-phase-driver.v1",
            "diagnostic_only": True,
            "qualification": False,
            "observation_complete": False,
            "failure": failure_evidence(error),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"observation_complete": result["observation_complete"], "qualification": False}))
    original = result.get("original_workload_result", {})
    return 0 if result["observation_complete"] and original.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
