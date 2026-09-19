"""Run the original installed auto probe once under the separate storage observer.

Instrumented outcomes are diagnostic only. The tracer can cause additional
50 ms storage-gate timeouts; this run cannot explain earlier unobserved failures
or establish their rate. Product deadlines, retries and corpus checks are intact.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import platform
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Standalone -I entry: these adjacent diagnostic helpers deliberately use
# top-level imports. This directory never contains the product package.
sys.path.append(str(Path(__file__).resolve().parent))
from windows_storage_artifact import (  # pyright: ignore[reportImplicitRelativeImport]
    ARTIFACT_ID,
    BUILD,
    MANIFEST_SHA256,
    RUNTIME_SHA256,
    SOURCE,
    TREE,
    WHEEL_SHA256,
    checkout_inventory,
    dump,
    installed_inventory,
    package_map,
    require,
    sha,
    verified_wheel,
)
from windows_storage_exception_observer import (  # pyright: ignore[reportImplicitRelativeImport]
    SOURCE_PINS,
    bind_installed,
)

IDENTITY_CASES = (
    "steady_without_client",
    "fresh_child",
    "steady_with_client",
    "death_before_restart",
    "live_replacement",
    "replacement_first_status",
    "replacement_fresh_child",
    "source_sha_mismatch",
    "source_sha_restoration",
    "source_sha_restoration_child",
    "package_version_mismatch",
    "package_version_restoration",
    "package_version_restoration_child",
    "same_size_restored_mtime_corruption",
    "original_artifact_restoration",
    "restoration_fresh_child",
    "retired_client_status",
)


def run_once(probe: Callable[[], int], observer: Any, finish: Callable[[dict[str, Any]], None]) -> int:
    """Preserve the original return/exception and invoke no extra workload."""
    result = None
    calls = 0
    failure = False
    probe_failure = False
    try:
        with observer:
            calls += 1
            try:
                result = probe()
            except BaseException:
                probe_failure = True
                raise
        return result
    except BaseException:
        failure = True
        raise
    finally:
        try:
            finish(
                {
                    "probe_invocations": calls,
                    "probe_exit_code": result,
                    "probe_raised": probe_failure,
                    "observed_scope_raised": failure,
                    "observer": observer.snapshot(),
                }
            )
        except BaseException:
            if not failure:
                raise
            # Never replace the already propagating original probe exception.
            print("windows_storage_diagnostic_evidence_failed", file=sys.stderr)


def load_original_probe(source_root: Path) -> Any:
    path = source_root / "ci/native_runtime/probe_native_default_auto.py"
    spec = importlib.util.spec_from_file_location("_original_installed_auto_probe", path)
    require(spec is not None and spec.loader is not None, "probe_spec")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in (
        "ci.native_runtime.default_auto_failure",
        "ci.native_runtime.default_auto_routes",
        "scripts.native_probe_receipts",
        "scripts.native_slo_contract",
        "scripts.native_slo_command_fixture",
    ):
        loaded = sys.modules.get(name)
        if loaded is None and name == "scripts.native_slo_command_fixture":
            continue  # The unchanged probe imports this helper lazily.
        loaded_path = getattr(loaded, "__file__", None)
        require(isinstance(loaded_path, str), "probe_helper_missing")
        assert isinstance(loaded_path, str)
        require(
            Path(loaded_path).resolve() == (source_root / (name.replace(".", "/") + ".py")).resolve(),
            "probe_helper_origin",
        )
    return module


def prior_controls(output: Path) -> dict[str, Any]:
    identity_path = output / "native-installed-identity.json"
    identity = json.loads(identity_path.read_text())
    require(identity["schema"] == "hol-guard.installed-runtime-identity.v1", "identity_schema")
    require(identity["build_sha"] == BUILD and identity["runtime_sha256"] == RUNTIME_SHA256, "identity_source")
    require(identity["manifest_sha256"] == MANIFEST_SHA256 and len(identity["cases"]) == 17, "identity_controls")
    require(tuple(case["case"] for case in identity["cases"]) == IDENTITY_CASES, "identity_case_set")
    require(
        all(
            case["result"] == ("replaced" if case["case"] == "live_replacement" else "passed")
            for case in identity["cases"]
        ),
        "identity_outcome",
    )
    lock_path = output / "native-installed-control-lock.json"
    locks = json.loads(lock_path.read_text())
    require(locks["schema"] == "hol-guard.installed-command-control-lock.v1", "lock_schema")
    require(len(locks["cases"]) == 4, "lock_controls")
    require(
        tuple((case["parent_shared"], case["child_shared"]) for case in locks["cases"])
        == ((True, True), (True, False), (False, True), (False, False)),
        "lock_case_set",
    )
    for case in locks["cases"]:
        require(
            all(type(case[key]) is bool for key in ("released", "child_acquired", "parent_shared", "child_shared"))
            and case["released"]
            and case["child_acquired"] == (case["parent_shared"] and case["child_shared"]),
            "lock_outcome",
        )
    return {
        "identity_sha256": sha(identity_path.read_bytes()),
        "identity_cases": 17,
        "control_lock_sha256": sha(lock_path.read_bytes()),
        "control_lock_cases": 4,
        "controls_precede_observer_in_separate_processes": True,
    }


def run_diagnostic(options: argparse.Namespace) -> int:
    require(
        sys.platform == "win32"
        and platform.python_implementation() == "CPython"
        and sys.version_info[:3] == (3, 12, 10),
        "platform_unsupported",
    )
    require(bool(sys.flags.isolated), "isolated_interpreter_required")
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "original_workflow_attempt_required")
    before = checkout_inventory(options.source, SOURCE, TREE)
    driver_before = checkout_inventory(options.driver_source, options.driver_commit)
    wheel = verified_wheel(options.archive)
    expected = package_map(wheel, options.source)
    package_root, installed_before = installed_inventory(expected)
    controls = prior_controls(options.output)
    import codex_plugin_scanner

    require(Path(codex_plugin_scanner.__file__).resolve() == package_root / "__init__.py", "package_import_origin")
    probe = load_original_probe(options.source)
    observer = bind_installed(package_root, dict(SOURCE_PINS))
    receipt: dict[str, Any] = {}

    def finish(observation: dict[str, Any]) -> None:
        checks = {
            "source_files_before_after_equal": lambda: checkout_inventory(options.source, SOURCE, TREE) == before,
            "driver_files_before_after_equal": lambda: (
                checkout_inventory(options.driver_source, options.driver_commit) == driver_before
            ),
            "installed_files_before_after_equal": lambda: installed_inventory(expected)[1] == installed_before,
        }
        verified = {}
        for name, check in checks.items():
            try:
                verified[name] = check()
            except Exception:
                verified[name] = False
        receipt.update(
            {
                "schema": "hol-guard.installed-windows-storage-diagnostic.v1",
                "source": SOURCE,
                "build": BUILD,
                "tree": TREE,
                "driver_commit": options.driver_commit,
                "original_artifact_id": ARTIFACT_ID,
                "original_wheel_sha256": WHEEL_SHA256,
                "original_runtime_sha256": RUNTIME_SHA256,
                "original_runtime_manifest_sha256": MANIFEST_SHA256,
                "python": platform.python_version(),
                "platform": sys.platform,
                "machine": platform.machine(),
                "distribution_versions": {
                    name: importlib.metadata.version(name) for name in ("hol-guard", "anyio", "mcp", "pywin32")
                },
                **verified,
                "installed_file_count": len(installed_before),
                "prior_controls": controls,
                **observation,
                "observer_units_scope": "entry_arguments_to_product_failure_diagnostics_method",
                "observer_units_are_product_committed_counters": False,
                "exception_event_to_record_attempt_join_proven": False,
                "observer_perturbation_quantified": False,
                "observer_can_create_50ms_timeouts": True,
                "historical_failure_cause_established": False,
                "unobserved_failure_rate_established": False,
                "headline_timing_eligible": False,
                "qualification_complete": False,
            }
        )
        dump(options.output / "windows-storage-observation.json", receipt)

    result = run_once(lambda: probe.main(json_path=options.output / "native-default-auto.json"), observer, finish)
    if result != 0:
        return result
    require(receipt["observer"]["complete"], "diagnostic_incomplete")
    require(
        receipt["source_files_before_after_equal"]
        and receipt["driver_files_before_after_equal"]
        and receipt["installed_files_before_after_equal"],
        "diagnostic_binding_changed",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--driver-source", required=True, type=Path)
    parser.add_argument("--driver-commit", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    options.source = options.source.resolve()
    options.driver_source = options.driver_source.resolve()
    options.output = options.output.resolve()
    return run_diagnostic(options)


if __name__ == "__main__":
    raise SystemExit(main())
