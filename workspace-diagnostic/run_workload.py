"""Run only the three original 100-scope cells with fixture-local observations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from workspace_cause.child import SCENARIOS
from workspace_cause.parent import FixtureForwarding
from workspace_cause.reader import read_cell, summarize

SOURCE_SHA = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
MAX_RUNTIME_BYTES = 128 * 1024 * 1024


def _write(path: Path, value: Any) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _digest(path: Path) -> str:
    total = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_RUNTIME_BYTES:
                raise ValueError("workspace_runtime_size")
            digest.update(block)
    if not total:
        raise ValueError("workspace_runtime_empty")
    return digest.hexdigest()


def _installed_runtime(source: Path) -> tuple[Path, dict[str, Any]]:
    distribution = importlib.metadata.distribution("hol-guard")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    if direct.get("dir_info", {}).get("editable") is True:
        raise ValueError("workspace_requires_installed_wheel")
    runtime = Path(str(distribution.locate_file("codex_plugin_scanner/_native/hol-guard-runtime"))).resolve(strict=True)
    if "site-packages" not in runtime.parts or runtime.is_relative_to(source / "src"):
        raise ValueError("workspace_runtime_install_origin")
    manifest = json.loads(runtime.with_name("runtime-manifest.json").read_text(encoding="utf-8"))
    digest = _digest(runtime)
    if (
        manifest.get("source_sha") != SOURCE_SHA
        or manifest.get("runtime_sha256") != digest
        or manifest.get("target") != "x86_64-unknown-linux-musl"
        or manifest.get("package_version") != distribution.version
    ):
        raise ValueError("workspace_installed_identity")
    return runtime, {
        "source_sha": SOURCE_SHA,
        "runtime_sha256": digest,
        "runtime_size": runtime.stat().st_size,
        "package_version": distribution.version,
        "target": manifest["target"],
        "manifest_sha256": _digest(runtime.with_name("runtime-manifest.json")),
        "installed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    if not sys.flags.isolated or os.name != "posix" or sys.platform != "linux":
        raise ValueError("workspace_diagnostic_requires_isolated_linux")
    forbidden = ("HOL_GUARD_", "GUARD_NATIVE", "GUARD_TEST_", "GUARD_ORACLE", "GUARD_DIAGNOSTIC", "PYTEST_")
    if "PYTHONPATH" in os.environ or any(name.startswith(forbidden) for name in os.environ):
        raise ValueError("workspace_diagnostic_environment")
    sys.path.insert(0, str(source))
    from scripts import native_slo_workspace_lifecycle_runner as runner

    if Path(runner.__file__).resolve(strict=True) != source / "scripts/native_slo_workspace_lifecycle_runner.py":
        raise ValueError("workspace_lifecycle_source_binding")
    runtime, identity_before = _installed_runtime(source)
    observations = output / "observations"
    observations.mkdir(mode=0o700)
    _write(output / "installed-before.json", identity_before)
    original_result: Any = None
    original_function_calls = 0
    all_selected_passed = False
    failure = None
    forwarding = FixtureForwarding(source, observations)
    admitted = False
    summaries: list[dict[str, Any]] = []
    try:
        with forwarding:
            original_function_calls += 1
            original_result = runner.run_lifecycle_sweep(
                runtime,
                ledger_path=output / "workspace-lifecycle.jsonl",
                counts=(100,),
                scenarios=SCENARIOS,
            )
        _write(output / "workspace-lifecycle.json", original_result)
        cells = original_result.get("cells")
        if (
            original_result.get("counts") != [100]
            or original_result.get("scenarios") != list(SCENARIOS)
            or original_result.get("complete_lifecycle_matrix_visited") is not False
            or original_result.get("implemented_checks_passed") is not False
            or original_result.get("headline_timing_eligible") is not False
            or original_result.get("full_rsp_128_129_qualification") is not False
            or not isinstance(cells, list)
            or len(cells) != 3
            or original_result.get("runtime", {}).get("build_sha") != SOURCE_SHA
            or original_result.get("runtime", {}).get("runtime_sha256") != identity_before["runtime_sha256"]
        ):
            raise ValueError("workspace_original_result_contract")
        for index, scenario in enumerate(SCENARIOS):
            report = read_cell(observations / f"{index:02d}.json", scenario)
            flags = report["original_result_flags"]
            original_cell = cells[index]
            if (
                original_cell.get("scenario") != scenario
                or original_cell.get("registered_workspaces") != 100
                or (original_cell.get("passed") is True) != flags["passed"]
            ):
                raise ValueError("workspace_original_cell_join")
            summaries.append(summarize(report))
        forwarding_report = forwarding.report()
        if (
            forwarding_report["patches_restored"] is not True
            or forwarding_report["declared_fixture_roster_complete"] is not True
        ):
            raise ValueError("workspace_forwarding_incomplete")
        admitted = True
    except BaseException as error:
        failure = type(error).__name__
        raise
    finally:
        try:
            _runtime, identity_after = _installed_runtime(source)
            identity_preserved = identity_after == identity_before
            _write(output / "installed-after.json", identity_after)
        except Exception:
            identity_preserved = False
        try:
            if failure is None:
                failure_class = None
            elif failure in {"RuntimeError", "ValueError", "OSError", "FileNotFoundError", "PermissionError"}:
                failure_class = failure
            else:
                failure_class = "other"
            all_selected_passed = (
                isinstance(original_result, dict)
                and isinstance(original_result.get("cells"), list)
                and len(original_result["cells"]) == 3
                and all(cell.get("passed") is True for cell in original_result["cells"])
            )
            _write(
                output / "diagnostic-result.json",
                {
                    "schema": "hol-guard.workspace-cause-diagnostic.v1",
                    "source_sha": SOURCE_SHA,
                    "selected_counts": [100],
                    "selected_scenarios": list(SCENARIOS),
                    "original_function_calls": original_function_calls,
                    "original_selected_cells_passed": all_selected_passed,
                    "original_full_matrix_passed": False,
                    "original_cli_full_matrix_gate_would_pass": False,
                    "diagnostic_admitted": admitted and identity_preserved,
                    "installed_identity_preserved": identity_preserved,
                    "forwarding": forwarding.report(),
                    "summaries": summaries,
                    "failure_class": failure_class,
                    "original_readiness_deadline_ms": 400,
                    "headline_timing_eligible": False,
                    "qualification_complete": False,
                    "native_internal_cause_attribution": False,
                },
            )
        except Exception:
            # Missing output is a failed collection, never a replacement for an original error.
            pass
    return 0 if admitted and identity_preserved and all_selected_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
