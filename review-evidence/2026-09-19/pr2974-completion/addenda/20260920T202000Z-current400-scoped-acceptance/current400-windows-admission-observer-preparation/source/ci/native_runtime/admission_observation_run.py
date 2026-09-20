"""One original installed corpus with counter observations outside each delivery."""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from ci.native_runtime.admission_observation_binding import (
    SOURCE_SHA,
    SOURCE_TREE,
    installed_origin,
    source_binding,
    wheel_binding,
)
from ci.native_runtime.admission_observation_capture import AdmissionCapture

CHANGED = frozenset(
    {
        "ci/native_runtime/admission_observation_values.py",
        "ci/native_runtime/admission_observation_capture.py",
        "ci/native_runtime/admission_observation_binding.py",
        "ci/native_runtime/admission_observation_run.py",
        "tests/test_admission_observation.py",
        "tests/test_admission_observation_runner.py",
    }
)


def persist(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def observe_once(call: Callable[[], int], capture: AdmissionCapture, export: Callable[[dict[str, Any]], None]) -> int:
    """An export fault fails separate admission, never replaces the original outcome."""
    outcome: dict[str, object] = {"returned": False, "returncode": None}
    try:
        with capture:
            result = call()
            outcome = {"returned": True, "returncode": result if type(result) is int else None}
            return result
    finally:
        try:
            report = capture.report()
            report["original_outcome"] = outcome
            export(report)
        except BaseException:
            with suppress(BaseException):
                print("admission_observation_export_failed", file=sys.stderr)


def _git(*arguments: str) -> str:
    return subprocess.check_output(("git", "-C", str(ROOT), *arguments), text=True, timeout=20).strip()


def binding(package: Path, wheel: Path) -> dict[str, Any]:
    if os.name != "nt" or sys.version_info[:3] != (3, 12, 10):
        raise RuntimeError("admission_platform_mismatch")
    installed_origin(package, ROOT, Path(sys.prefix).resolve())
    expected_sha, expected_tree = os.environ["DIAGNOSTIC_SOURCE_SHA"], os.environ["DIAGNOSTIC_SOURCE_TREE"]
    if _git("rev-parse", "HEAD") != expected_sha or _git("rev-parse", "HEAD^{tree}") != expected_tree:
        raise RuntimeError("admission_source_identity_mismatch")
    if _git("diff", "--name-only") or _git("diff", "--cached", "--name-only"):
        raise RuntimeError("admission_source_dirty")
    if set(_git("diff", "--name-only", SOURCE_SHA, "HEAD").splitlines()) != CHANGED:
        raise RuntimeError("admission_source_delta_mismatch")
    if _git("rev-parse", "HEAD^") != SOURCE_SHA or _git("rev-parse", SOURCE_SHA + "^{tree}") != SOURCE_TREE:
        raise RuntimeError("admission_source_parent_mismatch")
    return {
        "diagnostic_source": expected_sha,
        "diagnostic_tree": expected_tree,
        "driver": os.environ["GITHUB_SHA"],
        "product_source": SOURCE_SHA,
        "product_tree": SOURCE_TREE,
        "artifact": wheel_binding(wheel, package),
        "sources": source_binding(package, ROOT),
        "python": sys.version,
        "executable": sys.executable,
        "prefix": sys.prefix,
        "installed_package": str(package),
        "dependencies": sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions()),
    }


def run(output: Path, wheel: Path) -> int:
    import codex_plugin_scanner
    from ci.native_runtime import default_auto_failure, default_auto_routes
    from ci.native_runtime import probe_native_default_auto as probe

    output.mkdir(parents=True, exist_ok=True)
    package = Path(codex_plugin_scanner.__file__).resolve().parent
    before = binding(package, wheel)
    persist(output / "binding-before.json", before)
    if any(
        getattr(probe, name) is not getattr(default_auto_failure, name)
        for name in ("bind_corpus", "observe_corpus", "end_corpus")
    ):
        raise RuntimeError("admission_initial_probe_alias_changed")
    if (
        default_auto_routes._installed_hook_request
        is not default_auto_routes._HOOK_CLIENT_MODULE.installed_hook_request
    ):
        raise RuntimeError("admission_initial_request_alias_changed")
    capture = AdmissionCapture(probe, default_auto_routes)
    invocations = 0

    def original() -> int:
        nonlocal invocations
        invocations += 1
        return probe.main(json_path=output / "native-default-auto.json")

    def export(report: dict[str, Any]) -> None:
        report["original_probe_invocations"] = invocations
        persist(output / "admission-observation.json", report)
        after = binding(package, wheel)
        persist(output / "binding-after.json", after)
        persist(output / "binding-comparison.json", {"equal": before == after})
        if before != after:
            raise RuntimeError("admission_binding_changed")

    return observe_once(original, capture, export)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output, args.wheel))
