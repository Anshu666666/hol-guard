"""One unchanged installed default-auto invocation with failure-only observation."""

# The installed probe itself uses the repository root for its CI fixture imports.
# ruff: noqa: E402
from __future__ import annotations

import argparse
import hashlib
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

from ci.native_runtime.journal_checkpoint_artifact import MANIFEST_SHA, RUNTIME_SHA
from ci.native_runtime.journal_checkpoint_binding import BUILD_SHA, SOURCE_SHA, SOURCE_TREE, source_binding
from ci.native_runtime.journal_checkpoint_capture import JournalCheckpointCapture


def persist(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def observe_once(
    call: Callable[[], int], capture: JournalCheckpointCapture, export: Callable[[dict[str, Any]], None]
) -> int:
    """Keep the original result/exception; report an export failure separately."""
    try:
        with capture:
            return call()
    finally:
        try:
            export(capture.report())
        except BaseException:
            with suppress(BaseException):
                print("journal_diagnostic_export_failed", file=sys.stderr)


def _git(*arguments: str) -> str:
    return subprocess.check_output(("git", "-C", str(ROOT), *arguments), text=True, timeout=20).strip()


def binding(package: Path) -> dict[str, Any]:
    if os.name != "nt" or sys.version_info[:3] != (3, 12, 10):
        raise RuntimeError("journal_diagnostic_platform_mismatch")
    if package.is_relative_to(ROOT / "src") or not package.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("journal_diagnostic_installed_import_required")
    expected_source, expected_tree = os.environ["DIAGNOSTIC_SOURCE_SHA"], os.environ["DIAGNOSTIC_SOURCE_TREE"]
    if _git("rev-parse", "HEAD") != expected_source or _git("rev-parse", "HEAD^{tree}") != expected_tree:
        raise RuntimeError("journal_diagnostic_source_identity_mismatch")
    if _git("diff", "--name-only") or _git("diff", "--cached", "--name-only"):
        raise RuntimeError("journal_diagnostic_source_dirty")
    changed = set(_git("diff", "--name-only", SOURCE_SHA, "HEAD").splitlines())
    expected_changed = {
        "ci/native_runtime/journal_checkpoint_capture.py",
        "ci/native_runtime/journal_checkpoint_binding.py",
        "ci/native_runtime/journal_checkpoint_artifact.py",
        "ci/native_runtime/journal_checkpoint_run.py",
        "tests/test_journal_checkpoint_capture.py",
        "tests/test_journal_checkpoint_runner.py",
    }
    if changed != expected_changed:
        raise RuntimeError("journal_diagnostic_source_delta_mismatch")
    if _git("rev-parse", "HEAD^") != SOURCE_SHA or _git("rev-parse", SOURCE_SHA + "^{tree}") != SOURCE_TREE:
        raise RuntimeError("journal_diagnostic_parent_mismatch")
    native = package / "_native"
    runtime, manifest = native / "hol-guard-runtime.exe", native / "runtime-manifest.json"
    runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    manifest_bytes = manifest.read_bytes()
    if runtime_digest != RUNTIME_SHA or hashlib.sha256(manifest_bytes).hexdigest() != MANIFEST_SHA:
        raise RuntimeError("journal_diagnostic_installed_artifact_mismatch")
    decoded = json.loads(manifest_bytes)
    if decoded["source_sha"] != BUILD_SHA:
        raise RuntimeError("journal_diagnostic_build_identity_mismatch")
    return {
        "diagnostic_source": expected_source,
        "diagnostic_tree": expected_tree,
        "driver": os.environ["GITHUB_SHA"],
        "product_source": SOURCE_SHA,
        "product_tree": SOURCE_TREE,
        "build_sha": BUILD_SHA,
        "runtime_sha256": runtime_digest,
        "manifest_sha256": MANIFEST_SHA,
        "sources": source_binding(package, ROOT),
        "python": sys.version,
        "executable": sys.executable,
        "installed_package": str(package),
        "dependencies": sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions()),
    }


def run(output: Path) -> int:
    import codex_plugin_scanner
    from ci.native_runtime import probe_native_default_auto as probe
    from ci.native_runtime.journal_checkpoint_binding import operation_registry
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer

    output.mkdir(parents=True, exist_ok=True)
    package = Path(codex_plugin_scanner.__file__).resolve().parent
    before = binding(package)
    persist(output / "binding-before.json", before)
    capture = JournalCheckpointCapture(
        writer,
        probe,
        checkpoint_code=writer.RuntimeHookEvidenceWriter._checkpoint_completed_records.__code__,
        sites=operation_registry(journal),
    )
    invocations = 0

    def original_probe() -> int:
        nonlocal invocations
        invocations += 1
        return probe.main(json_path=output / "native-default-auto.json")

    def export(report: dict[str, Any]) -> None:
        report["original_probe_invocations"] = invocations
        persist(output / "journal-origin.json", report)
        after = binding(package)
        persist(output / "binding-after.json", after)
        persist(output / "binding-comparison.json", {"equal": before == after})
        if before != after:
            raise RuntimeError("journal_diagnostic_binding_changed")

    return observe_once(original_probe, capture, export)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(run(parser.parse_args().output))
