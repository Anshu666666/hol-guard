"""Finite installed 1/10/100 workspace publication witness supervisor.

This script is execution tooling. Run it only after source review. It makes one
collector attempt with the original six phases per cell and unchanged limits.
Linux subreaping belongs solely to this fresh observational harness process;
its cleanup does not qualify ordinary runtime parent/reaping behavior.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import (  # noqa: E402
    WHEEL,
    bounded,
    compact_directory,
    digest,
    encoded,
    error_name,
    private_directory,
    require,
    verify_helpers,
    verify_installation,
    write_json,
)


def source_inventory() -> dict[str, str]:
    selected = [
        *ROOT.glob("*.py"),
        *ROOT.glob("*.json"),
        *(path for path in ROOT.glob("helpers/**/*") if path.is_file()),
    ]
    return {str(path.relative_to(ROOT)): digest(bounded(path, 1024 * 1024)) for path in sorted(selected)}


def cleanup_compact_directories(registry: Path, temporary_parent: Path) -> dict[str, Any]:
    raw = bounded(registry, 3 * 4096)
    lines = raw.splitlines()
    require(len(lines) <= 3, "registered_home_count_exceeded")
    roots = set()
    removed = 0
    absent = 0
    for line in lines:
        value = json.loads(line)
        require(set(value) == {"root", "home", "compact"}, "private_registry_shape")
        root, home, compact = (Path(value[field]) for field in ("root", "home", "compact"))
        require(
            root.parent == temporary_parent and re.fullmatch(r"hol-guard-slo-[A-Za-z0-9_-]+", root.name),
            "private_registry_root",
        )
        require(root not in roots and home == root / ".hol-guard", "private_registry_home")
        require(compact == compact_directory(home), "private_registry_socket_scope")
        roots.add(root)
        if os.path.lexists(compact):
            private_directory(compact)
            compact.rmdir()  # Never recursively remove a compact socket directory.
            removed += 1
        else:
            absent += 1
    return {
        "registered_homes": len(roots),
        "compact_directories_removed": removed,
        "compact_directories_already_absent": absent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, default=WHEEL)
    parser.add_argument("--output-directory", type=Path, default=ROOT / "attempt-001")
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    destination = args.output_directory.resolve()
    require(not destination.exists(), "attempt_already_exists")
    destination.mkdir(mode=0o700)
    report: dict[str, Any] = {
        "schema": "installed-workspace-publication-witness.v1",
        "scope": "finite_linux_installed_bundled_auto_workspace_publication",
        "counts": [1, 10, 100],
        "maximum_scenario_hook_requests": 18,
        "phases_per_cell": 6,
        "readiness_budget_ms": 400,
        "hook_transport_timeout_seconds": 5,
        "writer_drain_budget_seconds": 5,
        "owner_budget_seconds": 180,
        "owner_drain_seconds": 5,
        "full_rsp_128_129_qualification": False,
        "headline_timing_eligible": False,
        "ownership_scope": "fresh_observational_subreaper_not_product_parent_reaping_semantics",
        "qualification_construction": "explicit_early_factory_attachment_and_partial_construction_cleanup",
        "pending": [
            "lost_metadata_hint",
            "key_rotation",
            "expiry_fault",
            "first_admission_fault",
            "concurrent_contention",
            "uninstrumented_paired_performance",
            "other_platforms",
        ],
        "failures": [],
        "cleanup": {},
    }
    private = None
    initial = None
    before = None
    owned = None
    started = time.monotonic()
    try:
        _, initial = verify_installation(wheel)
        report["production_provenance"] = initial
        report["qualification_helper_provenance"] = verify_helpers()
        before = source_inventory()
        write_json(destination / "harness-source-inventory.json", before)
        report["harness_inventory_sha256"] = digest(encoded(before))
        private = Path(tempfile.mkdtemp(prefix="private-run-", dir=ROOT)).resolve()
        private_directory(private)
        temporary_parent = private / "temporary"
        temporary_parent.mkdir(mode=0o700)
        registry = private / "homes.jsonl"
        descriptor = os.open(registry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        identities = destination / "receipt-identities.jsonl"
        descriptor = os.open(identities, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        config = {
            "wheel": str(wheel),
            "temporary_parent": str(temporary_parent),
            "private_registry": str(registry),
            "receipt_identities": str(identities),
            "ledger": str(destination / "publisher-ledger.jsonl"),
            "collector_report": str(destination / "collector-report.json"),
            "worker_receipt": str(destination / "worker-receipt.json"),
        }
        configuration = private / "configuration.json"
        write_json(configuration, config)
        environment = dict(os.environ)
        environment["TMPDIR"] = str(temporary_parent)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        sys.path.insert(0, str(ROOT / "helpers"))
        from scripts.ci.installed_transition_owner import run_owned

        owned = run_owned(
            (sys.executable, "-I", "-B", str(ROOT / "workspace_worker.py"), "--config", str(configuration)),
            cwd=private,
            environment=environment,
            timeout_seconds=180,
            drain_seconds=5,
            output_limit=256 * 1024,
        )
        report["owned_descendant_boundary"] = owned.evidence
        report["worker_returncode"] = owned.returncode
        report["bounded_streams"] = {
            "stdout_bytes": len(owned.stdout),
            "stdout_sha256": digest(owned.stdout),
            "stderr_bytes": len(owned.stderr),
            "stderr_sha256": digest(owned.stderr),
            "raw_streams_exported": False,
        }
        worker_path = Path(config["worker_receipt"])
        if worker_path.is_file():
            worker = json.loads(bounded(worker_path, 1024 * 1024))
            report["worker_result"] = worker.get("result")
            report["worker_failures"] = worker.get("failures")
            report["complete_receipt_bindings_passed"] = worker.get("complete_receipt_bindings_passed")
            report["implemented_checks_passed"] = worker.get("implemented_checks_passed")
        else:
            report["failures"].append("worker_receipt_missing")
        require(owned.evidence["verified"] is True, "observational_ownership_not_verified")
        require(owned.returncode == 0 and report.get("worker_result") == "passed", "collector_attempt_failed")
    except BaseException as error:
        report["failures"].append(error_name(error))
    finally:
        if initial is not None:
            try:
                _, after = verify_installation(wheel)
                require(after == initial, "installed_members_changed")
                report["installed_members_unchanged"] = True
            except BaseException as error:
                report["failures"].append(error_name(error))
        if before is not None:
            try:
                require(source_inventory() == before, "witness_sources_changed")
                report["harness_sources_unchanged"] = True
            except BaseException as error:
                report["failures"].append(error_name(error))
        if private is not None and owned is not None and owned.evidence.get("descendants_exhausted") is True:
            try:
                report["cleanup"].update(cleanup_compact_directories(private / "homes.jsonl", private / "temporary"))
                report["cleanup"]["owned_descendants_exhausted"] = True
            except BaseException as error:
                report["failures"].append(error_name(error))
            if not report["failures"]:
                try:
                    shutil.rmtree(private)
                except BaseException as error:
                    report["failures"].append(error_name(error))
        report["cleanup"]["private_material_removed"] = private is None or not private.exists()
        report["cleanup"]["failure_material_retained"] = private is not None and private.exists()
        report["duration_seconds"] = round(time.monotonic() - started, 6)
        try:
            report["artifacts"] = {
                path.name: {"bytes": path.stat().st_size, "sha256": digest(bounded(path, 4 * 1024 * 1024))}
                for path in sorted(destination.glob("*"))
                if path.is_file()
            }
        except BaseException as error:
            report["failures"].append(error_name(error))
        report["result"] = "passed" if not report["failures"] else "failed"
        write_json(destination / "receipt.json", report)
    print(
        json.dumps(
            {
                "result": report["result"],
                "failures": report["failures"],
                "receipt_sha256": digest(bounded(destination / "receipt.json", 1024 * 1024)),
            }
        )
    )
    return int(report["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
