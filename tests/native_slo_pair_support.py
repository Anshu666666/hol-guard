"""Synthetic immutable wheels and numeric pairs for orchestration tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from functools import lru_cache
from pathlib import Path

from scripts.native_slo_artifact import wheel_package_digest
from scripts.native_slo_pair_archive import archive_pair
from scripts.native_slo_pair_io import canonical, digest_file, write_public
from scripts.native_slo_pair_record import PairRecorder, expected_counts
from scripts.native_slo_qualification import confidence_summary, paired_order
from scripts.native_slo_qualification_bundle import BASELINE_SHA, BUNDLE_SCHEMA

SHA = "b" * 40
TARGET = "x86_64-unknown-linux-musl"
ROOT = Path(__file__).resolve().parents[1]
RECIPIENT = "d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb"


def bundle_fixture(root: Path):
    root.mkdir()
    arms = {}
    for arm in ("baseline", "candidate"):
        folder = root / arm
        folder.mkdir()
        wheel = folder / "hol_guard-1.0-py3-none-linux_x86_64.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("codex_plugin_scanner/__init__.py", arm)
        req = folder / "requirements.txt"
        req.write_text("fixture==1.0 --hash=sha256:" + "a" * 64 + "\n")
        arms[arm] = {
            "wheel": wheel.name,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "package_sha256": wheel_package_digest(wheel),
            "requirements_sha256": hashlib.sha256(req.read_bytes()).hexdigest(),
            "lock_sha256": "a" * 64,
            "build_sha": BASELINE_SHA if arm == "baseline" else SHA,
            "runtime_sha256": ("c" if arm == "baseline" else "d") * 64,
            "package_version": "1.0",
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "dependency_versions_sha256": "e" * 64,
        }
    value = {"schema": BUNDLE_SCHEMA, "target": TARGET, "arms": arms}
    (root / "bundle.json").write_bytes(canonical(value) + b"\n")
    return value


def context_fixture(bundle_root: Path, *, index=0, mode="smoke"):
    return {
        "build_sha": SHA,
        "target": TARGET,
        "run_id": 17,
        "run_attempt": 2,
        "pair_index": index,
        "runs": 5 if mode == "qualification" else 1,
        "mode": mode,
        "bundle_sha256": digest_file(bundle_root / "bundle.json", 64 * 1024),
    }


@lru_cache(maxsize=128)
def summary_fixture(count, latency):
    return confidence_summary([latency] * count)


def block_fixture(bundle, arm, plan):
    expected = bundle["arms"][arm]
    counts = expected_counts(plan)
    value = 10.0 if arm == "baseline" else 7.0
    raw = {key: [value] * count for key, count in counts.items()}
    report = {
        "schema": "hol-guard.native-qualification-block.v1",
        "artifact_sha256": expected["wheel_sha256"],
        "runtime": {
            "target": "x86_64-linux",
            "package_origin": "installed",
            "mode": "auto",
            "build_sha": expected["build_sha"],
            "runtime_sha256": expected["runtime_sha256"],
            "installed_package_sha256": expected["package_sha256"],
            "package_record_sha256": expected["package_sha256"],
            "package_version": expected["package_version"],
            "python_version": expected["python_version"],
            "dependency_versions_sha256": expected["dependency_versions_sha256"],
        },
        "corpus_digest": "f" * 64,
        "common_workload_digest": "f" * 64,
        "semantic_scope_digest": ("a" if arm == "baseline" else "b") * 64,
        "hardware": {
            "platform": TARGET,
            "cpu_model": "synthetic",
            "cpu_count": 4,
            "effective_cpu_count": 4,
            "ram_bytes": 16_000_000_000,
            "os_release": "synthetic",
            "runner_image": "synthetic-1",
            "runner_image_os": "synthetic",
        },
        "resources": {"sample_minimum_met": True},
        "measurements": {key: summary_fixture(count, value) for key, count in counts.items()},
    }
    return report, raw


def pair_fixture(root: Path, bundle_root: Path, bundle, *, index=0, mode="smoke", failed_arm=None, archive=True):
    root.mkdir(parents=True)
    public, private = root / "aggregate", root / "private_samples"
    public.mkdir()
    private.mkdir(mode=0o700)
    context = context_fixture(bundle_root, index=index, mode=mode)
    recorder = PairRecorder(public=public, private=private, context=context, bundle=bundle)
    with recorder:
        for arm in paired_order(index):
            recorder.offer(arm)
            if arm == failed_arm:
                write_public(
                    public / f"{index:02d}-{arm}-failure.json",
                    {"schema": "hol-guard.native-qualification-failure.v1", "reason": "synthetic_failure"},
                )
                recorder.failed(arm)
                continue
            report, raw = block_fixture(bundle, arm, recorder.plan)
            numeric = private / f"{index:02d}-{arm}.json"
            numeric.write_text(json.dumps(raw))
            write_public(public / f"{index:02d}-{arm}.json", report)
            recorder.completed(arm, report, numeric)
    args = argparse.Namespace(
        bundle=bundle_root,
        pair_root=root,
        candidate_sha=SHA,
        target=TARGET,
        run_id=17,
        run_attempt=2,
        pair_index=index,
        runs=context["runs"],
        mode=mode,
        recipient_id=RECIPIENT,
        public_key=ROOT / "docs/guard/rust-performance/qualification-recipient.pem",
    )
    if archive:
        write_public(root / "archive-receipt.json", archive_pair(args))
    return context, recorder, args
