"""Synthetic companion reports: no resident, installed process or timing claim."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.native_slo_evidence_files import atomic_exclusive
from scripts.native_slo_pair_io import canonical, write_public
from scripts.native_slo_qualification import paired_order, sampling_plan
from scripts.native_slo_surface_tail_contract import plan, workload
from scripts.native_slo_surface_tail_pair import archive_pair
from scripts.native_slo_surface_tail_record import TailRecorder
from tests.native_slo_pair_support import ROOT, SHA, TARGET, block_fixture, context_fixture, summary_fixture


def block(bundle, arm, route, mode="smoke"):
    base, _ = block_fixture(bundle, arm, sampling_plan(runs=1, qualification=False))
    values = [10.0 if arm == "baseline" else 7.0] * plan(mode)["samples_per_arm"]
    result = {key: base[key] for key in ("runtime", "hardware", "artifact_sha256")}
    result["runtime"].update(
        runtime_version="1.0",
        protocol_version=3,
        architecture="x86_64",
        system="Linux",
        rule_digest="e" * 64,
        reference_reader_capability="absent",
    )
    result["hardware"].update(
        platform="linux-x64",
        load_average=None,
        power_mode="unrecorded",
        rust_toolchain="record_in_build_artifact",
        build_flags="record_in_build_artifact",
    )
    result.update(
        {
            "schema": "hol-guard.nonpriority-tail-block.v1",
            **workload(route, mode),
            "boundary": "INSTALLED_LAUNCHER",
            "mode": mode,
            "measurements": {route.series: summary_fixture(len(values), values[0])},
            "preflight_cases": route.preflight_count,
            "validated_cases": route.preflight_count + len(values),
            "errors": 0,
            "native_route": "native_resident",
            "process_startup_included": True,
            "stdout_exit_checked": True,
            "full_host_activation": False,
            "resident_cold_measured": False,
            "delivery": "allow",
            "model_action": "not_applicable",
            "exit_code": 0,
            "registration_sha256": "f" * 64,
            "registration_artifacts": {},
            "matchers_read_back": 0,
            "matched_tool": "event_slot",
            "qualification_complete": False,
            "program_qualification_complete": False,
        }
    )
    return result, {route.series: values}


def pair(root: Path, bundle_root: Path, bundle, route, *, index=0, mode="smoke", failed_arm=None, archive=True):
    (root / "aggregate").mkdir(parents=True)
    (root / "private_samples").mkdir(mode=0o700)
    context = context_fixture(bundle_root, index=index, mode=mode)
    recorder = TailRecorder(root=root, context=context, route=route, bundle=bundle)
    for arm in paired_order(index):
        recorder.offer(arm)
        if arm == failed_arm:
            write_public(root / f"aggregate/{index:02d}-{arm}-failure.json", {"reason": "synthetic_failure"})
            recorder.failed(arm)
        else:
            report, raw = block(bundle, arm, route, mode)
            numeric = root / f"private_samples/{index:02d}-{arm}.json"
            atomic_exclusive(numeric, canonical(raw))
            recorder.completed(arm, report, numeric)
    recorder.finish()
    args = argparse.Namespace(
        bundle=bundle_root,
        output=root,
        target=TARGET,
        candidate_sha=SHA,
        route=route.identifier,
        pair_index=index,
        run_id=17,
        run_attempt=2,
        mode=mode,
        public_key=ROOT / "docs/guard/rust-performance/qualification-recipient.pem",
    )
    if archive:
        write_public(root / "archive-receipt.json", archive_pair(args))
    return context, recorder, args
