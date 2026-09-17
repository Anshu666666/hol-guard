#!/usr/bin/env python3
"""Synthetic full local package-evaluation benchmark; no network or real secrets.

Run this same script with --source-root pointing at baseline or candidate source.
The public evaluator includes lockfile reads/parsing, cached signed-bundle load,
policy composition, copies, and SQLite evidence writes. Fixture creation/signing
is outside timing. The sole fixture override supplies a synthetic workspace ID;
the store has no cloud credentials, so no remote evaluation or approval wait runs.
The evaluation cache is cleared outside timing before every sample.
This source-route diagnostic does not qualify an installed package or a Rust port.
Unversioned mode measures the cached bundle API in isolation: production lockfile
evaluation resolves exact versions before calling that API. Its timing must not
be presented as full package execution latency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--dependencies", type=int, required=True)
    parser.add_argument("--bundle-size", type=int, required=True)
    parser.add_argument("--mode", choices=("absent", "exact", "unversioned", "deny"), required=True)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.dependencies < 1 or args.bundle_size < 2 or args.samples < 1:
        parser.error("positive dependencies/samples and at least two bundle records are required")
    root = args.source_root.resolve()
    sys.path[:0] = [str(root / "src"), str(root)]
    from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
        evaluate_cached_supply_chain_bundle,
        load_supply_chain_bundle_response,
    )
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_guard_supply_chain_bundle import _generate_key_pair, _sign_bundle_response
    from tests.test_guard_supply_chain_evaluator import (
        WORKSPACE_ID,
        _artifact_for_targets,
        _bundle_response,
        _package,
    )

    # Unexpected networking fails the benchmark instead of contaminating local CPU/latency.
    network_attempts = []

    def reject_network(*_args, **_kwargs):
        network_attempts.append(True)
        raise AssertionError("The synthetic local package benchmark attempted network access")

    socket.create_connection = reject_network
    socket.socket.connect = reject_network
    socket.socket.connect_ex = reject_network
    packages = [
        _package(
            ecosystem="npm",
            name="anchor" if index == 0 else f"item-{index - 1}",
            version="1.0.0",
            default_action="block",
        )
        for index in range(args.bundle_size)
    ]
    response = _bundle_response(packages=packages)
    if args.mode == "deny":
        response["bundle"]["emergencyDenylist"] = [
            {
                "ecosystem": "npm",
                "name": "item-0",
                "namespace": None,
                "reason": "known_malware",
                "recommendedFixVersion": "2.0.0",
            }
        ]
        private_key, _ = _generate_key_pair()
        response = _sign_bundle_response(response["bundle"], private_key_pem=private_key)
    entries = {}
    for index in range(args.dependencies):
        name = (
            f"absent-{index}"
            if args.mode == "absent"
            else ("item-0" if args.mode == "deny" else f"item-{index % (args.bundle_size - 1)}")
        )
        entries[f"node_modules/holder/node_modules/path-{index}"] = {"name": name, "version": "1.0.0"}
    lockfile = json.dumps({"lockfileVersion": 3, "packages": entries}, separators=(",", ":")).encode()
    target = "anchor@1.0.0"
    wall, cpu, semantic = [], [], []
    with tempfile.TemporaryDirectory(prefix="guard-package-bench-") as temporary:
        directory = Path(temporary)
        workspace = directory / "workspace"
        workspace.mkdir()
        (workspace / "package-lock.json").write_bytes(lockfile)
        store = GuardStore(directory / "guard")
        store.get_cloud_workspace_id = lambda: WORKSPACE_ID
        store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
        parsed_response = load_supply_chain_bundle_response(response)
        for _sample in range(args.samples):
            artifact = _artifact_for_targets(target, lockfile_paths=("package-lock.json",))
            with store._connect() as connection:
                connection.execute("delete from guard_supply_chain_eval_cache")
            print(json.dumps({"event": "measurement_started", "sample": _sample}), flush=True)
            cpu_started = time.process_time_ns()
            started = time.perf_counter_ns()
            if args.mode == "unversioned":
                decisions = tuple(
                    evaluate_cached_supply_chain_bundle(
                        parsed_response,
                        package_name=f"item-{index % (args.bundle_size - 1)}",
                        package_version=None,
                        ecosystem="npm",
                        now=1779148800.0,
                    )
                    for index in range(args.dependencies)
                )
                wall.append((time.perf_counter_ns() - started) / 1_000_000)
                cpu.append((time.process_time_ns() - cpu_started) / 1_000_000)
                if any(decision.action != "block" for decision in decisions):
                    raise AssertionError("Unversioned bundle lookup lost a known-malware decision")
                semantic.append(
                    hashlib.sha256(
                        json.dumps([asdict(item) for item in decisions], sort_keys=True).encode()
                    ).hexdigest()
                )
                continue
            result = evaluate_package_request_artifact(
                artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
            )
            wall.append((time.perf_counter_ns() - started) / 1_000_000)
            cpu.append((time.process_time_ns() - cpu_started) / 1_000_000)
            expected_count = 1 if args.mode == "absent" else args.dependencies + 1
            if result.decision != "block" or len(result.packages) != expected_count:
                raise AssertionError(f"Unexpected route output: {result.decision}, {len(result.packages)} packages")
            if any(package.get("lockfileParseComplete") is False for package in result.packages):
                raise AssertionError("Benchmark produced an incomplete parse")
            semantic.append(
                hashlib.sha256(
                    json.dumps(
                        {
                            "decision": result.decision,
                            "policy_action": result.policy_action,
                            "packages": result.packages,
                            "reasons": result.reasons,
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest()
            )
    if network_attempts:
        raise AssertionError("The synthetic local package benchmark attempted network access")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip())
    output = {
        "schema": "guard-package-local-benchmark-v1",
        "source_commit": commit,
        "source_dirty": dirty,
        "source_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD", "--", "src"], cwd=root)
        ).hexdigest(),
        "evaluation_cache": "cleared before each sample, outside timing",
        "route": "evaluate_cached_supply_chain_bundle batch"
        if args.mode == "unversioned"
        else "evaluate_package_request_artifact",
        "installed_artifact": False,
        "dependencies": args.dependencies,
        "bundle_size": args.bundle_size,
        "mode": args.mode,
        "samples": args.samples,
        "lockfile_bytes": len(lockfile),
        "corpus_sha256": hashlib.sha256(lockfile + json.dumps(response["bundle"], sort_keys=True).encode()).hexdigest(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "wall_ms": wall,
        "cpu_ms": cpu,
        "cpu_scope": "current evaluator process; child process CPU is not sampled",
        "wall_median_ms": statistics.median(wall),
        "cpu_median_ms": statistics.median(cpu),
        "semantic_sha256": semantic,
        "limitations": [
            "Synthetic local source route; no launcher/startup/network/approval wait",
            "Small samples are diagnostic observations, not reliable tail quantiles",
            "Shared host contention must be excluded before release qualification",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: output[key]
                for key in (
                    "source_commit",
                    "dependencies",
                    "bundle_size",
                    "mode",
                    "samples",
                    "wall_median_ms",
                    "cpu_median_ms",
                )
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
