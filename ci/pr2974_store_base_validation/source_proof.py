"""Execute the original mechanical proof and recheck the strict formatter bridge."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from common import BASELINE, CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from source_contract import verify_preparation
from format_bridge import prove


def run_source_proof(run: Run) -> None:
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules), "Proof must precede product imports"
    before, packet = verify_preparation(CONFIG, HERE, SOURCE)
    root = SCRATCH / "mechanical-source-input"
    root.mkdir(mode=0o700)
    for relative, record in before["files"].items():
        path = root / relative
        assert path.is_relative_to(root)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(record["content"].encode("utf-8"))
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(name, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    passed = run.command("store-base-mechanical-source-inverse", [
        sys.executable, "-I", "-B", str(HERE / "assert_store_base_partition.py"),
        "--baseline", str(BASELINE / "src/codex_plugin_scanner/guard/store_base.py"),
        "--candidate-root", str(root), "--manifest", str(HERE / "store-base-source-manifest.json"),
        "--output", str(REPORT / "store-base-source-inverse.json"),
    ], cwd=SCRATCH, timeout=180, env=env)
    run.require(passed, "The exact original StoreBase mechanical source proof failed")
    inverse = json.loads((REPORT / "store-base-source-inverse.json").read_bytes())
    run.require(inverse["function_and_class_asts_match_precise_forward_transform"], "Definition inverse missing")
    run.require(len(inverse["global_loads"]) == 201 and len(inverse["metadata_definitions"]) == 117,
                "StoreBase original inventory changed")
    bridges = []
    for relative, record in before["files"].items():
        old = record["content"].encode("utf-8")
        current = (SOURCE / relative).read_bytes()
        result = prove(old, current, relative, REPORT / "fresh-format-bridges")
        result["physical_lines"] = len(current.splitlines())
        result["within_500_physical_lines"] = result["physical_lines"] <= 500
        bridges.append(result)
        run.require(result["passed"] and result["within_500_physical_lines"],
                    "Strict full-file formatter bridge failed: " + relative)
        assert (root / relative).read_bytes() == old
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    write_json(REPORT / "store-base-source-contract.json", {
        "baseline": CONFIG["baseline_sha"], "reviewed_unformatted_source": CONFIG["unformatted_source_sha"],
        "formatted_source": CONFIG["source_sha"], "formatted_tree": CONFIG["source_tree"],
        "actual_original_mechanical_inverse_passed": True, "moved_definitions": 57,
        "live_global_loads": 201, "metadata_definitions": 117,
        "all_nine_fresh_strict_format_bridges": bridges,
        "original_formatter_packet_sha256": CONFIG["format_packet_sha256"],
        "source_manifest_sha256": sha256((HERE / "store-base-source-manifest.json").read_bytes()),
        "product_imports": [], "collection_or_test_execution": False, "passed": True,
        "qualification_complete": False,
    })
