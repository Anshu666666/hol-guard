"""Model the pinned action's actual singleton extraction and sealed pair roots."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts.native_slo_pair_aggregate import aggregate_pairs
from scripts.native_slo_pair_plan import PLATFORMS
from scripts.native_slo_surface_tail_aggregate import aggregate, pair_name
from scripts.native_slo_surface_tail_contract import route_for
from tests.native_slo_pair_support import ROOT, bundle_fixture, pair_fixture
from tests.native_slo_surface_tail_support import pair


def _download(kind):
    jobs = yaml.safe_load((ROOT / ".github/workflows/native-performance-qualification.yml").read_text())["jobs"]
    job = jobs["aggregate" if kind == "priority" else "nonpriority-tail-aggregation"]
    mode = "mode" if kind == "priority" else "tails_mode"
    downloads = [
        step
        for step in job["steps"]
        if "actions/download-artifact@" in step.get("uses", "") and step["with"]["path"] != "wheel-bundle"
    ]
    assert len(downloads) == 2
    smoke = next(step for step in downloads if step["if"] == f"always() && needs.plan.outputs.{mode} == 'smoke'")
    full = next(step for step in downloads if step["if"] == f"always() && needs.plan.outputs.{mode} == 'qualification'")
    assert set(smoke["with"]) == {"name", "path"}
    assert set(full["with"]) == {"pattern", "path", "merge-multiple"}
    assert full["with"]["merge-multiple"] is False
    assert smoke["uses"] == full["uses"] == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    return smoke["with"]


def _render(value, target):
    expressions = {
        "matrix.target": target,
        "github.run_id": "17",
        "github.run_attempt": "2",
        "needs.plan.outputs.tails_selection": "cursor.beforeShellExecution.global",
    }
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda match: expressions[match[1]], value)


@pytest.mark.parametrize("target", [platform["target"] for platform in PLATFORMS])
@pytest.mark.parametrize("kind", ["priority", "tail"])
def test_each_smoke_target_keeps_the_exact_artifact_root(kind, target):
    download = _download(kind)
    name, path = (_render(download[key], target) for key in ("name", "path"))
    expected = (
        f"pair-{target}-0-17-2"
        if kind == "priority"
        else pair_name(
            route_for("cursor.beforeShellExecution.global"), {"target": target, "run_id": 17, "run_attempt": 2}, 0
        )
    )
    assert name == expected
    assert Path(path).name == expected
    assert Path(path).parent == Path("retained-pairs" if kind == "priority" else "tail-pairs")


@pytest.mark.parametrize("kind", ["priority", "tail"])
@pytest.mark.parametrize("failed_arm", [None, "candidate"])
def test_real_sealed_pair_survives_singleton_extraction_without_promoting_failure(tmp_path, kind, failed_arm):
    bundle_root = tmp_path / "bundle"
    bundle = bundle_fixture(bundle_root)
    source = tmp_path / "offered"
    route = route_for("cursor.beforeShellExecution.global")
    if kind == "priority":
        context, _, _ = pair_fixture(source, bundle_root, bundle, failed_arm=failed_arm)
    else:
        context, _, _ = pair(source, bundle_root, bundle, route, failed_arm=failed_arm)
    context.pop("pair_index")
    download = _download(kind)
    destination = tmp_path / _render(download["path"], context["target"])
    archive = tmp_path / "artifact.zip"
    # Only the actual uploaded public+encrypted shape; no plaintext numeric data.
    with zipfile.ZipFile(archive, "w") as stream:
        for path in source.rglob("*"):
            if path.is_file() and path.relative_to(source).parts[0] != "private_samples":
                stream.write(path, path.relative_to(source))
    with zipfile.ZipFile(archive) as stream:
        # The pinned action extracts a sole artifact straight into with.path.
        stream.extractall(destination)
    if kind == "priority":
        result = aggregate_pairs(pair_roots=destination.parent, bundle_root=bundle_root, context=context)
    else:
        result = aggregate(roots=destination.parent, bundle=bundle, context=context, route=route)
    assert result["collection_complete"] is (failed_arm is None)
    assert result["qualification_complete"] is False and result["program_qualification_complete"] is False
    assert result["pairs"][0]["archive_complete"] is True
    assert result["pairs"][0]["arms"]["candidate"] == ("completed" if failed_arm is None else "failed")
