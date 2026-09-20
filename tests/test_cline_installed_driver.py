"""Finite result accounting and first-failure preservation; no installed workload."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import subprocess
import zipfile
from typing import Any

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime
from scripts.ci.cline_installed_driver import driver


@pytest.mark.parametrize(
    "fault",
    (None, "missing_case", "duplicate_case", "delivery", "cleanup", "profile", "oracle", "timing", "reclassify"),
)
def test_original_four_cases_and_complete_semantics_are_required(fault):
    from scripts.ci.cline_witness.run import CASE_IDS

    value: dict[str, Any] = {
        "passed": True,
        "declared_cases": list(CASE_IDS),
        "performance_qualified": False,
        "historical_failed_run_reclassified": False,
        "attempts": [
            {
                "case_id": case,
                "passed": True,
                "cleanup_faults": [],
                "original_delivery": {"stdout_checked": True, "exit_checked": True},
                "child": {
                    "observation_complete": True,
                    "profile_restored": True,
                    "faults": [],
                    "original_edge": {
                        "original_validator_called": True,
                        "original_native_validation_passed": True,
                        "complete": True,
                    },
                },
            }
            for case in CASE_IDS
        ],
    }
    if fault == "missing_case":
        value["attempts"].pop()
    elif fault == "duplicate_case":
        value["attempts"][-1] = value["attempts"][0]
    elif fault == "delivery":
        value["attempts"][0]["original_delivery"]["exit_checked"] = False
    elif fault == "cleanup":
        value["attempts"][0]["cleanup_faults"] = ["owned_file_cleanup_failed"]
    elif fault == "profile":
        value["attempts"][0]["child"]["profile_restored"] = False
    elif fault == "oracle":
        del value["attempts"][0]["child"]["original_edge"]["original_native_validation_passed"]
    elif fault == "timing":
        value["performance_qualified"] = True
    elif fault == "reclassify":
        value["historical_failed_run_reclassified"] = True
    if fault:
        with pytest.raises(RuntimeError, match="rsp136_"):
            driver.population("cline-witness", value)
    else:
        assert driver.population("cline-witness", value) == {"validated_cases": 4, "declared_attempts": 4}


def test_original_process_error_survives_separate_after_inventory_failure(tmp_path, monkeypatch):
    original = RuntimeError("original fixture command failure")
    identity = {"identity": "synthetic"}
    offered = []
    calls = 0

    def installed(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return identity
        raise RuntimeError("after inventory failure")

    def process(*args, **kwargs):
        offered.append(args)
        raise original

    (tmp_path / "provision.json").write_text(json.dumps({"passed": True, "installed_after": identity}))
    monkeypatch.setattr(driver, "installed", installed)
    monkeypatch.setattr(driver, "ROOT", tmp_path)
    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", process)
    args = argparse.Namespace(output=tmp_path, artifact=tmp_path, cell="fixture")
    contract: dict[str, Any] = {"cells": {"fixture": {"wheel": {"path": "fixture.whl"}, "build_source": "1" * 40}}}
    result = {}
    with pytest.raises(RuntimeError) as raised:
        driver.run(args, contract, result)
    assert raised.value is original and len(offered) == 1
    assert result["installed_after_failure"]["kind"] == "RuntimeError"
    assert result["installation_unchanged"] is False
    assert result["stages"] == [{"label": "cline-witness", "offered": True, "returned": False}]


@pytest.mark.parametrize("fault", [None, "provider", "extra_test", "before_blob", "build_tree"])
def test_retained_build_requires_exact_test_delta_and_unchanged_providers(tmp_path, monkeypatch, fault):
    root, built = tmp_path / "source", tmp_path / "built"
    root.mkdir()
    environment = dict(
        os.environ,
        GIT_AUTHOR_NAME="Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], env=environment).decode().strip()

    git("init", "-q")
    for directory in ("src", "rust", "scripts", "contracts", "contributions", "tests"):
        (root / directory).mkdir()
        (root / directory / "fixture").write_text("original\n")
    git("add", ".")
    git("commit", "-qm", "original build")
    old, old_tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    old_blob = git("rev-parse", "HEAD:tests/fixture")
    subprocess.run(["git", "clone", "-q", str(root), str(built)], check=True)
    (root / "tests/fixture").write_text("corrected test\n")
    if fault == "provider":
        (root / "src/fixture").write_text("changed implementation\n")
    if fault == "extra_test":
        (root / "tests/unreviewed").write_text("other test\n")
    git("add", ".")
    git("commit", "-qm", "test-only successor")
    product = git("rev-parse", "HEAD")
    contract: dict[str, Any] = {
        "product_source": product,
        "product_tree": git("rev-parse", "HEAD^{tree}"),
        "artifact_base_source": old,
        "artifact_base_tree": old_tree,
        "allowed_nonprovider_successor": [
            {"path": "tests/fixture", "before": old_blob, "after": git("rev-parse", "HEAD:tests/fixture")}
        ],
    }
    cell = {"build_source": old, "build_tree": old_tree}
    if fault == "before_blob":
        contract["allowed_nonprovider_successor"][0]["before"] = "0" * 40
    if fault == "build_tree":
        cell["build_tree"] = "0" * 40
    monkeypatch.setattr(driver, "ROOT", root)
    if fault:
        with pytest.raises(RuntimeError, match="rsp136_"):
            driver.artifact_source_binding(built, contract, cell)
    else:
        result = driver.artifact_source_binding(built, contract, cell)
        assert result["build_source"] == old and result["build_tree"] == old_tree
        assert set(result["unchanged_provider_trees"]) == {"src", "rust", "scripts", "contracts", "contributions"}


@pytest.mark.parametrize("fault", [None, "python", "asset", "metadata", "record", "symlink", "duplicate", "unsafe"])
def test_original_wheel_members_and_record_keep_distinct_tamper_proofs(tmp_path, fault):
    from scripts.installed_canary_proof import InstalledCanaryError, verify_installed_record

    root, wheel = tmp_path / "installation", tmp_path / "candidate.whl"
    rows = {
        "codex_plugin_scanner/__init__.py": b"VALUE = 1\n",
        "codex_plugin_scanner/asset.json": b'{"version":1}\n',
        "hol_guard-3.0.1.dist-info/METADATA": b"Name: hol-guard\nVersion: 3.0.1\n",
        "hol_guard-3.0.1.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
    }
    record = "hol_guard-3.0.1.dist-info/RECORD"
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    for name, data in rows.items():
        writer.writerow(
            (name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="), len(data))
        )
    writer.writerow((record, "", ""))
    rows[record] = stream.getvalue().encode()
    for name, data in rows.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in rows.items():
            archive.writestr(name, data)
        if fault == "duplicate":
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr("codex_plugin_scanner/__init__.py", rows["codex_plugin_scanner/__init__.py"])
        elif fault == "unsafe":
            archive.writestr("../escape", b"outside")
    changed = {
        "python": "codex_plugin_scanner/__init__.py",
        "asset": "codex_plugin_scanner/asset.json",
        "metadata": "hol_guard-3.0.1.dist-info/METADATA",
        "record": record,
    }
    if fault in changed:
        (root / changed[fault]).write_bytes(b"modified\n")
    if fault == "symlink":
        path = root / "codex_plugin_scanner/__init__.py"
        path.unlink()
        target = tmp_path / "same-bytes.py"
        target.write_bytes(rows["codex_plugin_scanner/__init__.py"])
        path.symlink_to(target)
    distribution = importlib.metadata.PathDistribution(root / "hol_guard-3.0.1.dist-info")
    if fault == "record":
        assert driver.wheel_members(distribution, wheel) == 4
        with pytest.raises((ValueError, InstalledCanaryError)):
            verify_installed_record(distribution)
    elif fault:
        with pytest.raises(RuntimeError, match="rsp136_"):
            driver.wheel_members(distribution, wheel)
    else:
        cache = root / "codex_plugin_scanner/__pycache__/__init__.cpython-312.pyc"
        cache.parent.mkdir()
        cache.write_bytes(b"explicitly outside original-member and RECORD scope")
        assert driver.wheel_members(distribution, wheel) == 4
        assert verify_installed_record(distribution)[1] == 4
        assert cache.read_bytes() == b"explicitly outside original-member and RECORD scope"
