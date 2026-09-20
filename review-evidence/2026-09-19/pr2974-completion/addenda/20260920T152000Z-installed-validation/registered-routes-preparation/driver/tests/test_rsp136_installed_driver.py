"""Finite result accounting and first-failure preservation; no installed workload."""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import subprocess
import zipfile

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime
from scripts.ci.rsp136_installed_routes import driver


def report(label):
    if label in {"priority-controls", "priority-approval"}:
        count, attempts = (62, 62) if label == "priority-controls" else (2, 3)
        return {
            "passed": True,
            "result": {
                "validated_cases": count,
                "validated_attempts": attempts,
                "implemented_scope_passed": True,
                "qualification_complete": False,
            },
        }
    if label == "registered-aliases":
        return {
            "passed": True,
            "result": {
                "validated_cases": 29,
                "unsupported": [],
                "cases": [
                    {"harness": "fixture", "event": "fixture", "scope": "fixture", "case_id": str(i)} for i in range(29)
                ],
            },
        }
    if label == "pi-sources":
        return {
            "passed": True,
            "declared_calls": 10,
            "callback_rows": [{"returned": i % 2 == 1} for i in range(20)],
            "http_native_reference_join": True,
            "receipts": {"complete": True, "rows": {str(i): {} for i in range(10)}},
        }
    return {
        "passed": True,
        "native": {
            "passed": True,
            "cases": [{"receipt_durable": True} for _ in range(22)],
            "native_approval_consume_qualified": False,
        },
    }


@pytest.mark.parametrize(
    "label", ["priority-controls", "priority-approval", "registered-aliases", "pi-sources", "ollama"]
)
def test_complete_original_population_is_admitted_as_correctness_only(label):
    value = report(label)
    before = copy.deepcopy(value)
    result = driver.population(label, value)
    assert result["validated_cases"] > 0 and result["declared_attempts"] > 0
    assert value == before


@pytest.mark.parametrize(
    "fault",
    [
        "short_priority",
        "missing_approval_attempt",
        "duplicate_alias",
        "unsupported_alias",
        "missing_pi_return",
        "missing_pi_receipt",
        "failed_pi_join",
        "missing_ollama_receipt",
        "claimed_native_consume",
    ],
)
def test_pass_flag_cannot_admit_an_incomplete_or_overclaimed_population(fault):
    label = {
        "short_priority": "priority-controls",
        "missing_approval_attempt": "priority-approval",
        "duplicate_alias": "registered-aliases",
        "unsupported_alias": "registered-aliases",
        "missing_pi_return": "pi-sources",
        "missing_pi_receipt": "pi-sources",
        "failed_pi_join": "pi-sources",
        "missing_ollama_receipt": "ollama",
        "claimed_native_consume": "ollama",
    }[fault]
    value = report(label)
    if fault == "short_priority":
        value["result"]["validated_cases"] -= 1
    elif fault == "missing_approval_attempt":
        value["result"]["validated_attempts"] -= 1
    elif fault == "duplicate_alias":
        value["result"]["cases"][-1] = value["result"]["cases"][0]
    elif fault == "unsupported_alias":
        value["result"]["unsupported"] = [{"harness": "fixture"}]
    elif fault == "missing_pi_return":
        value["callback_rows"][-1]["returned"] = False
    elif fault == "missing_pi_receipt":
        value["receipts"]["rows"].pop("0")
    elif fault == "failed_pi_join":
        value["http_native_reference_join"] = False
    elif fault == "missing_ollama_receipt":
        value["native"]["cases"][0]["receipt_durable"] = False
    else:
        value["native"]["native_approval_consume_qualified"] = True
    with pytest.raises(RuntimeError, match="rsp136_"):
        driver.population(label, value)


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
    contract = {"cells": {"fixture": {"wheel": {"path": "fixture.whl"}, "build_source": "1" * 40}}}
    result = {}
    with pytest.raises(RuntimeError) as raised:
        driver.run(args, contract, result)
    assert raised.value is original and len(offered) == 1
    assert result["installed_after_failure"]["kind"] == "RuntimeError"
    assert result["installation_unchanged"] is False
    assert result["stages"] == [{"label": "priority-controls", "offered": True, "returned": False}]


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
    contract = {
        "product_source": product,
        "product_tree": git("rev-parse", "HEAD^{tree}"),
        "artifact_base_source": old,
        "artifact_base_tree": old_tree,
        "allowed_test_successor": [
            {"path": "tests/fixture", "before": old_blob, "after": git("rev-parse", "HEAD:tests/fixture")}
        ],
    }
    cell = {"build_source": old, "build_tree": old_tree}
    if fault == "before_blob":
        contract["allowed_test_successor"][0]["before"] = "0" * 40
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
