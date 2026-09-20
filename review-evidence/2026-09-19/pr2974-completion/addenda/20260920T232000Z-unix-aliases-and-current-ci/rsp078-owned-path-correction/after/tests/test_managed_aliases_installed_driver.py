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
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime
from scripts.ci.managed_aliases_installed import driver


def report(workspace: Path) -> dict[str, Any]:
    from scripts.native_slo_managed_aliases import (
        PERMISSION_RESPONSE,
        daemon_cases,
        delivery_projection,
        permission_cases,
        watch_cases,
    )
    from scripts.native_slo_registered_surfaces_run import delivery_expectation

    cases = daemon_cases(workspace) + permission_cases(workspace, kind="permission_no_daemon") + watch_cases(workspace)
    rows = []
    for case in cases:
        row: dict[str, Any] = {
            "label": case.label,
            "harness": case.harness,
            "event": case.event,
            "scope": case.scope,
            "kind": case.kind,
            "status": "completed",
            "stage": "complete",
            "registration_unchanged": True,
            "native_evaluation": case.kind == "evaluated",
            "timed_out": False,
            "containment_failed": False,
            "output_limit_exceeded": False,
            "returncode": 0,
        }
        for name in ("registration", "registered_argv", "registered_executable", "input", "stdout", "stderr"):
            row[name + "_sha256"] = hashlib.sha256(b"").hexdigest()
        if case.kind == "evaluated":
            assert case.normal_case is not None and case.normal_case.native_expected is not None
            delivery, row["returncode"] = delivery_expectation(case.normal_case)
            row["delivery"] = dict(delivery.fields)
            row["delivery"].update(dict.fromkeys(delivery.nonempty_fields, "Original fixture reason."))
            row["evidence"] = {"native_result": dict(case.normal_case.native_expected.fields)}
            row["route"] = "native_resident"
        elif case.kind in {"permission_daemon", "permission_no_daemon"}:
            row["delivery"] = dict(PERMISSION_RESPONSE)
            if case.kind == "permission_daemon":
                row["evidence"] = {"native_result": None}
                row["route"] = "native_fail_safe"
        else:
            row["delivery"] = {"permission": "allow"} if case.event == "beforeShellExecution" else {}
        if case.kind in {"evaluated", "permission_daemon"}:
            row["evidence"].update(
                native_call_count=1,
                native_completed_call_count=1,
                setup={
                    "fault_scope": "none",
                    "python_oracle_disabled": True,
                    "isolated_store": True,
                    "policy_ack_current": True,
                    "effective_policy_allow": True,
                },
            )
            row["routes_before"] = {row["route"]: 0}
            row["routes_after"] = {row["route"]: 1}
        else:
            row["daemon_endpoint_before"] = {"daemon-state.json": False, "daemon-auth-token": False}
            row["daemon_endpoint_after"] = dict(row["daemon_endpoint_before"])
            row["absence_scope"] = "fresh_owned_home_no_daemon_started_endpoint_files_absent"
            row["posture"] = "watch" if case.kind == "watch_no_daemon" else "protected"
        row["delivery"] = delivery_projection(case, row["delivery"], row["returncode"], "")
        rows.append(row)
    return {
        "passed": True,
        "declared_cases": 14,
        "rows": rows,
        "daemon_cleanup_contained": True,
        "no_daemon_cleanup_contained": True,
        "performance_qualified": False,
        "native_approval_consume_qualified": False,
        "external_host_application_executed": False,
        "platform_scope": "POSIX",
        "identity": {"installed_package_sha256": "a" * 64},
        "installed_package_after_sha256": "a" * 64,
    }


def test_complete_registered_population_is_admitted_as_correctness_only(tmp_path):
    value = report(tmp_path)
    before = copy.deepcopy(value)
    assert driver.population("managed-aliases", value) == {
        "validated_cases": 14,
        "declared_attempts": 14,
        "native_evaluated": 4,
        "daemon_permission_unavailable": 4,
        "daemon_absent": 6,
    }
    assert value == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "kind",
        "native-claim",
        "native-result",
        "edge-count",
        "route",
        "route-delta",
        "oracle",
        "policy",
        "permission-allow",
        "permission-message",
        "permission-exit",
        "cursor-exit",
        "endpoint",
        "posture",
        "invented-witness",
        "timeout",
        "containment",
        "output",
        "hash",
        "stderr",
        "registration",
        "cleanup",
        "host",
        "performance",
        "approval",
        "windows",
        "package",
        "declared",
    ],
)
def test_pass_flag_cannot_admit_incomplete_or_overclaimed_population(fault, tmp_path):
    value = report(tmp_path)
    first, permission, absent = value["rows"][0], value["rows"][4], value["rows"][8]
    if fault == "missing":
        value["rows"].pop()
    elif fault == "duplicate":
        value["rows"][-1] = copy.deepcopy(value["rows"][-2])
    elif fault == "kind":
        first["kind"] = "permission_daemon"
    elif fault == "native-claim":
        permission["native_evaluation"] = True
    elif fault == "native-result":
        permission["evidence"]["native_result"] = {"policy_action": "allow"}
    elif fault == "edge-count":
        permission["evidence"]["native_call_count"] = 0
    elif fault == "route":
        permission["route"] = "native_resident"
    elif fault == "route-delta":
        first["routes_after"]["native_resident"] = 2
    elif fault == "oracle":
        first["evidence"]["setup"]["python_oracle_disabled"] = False
    elif fault == "policy":
        permission["evidence"]["setup"]["effective_policy_allow"] = False
    elif fault == "permission-allow":
        permission["delivery"]["fields"]["behavior"] = "allow"
    elif fault == "permission-message":
        permission["delivery"]["fields"]["message"] = "changed"
    elif fault == "permission-exit":
        permission["returncode"] = 2
    elif fault == "cursor-exit":
        first["returncode"] = 0
    elif fault == "endpoint":
        absent["daemon_endpoint_after"]["daemon-auth-token"] = True
    elif fault == "posture":
        absent["posture"] = "watch"
    elif fault == "invented-witness":
        absent["evidence"] = {}
    elif fault == "timeout":
        first["timed_out"] = True
    elif fault == "containment":
        first["containment_failed"] = True
    elif fault == "output":
        first["output_limit_exceeded"] = True
    elif fault == "hash":
        first["registered_executable_sha256"] = "bad"
    elif fault == "stderr":
        first["stderr_sha256"] = hashlib.sha256(b"error").hexdigest()
    elif fault == "registration":
        first["registration_unchanged"] = False
    elif fault == "cleanup":
        value["daemon_cleanup_contained"] = False
    elif fault == "host":
        value["external_host_application_executed"] = True
    elif fault == "performance":
        value["performance_qualified"] = True
    elif fault == "approval":
        value["native_approval_consume_qualified"] = True
    elif fault == "windows":
        value["platform_scope"] = "Windows"
    elif fault == "package":
        value["installed_package_after_sha256"] = "b" * 64
    elif fault == "declared":
        value["declared_cases"] = 13
    with pytest.raises((RuntimeError, AssertionError)):
        driver.population("managed-aliases", value)


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
    assert result["stages"] == [{"label": "managed-aliases", "offered": True, "returned": False}]


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


def test_managed_only_offers_one_exact_registered_cohort(tmp_path, monkeypatch):
    identity = {"identity": "synthetic"}
    offered = []
    (tmp_path / "provision.json").write_text(json.dumps({"passed": True, "installed_after": identity}))
    monkeypatch.setattr(driver, "installed", lambda *args: identity)
    monkeypatch.setattr(driver, "ROOT", tmp_path)

    def process(command, **kwargs):
        output = Path(command[command.index("--output") + 1])
        label = output.stem
        offered.append(label)
        output.write_text(json.dumps(report(tmp_path)))
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", process)
    args = argparse.Namespace(output=tmp_path, artifact=tmp_path, cell="fixture")
    contract: dict[str, Any] = {"cells": {"fixture": {"wheel": {"path": "fixture.whl"}, "build_source": "1" * 40}}}
    result = {}
    driver.run(args, contract, result)
    assert offered == ["managed-aliases"]
    assert sum(row["population"]["declared_attempts"] for row in result["stages"]) == 14
    assert result["installation_unchanged"] is True


def test_unadmitted_contract_stops_before_platform_git_or_artifact_access(monkeypatch):
    monkeypatch.setattr(driver, "git", lambda *args: pytest.fail("unadmitted contract reached Git"))
    with pytest.raises(RuntimeError, match="input_contract_unadmitted"):
        driver.binding(argparse.Namespace(), {"ready": False})


@pytest.mark.parametrize("fault", [False, True], ids=["accepted", "refused"])
def test_population_owns_private_catalog_and_cleans_after_result(tmp_path, monkeypatch, fault):
    from scripts import native_slo_managed_aliases as aliases

    value = report(tmp_path / "modeled")
    before = copy.deepcopy(value)
    if fault:
        value["rows"][0]["returncode"] = 0
        before = copy.deepcopy(value)
    original = aliases.daemon_cases
    observed = []
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def owned_cases(workspace):
        # Refuse an unowned path before the original factory can write, even as root.
        assert workspace.is_relative_to(tmp_path)
        assert workspace.is_dir() and workspace.stat().st_mode & 0o777 == 0o700
        observed.append(workspace)
        return original(workspace)

    monkeypatch.setattr(aliases, "daemon_cases", owned_cases)
    if fault:
        with pytest.raises(AssertionError, match="managed_alias_delivery_projection"):
            driver.population("managed-aliases", value)
    else:
        result = driver.population("managed-aliases", value)
        assert result["validated_cases"] == 14
        assert str(tmp_path) not in json.dumps(result)
    assert len(observed) == 1 and not observed[0].exists()
    assert value == before
