"""Data-only admission controls; no installed product or launcher is imported."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import types
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[1]
SPEC = importlib.util.spec_from_file_location("child_input_control", ROOT / "verify_inputs.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def admitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[argparse.Namespace, dict[str, Any]]:
    contract = json.loads((ROOT / "input-contract.json").read_text())
    manifest = json.loads((ROOT / "run-source-bindings.json").read_text())
    source, driver, artifact = (tmp_path / name for name in ("source", "driver", "artifact"))
    for folder in (source, driver, artifact):
        folder.mkdir()
    for row in contract["observer_files"]:
        target = driver / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (WORKSPACE / "priority-child-attribution-v3" / row["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob"]
        target.write_bytes(data)
    for row in manifest["files"] + contract["interpreter_preparation"]["helpers"]:
        target = source / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (WORKSPACE / "priority-child-attribution-v3" / row["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob"]
        target.write_bytes(data)
    target = driver / contract["source_bindings_path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "run-source-bindings.json", target)
    archive_path = WORKSPACE / "qualification-recovered/normal-f8-mac/arm/original.zip"
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == contract["artifact"]["archive_sha256"]
    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == {row["name"] for row in contract["artifact"]["members"]}
        for row in contract["artifact"]["members"]:
            destination = artifact / row["name"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(row["name"]) as stream, destination.open("xb") as output:
                shutil.copyfileobj(stream, output, length=65536)

    def git(root: Path, *arguments: str) -> str:
        if arguments == ("status", "--porcelain", "--untracked-files=no"):
            return ""
        if root == driver:
            if arguments == ("rev-parse", "HEAD"):
                return "d" * 40
            if arguments == ("rev-parse", "HEAD^{tree}"):
                return "e" * 40
            if arguments == ("rev-list", "--parents", "-n", "1", "HEAD"):
                return "d" * 40 + " " + contract["observer_source"]
            if arguments == ("diff", "--name-only", "HEAD^", "HEAD"):
                return "\n".join(sorted(MODULE._NEW_PATHS))
            if arguments == ("rev-parse", "HEAD~2"):
                return contract["current_pr_source"]
            if arguments == ("rev-parse", "HEAD~2^{tree}"):
                return contract["current_pr_tree"]
            if arguments == ("rev-parse", "HEAD^^{tree}"):
                return contract["observer_tree"]
            if arguments == ("rev-list", "--parents", "-n", "1", "HEAD^"):
                return contract["observer_source"] + " " + contract["current_pr_source"]
            if arguments == ("diff", "--name-only", "HEAD~2", "HEAD^"):
                return "\n".join(row["path"] for row in contract["observer_files"])
            if arguments == ("diff", "--diff-filter=DMRTUXB", "--name-only", "HEAD~2", "HEAD^"):
                return ""
            rows = contract["observer_files"]
        else:
            assert root == source
            if arguments == ("rev-parse", "HEAD"):
                return contract["selected_build_source"]
            if arguments == ("rev-parse", "HEAD^{tree}"):
                return contract["selected_tree"]
            rows = manifest["files"] + contract["interpreter_preparation"]["helpers"]
        assert arguments[0] == "rev-parse" and arguments[1].startswith("HEAD:")
        return next(row["git_blob"] for row in rows if row["path"] == arguments[1][5:])

    monkeypatch.setattr(MODULE, "_git", git)
    monkeypatch.setattr(MODULE, "sys", types.SimpleNamespace(platform="darwin", version_info=(3, 12)))
    monkeypatch.setattr(MODULE, "platform", types.SimpleNamespace(machine=lambda: "arm64"))
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    return argparse.Namespace(source=source, driver=driver, artifact=artifact), contract


def test_exact_original_members_and_source_providers(admitted: tuple[argparse.Namespace, dict[str, Any]]) -> None:
    args, contract = admitted
    result = MODULE._verify(args)
    assert len(result["artifact_members"]) == 8
    assert len(result["providers"]) == 44
    assert len(result["observer_files"]) == 35
    assert result["native_manifest"] == contract["wheel"]["manifest"]
    assert result["source_sha"] != result["product_sha_with_equal_tree"]


@pytest.mark.parametrize("kind", ["wrong_parent", "second_parent", "extra_path"])
def test_exact_new_sole_parent_and_delta_are_required(
    admitted: tuple[argparse.Namespace, dict[str, Any]], monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    args, _contract = admitted
    original = MODULE._git

    def changed(root: Path, *arguments: str) -> str:
        value = original(root, *arguments)
        if root == args.driver and arguments == ("rev-list", "--parents", "-n", "1", "HEAD"):
            if kind == "wrong_parent":
                return "d" * 40 + " " + "f" * 40
            if kind == "second_parent":
                return value + " " + "f" * 40
        if root == args.driver and arguments == ("diff", "--name-only", "HEAD^", "HEAD") and kind == "extra_path":
            return value + "\nsrc/unreviewed.py"
        return value

    monkeypatch.setattr(MODULE, "_git", changed)
    with pytest.raises(ValueError, match=r"child_input_driver_(parent|delta)"):
        MODULE._verify(args)


def test_cause_defining_provider37_is_required(admitted: tuple[argparse.Namespace, dict[str, Any]]) -> None:
    args, _contract = admitted
    path = args.source / "src/codex_plugin_scanner/guard/daemon/server_helpers_values.py"
    path.write_text("# unbound consumed-budget helper\n")
    with pytest.raises(ValueError, match="child_input_provider_bytes"):
        MODULE._verify(args)


@pytest.mark.parametrize("kind", ["wrong_parent", "changed_product", "not_addition"])
def test_observer_only_addition_scope_is_required(admitted, monkeypatch, kind):
    args, _contract = admitted
    original = MODULE._git

    def changed(root, *arguments):
        value = original(root, *arguments)
        if root == args.driver:
            if kind == "wrong_parent" and arguments == ("rev-list", "--parents", "-n", "1", "HEAD^"):
                return "d" * 40 + " " + "f" * 40
            if kind == "changed_product" and arguments == ("diff", "--name-only", "HEAD~2", "HEAD^"):
                return value + "\nsrc/changed_product.py"
            if kind == "not_addition" and arguments == (
                "diff",
                "--diff-filter=DMRTUXB",
                "--name-only",
                "HEAD~2",
                "HEAD^",
            ):
                return "src/changed_product.py"
        return value

    monkeypatch.setattr(MODULE, "_git", changed)
    with pytest.raises(ValueError, match="child_input_observer_"):
        MODULE._verify(args)


@pytest.mark.parametrize(
    "mutation", ["extra_member", "missing_member", "changed_member", "changed_provider", "changed_observer"]
)
def test_exact_admission_rejects_changed_inputs(
    admitted: tuple[argparse.Namespace, dict[str, Any]], mutation: str
) -> None:
    args, contract = admitted
    if mutation == "extra_member":
        (args.artifact / "unbound.json").write_text("{}")
    elif mutation == "missing_member":
        (args.artifact / "native-default-auto.json").unlink()
    elif mutation == "changed_member":
        (args.artifact / "native-default-auto.json").write_text("{}")
    elif mutation == "changed_provider":
        (args.source / "scripts/native_slo_priority_launchers.py").write_text("# changed\n")
    else:
        (args.driver / contract["observer_files"][0]["path"]).write_text("# changed\n")
    with pytest.raises(ValueError, match="child_input_"):
        MODULE._verify(args)


def test_duplicate_keys_refused(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    path.write_text('{"value":1,"value":2}')
    with pytest.raises(ValueError, match="duplicate_json_key"):
        MODULE._json(path)


def test_json_read_bound_refused(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    path.write_bytes(b" " * (128 * 1024 + 1))
    with pytest.raises(ValueError, match="json_bound"):
        MODULE._json(path)


def test_symlink_file_refused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("data")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="regular_file"):
        MODULE._digest(link)


def test_existing_receipt_is_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = b"existing immutable receipt\n"
    receipt = tmp_path / "input-before.json"
    receipt.write_bytes(original)
    monkeypatch.setattr(MODULE, "_verify", lambda _args: {"synthetic": True})
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "verify_inputs.py",
            "before",
            "--source",
            str(tmp_path),
            "--driver",
            str(tmp_path),
            "--artifact",
            str(tmp_path),
            "--output",
            str(tmp_path),
        ],
    )
    with pytest.raises(FileExistsError):
        MODULE.main()
    assert receipt.read_bytes() == original


@pytest.mark.parametrize("mutation", ["none", "missing", "reordered", "duplicate", "skip", "type_error"])
def test_hosted_control_gate_requires_exact_order_and_zero_errors(tmp_path, mutation):
    import xml.etree.ElementTree as ET

    body = (WORKSPACE / "qualification-recovered/child-duplicate-correction/source-controls.xml").read_bytes()
    root = ET.fromstring(body)
    suite = next(root.iter("testsuite"))
    rows = list(suite)
    cases = [item for item in rows if item.tag == "testcase"]
    if mutation == "missing":
        suite.remove(cases[-1])
    elif mutation == "reordered":
        suite.remove(cases[0])
        suite.append(cases[0])
    elif mutation == "duplicate":
        suite.remove(cases[-1])
        suite.append(cases[0])
    elif mutation == "skip":
        ET.SubElement(cases[0], "skipped")
    (tmp_path / "child-controls.xml").write_bytes(ET.tostring(root))
    types = json.loads(
        (WORKSPACE / "qualification-recovered/child-duplicate-correction/source-types.json").read_bytes()
    )
    if mutation == "type_error":
        types["summary"]["errorCount"] = 1
    (tmp_path / "child-types.json").write_text(json.dumps(types))
    if mutation == "none":
        result = MODULE._controls(tmp_path)
        assert result["passed"] is True and result["cases"] == 120
    else:
        with pytest.raises(ValueError, match="child_input_controls_"):
            MODULE._controls(tmp_path)
