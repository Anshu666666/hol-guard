from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_dependency_identity as dependencies
from scripts import native_slo_pair_install as installer
from scripts.native_slo_pair_io import canonical
from scripts.native_slo_qualification_bundle import export_bundle, load_bundle
from tests.native_slo_pair_support import SHA, TARGET, bundle_fixture


@pytest.mark.parametrize("mutation", ["wheel", "requirements", "baseline_sha", "candidate_sha", "path", "duplicate"])
def test_bundle_rejects_artifact_input_or_identity_substitution(tmp_path, mutation):
    root = tmp_path / "bundle"
    value = bundle_fixture(root)
    if mutation in {"wheel", "requirements"}:
        path = root / "baseline" / (value["arms"]["baseline"]["wheel"] if mutation == "wheel" else "requirements.txt")
        with path.open("ab") as stream:
            stream.write(b"tampered")
    elif mutation == "duplicate":
        content = (root / "bundle.json").read_text()
        (root / "bundle.json").write_text('{"schema":"duplicate",' + content[1:])
    else:
        if mutation == "path":
            value["arms"]["baseline"]["wheel"] = "../hol_guard-escape.whl"
        else:
            value["arms"]["baseline" if mutation == "baseline_sha" else "candidate"]["build_sha"] = "c" * 40
        (root / "bundle.json").write_bytes(canonical(value))
    with pytest.raises(ValueError):
        load_bundle(root, target=TARGET, candidate_sha=SHA)


def test_export_uses_frozen_hashes_and_candidate_psutil_for_both_arms(tmp_path):
    existing = tmp_path / "original"
    value = bundle_fixture(existing)
    sources = {arm: tmp_path / f"source-{arm}" for arm in value["arms"]}
    lock = '[[package]]\nname="psutil"\nversion="7.2.2"\nwheels=[{hash="sha256:' + "f" * 64 + '"}]\n'
    for source in sources.values():
        source.mkdir()
        (source / "uv.lock").write_text(lock)
    calls = []

    def export(argv, *, cwd):
        calls.append((argv, cwd))
        Path(argv[argv.index("--output-file") + 1]).write_text("fixture==1.0 --hash=sha256:" + "a" * 64 + "\n")
        return ""

    metadata = {
        arm: {
            "source_sha": info["build_sha"],
            "runtime_sha256": info["runtime_sha256"],
            "package_version": info["package_version"],
            "python": info["python_version"],
            "dependency_versions_sha256": info["dependency_versions_sha256"],
            "target": TARGET,
        }
        for arm, info in value["arms"].items()
    }
    root = tmp_path / "export"
    export_bundle(
        destination=root,
        sources=sources,
        wheels={arm: existing / arm / info["wheel"] for arm, info in value["arms"].items()},
        metadata=metadata,
        run=export,
    )
    assert len(calls) == 2
    for argv, _ in calls:
        assert "--frozen" in argv and "--no-emit-project" in argv
        assert argv[argv.index("--no-emit-package") + 1] == "psutil" and "--no-hashes" not in argv
    for arm in value["arms"]:
        requirements = (root / arm / "requirements.txt").read_text()
        assert requirements.count("psutil==7.2.2") == 1 and "--hash=sha256:" + "f" * 64 in requirements
    assert (
        load_bundle(root, target=TARGET, candidate_sha=SHA)["arms"]["baseline"]["build_sha"]
        == value["arms"]["baseline"]["build_sha"]
    )


def test_verified_installs_require_hashes_exact_inventory_and_no_project_source(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    value = bundle_fixture(root)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="e" * 64 + "\n", returncode=0)

    prepared = []

    def prepare(python, *, environment_root):
        assert calls[-1][:2] == ["uv", "venv"]
        assert python == installer.interpreter(environment_root.parent, environment_root.name)
        prepared.append(environment_root.name)
        return {"private_copy": True}

    monkeypatch.setattr(installer, "prepare_private_interpreter", prepare)
    monkeypatch.setattr(installer.subprocess, "run", run)
    destination = tmp_path / "environments"
    installer.install_bundle(root, destination, target=TARGET, candidate_sha=SHA)
    assert len(calls) == 8 and prepared == ["baseline", "candidate"]
    for offset, arm in ((0, "baseline"), (4, "candidate")):
        assert calls[offset][0:2] == ["uv", "venv"]
        assert "--require-hashes" in calls[offset + 1]
        assert "--no-deps" in calls[offset + 2]
        assert calls[offset + 2][-1] == str(root / arm / value["arms"][arm]["wheel"])
        assert calls[offset + 3][1] == "-I"
    with pytest.raises(ValueError, match="destination"):
        installer.install_bundle(root, installer._ROOT / "unsafe-environment", target=TARGET, candidate_sha=SHA)


def test_changed_installed_dependency_stops_before_sampling(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "prepare_private_interpreter", lambda *args, **kwargs: {})
    root = tmp_path / "bundle"
    bundle_fixture(root)
    monkeypatch.setattr(
        installer.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout="wrong", returncode=0)
    )
    with pytest.raises(ValueError, match="dependency_mismatch"):
        installer.install_bundle(root, tmp_path / "environments", target=TARGET, candidate_sha=SHA)


@pytest.mark.parametrize("index", range(5))
def test_pair_command_preserves_five_run_plan_and_owned_hour_per_arm(tmp_path, index):
    bundle = bundle_fixture(tmp_path / "bundle")
    args = argparse.Namespace(
        action="pair",
        environments=tmp_path / "env",
        bundle=tmp_path / "bundle",
        output=tmp_path / "out",
        mode="qualification",
        pair_index=index,
        target=TARGET,
        candidate_sha=SHA,
        run_id=17,
        run_attempt=2,
    )
    command = installer.command(args, bundle)
    assert command[command.index("--runs") + 1] == "5"
    assert command[command.index("--pair-index") + 1] == str(index)
    assert command[command.index("--block-timeout-seconds") + 1] == "3600"
    assert command[command.index("--baseline-python") + 1] != command[command.index("--candidate-python") + 1]
    assert "native_loopback_resolver.py" in command[1]


def test_dependency_inventory_is_order_independent_and_rejects_duplicates(monkeypatch):
    first = SimpleNamespace(metadata={"Name": "Example_Package"}, version="1.0")
    second = SimpleNamespace(metadata={"Name": "another"}, version="2.0")
    project = SimpleNamespace(metadata={"Name": "hol-guard"}, version="3.2")
    monkeypatch.setattr(dependencies.importlib.metadata, "distributions", lambda: [first, second, project])
    digest = dependencies.dependency_versions_digest()
    monkeypatch.setattr(dependencies.importlib.metadata, "distributions", lambda: [second, first])
    assert dependencies.dependency_versions_digest() == digest
    monkeypatch.setattr(dependencies.importlib.metadata, "distributions", lambda: [first, first])
    with pytest.raises(ValueError, match="ambiguous"):
        dependencies.dependency_versions_digest()


@pytest.mark.parametrize("name", ["native_slo_pair_install.py", "build_native_qualification_artifacts.py"])
def test_cli_help_bootstraps_without_site_packages(name):
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-I", "-S", str(installer._ROOT / "scripts" / name), "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and "--candidate" in result.stdout


def test_worker_adds_its_actual_inventory_and_runner_identity_before_publication(tmp_path, monkeypatch, capsys):
    import sys

    from scripts import native_slo_qualification_run, qualify_guard_native
    from scripts.native_slo_qualification import sampling_plan
    from tests.native_slo_pair_support import block_fixture

    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["runtime"].pop("dependency_versions_sha256")
    for key in ("runner_image", "runner_image_os"):
        report["hardware"].pop(key)
    monkeypatch.setattr(native_slo_qualification_run, "run_block", lambda **kwargs: report)
    monkeypatch.setenv("ImageVersion", "20260907.300.1")
    monkeypatch.setenv("ImageOS", "ubuntu24")
    monkeypatch.setattr(
        sys,
        "argv",
        ["qualify", "--worker", "--mode", "smoke", "--runs", "1", "--raw-file", str(tmp_path / "numbers.json")],
    )
    expected = dependencies.dependency_versions_digest()
    assert qualify_guard_native.main() == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["runtime"]["dependency_versions_sha256"] == expected
    assert emitted["hardware"]["runner_image"] == "20260907.300.1"
    assert emitted["hardware"]["runner_image_os"] == "ubuntu24"
