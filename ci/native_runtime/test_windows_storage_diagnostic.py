"""Finite driver and admission controls; no downloads or Guard/native workload."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import zipfile
from contextlib import AbstractContextManager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_windows_storage_exceptions as driver  # pyright: ignore[reportImplicitRelativeImport]
import windows_storage_artifact as artifact  # pyright: ignore[reportImplicitRelativeImport]


class ObserverDouble(AbstractContextManager["ObserverDouble"]):
    def __init__(self, refusal: BaseException | None = None) -> None:
        self.refusal = refusal
        self.entered = self.exited = 0

    def __enter__(self) -> ObserverDouble:
        super().__enter__()
        self.entered += 1
        if self.refusal is not None:
            raise self.refusal
        return self

    def __exit__(self, *_args: object) -> None:
        self.exited += 1

    def snapshot(self) -> dict[str, Any]:
        return {"complete": self.refusal is None, "original_exception_not_suppressed": True}


@pytest.mark.parametrize("exit_code", [0, 7])
def test_exactly_one_probe_call_and_original_return(exit_code: int) -> None:
    calls = []
    reports = []
    observer = ObserverDouble()

    def probe() -> int:
        calls.append("original")
        return exit_code

    assert driver.run_once(probe, observer, reports.append) == exit_code
    assert calls == ["original"] and observer.entered == observer.exited == 1
    assert reports[0]["probe_invocations"] == 1 and reports[0]["probe_exit_code"] == exit_code


@pytest.mark.parametrize("write_failure", [False, True])
def test_original_probe_exception_identity_survives_evidence_failure(write_failure: bool) -> None:
    original = OSError(13, "private original")
    calls = []

    def probe() -> int:
        calls.append("original")
        raise original

    def finish(report: dict[str, Any]) -> None:
        assert report["probe_invocations"] == 1 and report["probe_raised"] is True
        if write_failure:
            raise RuntimeError("private evidence failure")

    with pytest.raises(OSError) as caught:
        driver.run_once(probe, ObserverDouble(), finish)
    assert caught.value is original and calls == ["original"]


def test_observer_refusal_never_starts_probe() -> None:
    refusal = RuntimeError("fixed refusal")
    reports = []
    with pytest.raises(RuntimeError) as caught:
        driver.run_once(lambda: pytest.fail("unexpected workload"), ObserverDouble(refusal), reports.append)
    assert caught.value is refusal and reports[0]["probe_invocations"] == 0
    assert reports[0]["probe_raised"] is False and reports[0]["observed_scope_raised"] is True


def test_successful_probe_does_not_hide_evidence_write_failure() -> None:
    original = OSError("write failed")

    def finish(_report: dict[str, Any]) -> None:
        raise original

    with pytest.raises(OSError) as caught:
        driver.run_once(lambda: 0, ObserverDouble(), finish)
    assert caught.value is original


def metadata() -> dict[str, Any]:
    return {
        "id": artifact.ARTIFACT_ID,
        "name": "hol-guard-native-wheel-windows-x64",
        "size_in_bytes": artifact.ARCHIVE_BYTES,
        "digest": "sha256:" + artifact.ARCHIVE_SHA256,
        "expired": False,
        "workflow_run": {"id": artifact.RUN_ID, "head_sha": artifact.SOURCE},
    }


@pytest.mark.parametrize(
    "field,value",
    [("id", 1), ("name", "different"), ("size_in_bytes", 1), ("digest", "sha256:" + "0" * 64), ("expired", True)],
)
def test_original_artifact_metadata_cannot_be_substituted(field: str, value: Any) -> None:
    correct = metadata()
    artifact.verify_metadata(correct)
    correct[field] = value
    with pytest.raises(artifact.BindingError):
        artifact.verify_metadata(correct)


@pytest.mark.parametrize("field,value", [("id", 1), ("head_sha", "0" * 40)])
def test_original_run_and_source_are_required(field: str, value: Any) -> None:
    candidate = metadata()
    candidate["workflow_run"][field] = value
    with pytest.raises(artifact.BindingError, match="artifact_source"):
        artifact.verify_metadata(candidate)


def test_failed_archive_transfer_is_retained_without_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        assert args[:5] == ["gh", "api", "--hostname", "github.com", args[4]]
        if len(calls) == 1:
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata()).encode(), b"")
        kwargs["stdout"].write(b"partial archive")
        return subprocess.CompletedProcess(args, 1, b"", b"private transport error")

    monkeypatch.setattr(artifact.subprocess, "run", invoke)
    with pytest.raises(artifact.BindingError, match="artifact_download"):
        artifact.gh_download(tmp_path / "archive", tmp_path / "evidence")
    assert len(calls) == 2
    assert (tmp_path / "archive" / f"{artifact.ARTIFACT_ID}.zip").read_bytes() == b"partial archive"
    receipt = (tmp_path / "evidence/artifact-download.json").read_text()
    assert "private transport error" not in receipt
    assert json.loads(receipt)["gh_invocations_for_archive"] == 1


def test_transfer_timeout_keeps_partial_bytes_and_original_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    original = subprocess.TimeoutExpired(["gh", "api", "fixed-original-artifact"], 60)

    def invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        if len(calls) == 1:
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata()).encode(), b"")
        kwargs["stdout"].write(b"partial original")
        raise original

    monkeypatch.setattr(artifact.subprocess, "run", invoke)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        artifact.gh_download(tmp_path / "archive", tmp_path / "evidence")
    assert caught.value is original and len(calls) == 2
    assert (tmp_path / "archive" / f"{artifact.ARTIFACT_ID}.zip").read_bytes() == b"partial original"
    report = json.loads((tmp_path / "evidence/artifact-download.json").read_text())
    assert report["transfer_raised"] is True and report["gh_exit_code"] is None
    assert report["gh_invocations_for_archive"] == 1 and report["workload_invocations"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "identity_source",
        "identity_missing",
        "identity_duplicate",
        "identity_failed",
        "lock_missing",
        "lock_duplicate",
        "lock_unreleased",
        "lock_wrong_outcome",
        "lock_non_boolean",
    ],
)
def test_original_control_cases_and_outcomes_cannot_be_substituted(tmp_path: Path, mutation: str) -> None:
    identity: dict[str, Any] = {
        "schema": "hol-guard.installed-runtime-identity.v1",
        "build_sha": artifact.BUILD,
        "runtime_sha256": artifact.RUNTIME_SHA256,
        "manifest_sha256": artifact.MANIFEST_SHA256,
        "cases": [
            {"case": name, "result": "replaced" if name == "live_replacement" else "passed"}
            for name in driver.IDENTITY_CASES
        ],
    }
    locks: dict[str, Any] = {
        "schema": "hol-guard.installed-command-control-lock.v1",
        "cases": [
            {"parent_shared": parent, "child_shared": child, "child_acquired": parent and child, "released": True}
            for parent, child in ((True, True), (True, False), (False, True), (False, False))
        ],
    }

    def save() -> None:
        (tmp_path / "native-installed-identity.json").write_text(json.dumps(identity))
        (tmp_path / "native-installed-control-lock.json").write_text(json.dumps(locks))

    save()
    assert driver.prior_controls(tmp_path)["control_lock_cases"] == 4
    if mutation == "identity_source":
        identity["build_sha"] = "0" * 40
    elif mutation == "identity_missing":
        identity["cases"].pop()
    elif mutation == "identity_duplicate":
        identity["cases"][-1] = dict(identity["cases"][0])
    elif mutation == "identity_failed":
        identity["cases"][0]["result"] = "failed"
    elif mutation == "lock_missing":
        locks["cases"].pop()
    elif mutation == "lock_duplicate":
        locks["cases"][-1] = dict(locks["cases"][0])
    elif mutation == "lock_unreleased":
        locks["cases"][0]["released"] = False
    elif mutation == "lock_wrong_outcome":
        locks["cases"][1]["child_acquired"] = True
    else:
        locks["cases"][0]["released"] = 1
    save()
    with pytest.raises(artifact.BindingError):
        driver.prior_controls(tmp_path)


def test_zip_path_rejection_precedes_extraction() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../outside.whl", b"untrusted")
    with zipfile.ZipFile(stream) as archive, pytest.raises(artifact.BindingError, match="archive_path"):
        artifact.safe_members(archive)


def test_corrupt_archive_is_rejected_before_wheel_parse(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"corrupt")
    with pytest.raises(artifact.BindingError, match="archive_bytes"):
        artifact.verified_wheel(path)


def test_installed_same_size_mutation_and_extra_file_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "site-packages/codex_plugin_scanner"
    package.mkdir(parents=True)
    content = package / "__init__.py"
    content.write_bytes(b"original")
    distribution = SimpleNamespace(read_text=lambda _name: None, locate_file=lambda _name: package)
    monkeypatch.setattr(artifact.importlib.metadata, "distribution", lambda _name: distribution)
    monkeypatch.setattr(artifact.sys, "prefix", str(tmp_path))
    expected = {artifact.PREFIX + "__init__.py": artifact.sha(b"original")}
    assert artifact.installed_inventory(expected)[1] == expected
    content.write_bytes(b"modified")
    with pytest.raises(artifact.BindingError, match="installed_bytes"):
        artifact.installed_inventory(expected)
    content.write_bytes(b"original")
    (package / "extra.py").write_bytes(b"extra")
    with pytest.raises(artifact.BindingError, match="installed_bytes"):
        artifact.installed_inventory(expected)


def test_editable_distribution_refused_before_workload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    distribution = SimpleNamespace(read_text=lambda _name: '{"dir_info":{"editable":true}}')
    monkeypatch.setattr(artifact.importlib.metadata, "distribution", lambda _name: distribution)
    with pytest.raises(artifact.BindingError, match="editable_install"):
        artifact.installed_inventory({})


def test_source_commit_tree_and_same_size_drift_are_rejected(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(tmp_path), *args], capture_output=True, check=True)
        return result.stdout.decode().strip()

    git("init", "--quiet")
    source = tmp_path / "probe.py"
    source.write_bytes(b"original")
    git("add", "probe.py")
    git(
        "-c",
        "user.name=Finite control",
        "-c",
        "user.email=finite@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    assert artifact.checkout_inventory(tmp_path, commit, tree) == {"probe.py": artifact.sha(b"original")}
    with pytest.raises(artifact.BindingError, match="checkout_commit"):
        artifact.checkout_inventory(tmp_path, "0" * 40, tree)
    with pytest.raises(artifact.BindingError, match="checkout_tree"):
        artifact.checkout_inventory(tmp_path, commit, "0" * 40)
    metadata = source.stat()
    source.write_bytes(b"modified")
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    with pytest.raises(artifact.BindingError, match="checkout_bytes"):
        artifact.checkout_inventory(tmp_path, commit, tree)
    source.write_bytes(b"original")
    (tmp_path / "unexpected.py").write_text("pass")
    with pytest.raises(artifact.BindingError, match="checkout_untracked"):
        artifact.checkout_inventory(tmp_path, commit, tree)


def test_unsupported_platform_refuses_before_binding_or_guard_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(driver.sys, "platform", "linux")
    monkeypatch.setattr(driver, "checkout_inventory", lambda *_args: pytest.fail("source admission should not start"))
    before = set(sys.modules)
    with pytest.raises(artifact.BindingError, match="platform_unsupported"):
        driver.run_diagnostic(argparse.Namespace())
    assert not {name for name in set(sys.modules) - before if name.startswith("codex_plugin_scanner")}


@pytest.mark.parametrize("outcome", ["success", "nonzero", "exception"])
def test_full_driver_forwards_one_original_probe_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    # Admission and workload doubles execute the actual driver without any
    # product module import, native process, SQLite access or network request.
    events = []
    original = OSError(13, "private original operation")
    package = tmp_path / "site-packages/codex_plugin_scanner"
    before_modules = set(sys.modules)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner", SimpleNamespace(__file__=str(package / "__init__.py")))
    monkeypatch.setattr(
        driver,
        "sys",
        SimpleNamespace(
            platform="win32", version_info=(3, 12, 10), flags=SimpleNamespace(isolated=1), stderr=sys.stderr
        ),
    )
    monkeypatch.setattr(
        driver,
        "platform",
        SimpleNamespace(
            python_implementation=lambda: "CPython", python_version=lambda: "3.12.10", machine=lambda: "AMD64"
        ),
    )
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setattr(driver, "checkout_inventory", lambda *_args: {"fixed-source": "fixed-digest"})
    monkeypatch.setattr(driver, "verified_wheel", lambda _path: b"fixed-wheel")
    monkeypatch.setattr(driver, "package_map", lambda *_args: {"fixed-package": "fixed-digest"})
    monkeypatch.setattr(driver, "installed_inventory", lambda *_args: (package, {"fixed-package": "fixed-digest"}))
    monkeypatch.setattr(driver, "prior_controls", lambda *_args: {"finite_control_double": True})
    monkeypatch.setattr(driver.importlib.metadata, "version", lambda _name: "finite-control-double")

    def probe(*, json_path: Path) -> int:
        events.append(("original_probe", json_path.name))
        if outcome == "exception":
            raise original
        return 7 if outcome == "nonzero" else 0

    monkeypatch.setattr(driver, "load_original_probe", lambda _root: SimpleNamespace(main=probe))
    observer = ObserverDouble()
    monkeypatch.setattr(driver, "bind_installed", lambda *_args: observer)
    options = argparse.Namespace(
        source=tmp_path / "source",
        driver_source=tmp_path / "driver",
        driver_commit="fixed-driver",
        archive=tmp_path / "archive.zip",
        output=tmp_path / "evidence",
    )
    if outcome == "exception":
        with pytest.raises(OSError) as caught:
            driver.run_diagnostic(options)
        assert caught.value is original
    else:
        assert driver.run_diagnostic(options) == (7 if outcome == "nonzero" else 0)
    assert events == [("original_probe", "native-default-auto.json")]
    assert observer.entered == observer.exited == 1
    report = json.loads((options.output / "windows-storage-observation.json").read_text())
    assert report["probe_invocations"] == 1 and report["probe_raised"] == (outcome == "exception")
    assert report["observer_can_create_50ms_timeouts"] and not report["observer_perturbation_quantified"]
    assert not report["observer_units_are_product_committed_counters"] and not report["qualification_complete"]
    assert "private original operation" not in json.dumps(report)
    assert not {name for name in set(sys.modules) - before_modules if name.startswith("codex_plugin_scanner.")}
