from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts/ci/verify_kernel_resource_controls.py"
_SPEC = importlib.util.spec_from_file_location("resource_finite_driver_under_test", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
driver = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(driver)


def complete() -> dict[str, Any]:
    return {
        "schema": "hol-guard.kernel-resource-host-controller.v1",
        "passed": True,
        "worker_launched": True,
        "cleanup_complete": True,
        "stream_capture_complete": True,
        "original_workload_executed": False,
        "worker_exit": 0,
        "fault": None,
        "collection_failure": None,
        "stderr_retained_bytes": 0,
        "worker_report": {
            "admitted": True,
            "passed": True,
            "controls": [{"name": "finite", "passed": True, "error": None}],
        },
    }


def test_original_finite_result_admits_without_modification() -> None:
    value = complete()
    before = json.dumps(value)
    driver.admit_result(value, ["finite"])
    assert json.dumps(value) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("cleanup_complete", False),
        ("stream_capture_complete", False),
        ("worker_exit", False),
        ("worker_exit", -9),
        ("original_workload_executed", True),
        ("fault", "os"),
        ("stderr_retained_bytes", 1),
    ],
)
def test_incomplete_or_failed_original_result_is_not_promoted(field: str, value: Any) -> None:
    report = complete()
    report[field] = value
    with pytest.raises(ValueError):
        driver.admit_result(report, ["finite"])


@pytest.mark.parametrize("change", ["missing", "duplicate", "failed", "not_admitted"])
def test_actual_control_population_and_admission_are_required(change: str) -> None:
    report = complete()
    row = report["worker_report"]
    if change == "missing":
        row["controls"] = []
    elif change == "duplicate":
        row["controls"] *= 2
    elif change == "failed":
        row["controls"][0]["error"] = "assertion"
    else:
        row["admitted"] = False
    with pytest.raises(ValueError):
        driver.admit_result(report, ["finite"])


@pytest.mark.parametrize("tail", ["", "<skipped/>", "<failure/>"])
def test_ordered_original_junit_does_not_count_skips_as_passes(tmp_path: Path, tail: str) -> None:
    xml = tmp_path / "actual.xml"
    xml.write_text(
        '<testsuites><testsuite><testcase classname="actual" name="finite">'
        + tail
        + "</testcase></testsuite></testsuites>"
    )
    if tail:
        with pytest.raises(ValueError):
            driver.verify_junit(xml, ["actual::finite"])
    else:
        driver.verify_junit(xml, ["actual::finite"])
        with pytest.raises(ValueError):
            driver.verify_junit(xml, ["actual::other"])


def test_duplicate_json_refused_and_frozen_receipt_cannot_be_replaced(tmp_path: Path) -> None:
    path = tmp_path / "original.json"
    path.write_text('{"passed":true,"passed":false}')
    with pytest.raises(ValueError, match="duplicate"):
        driver.read_json(path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        driver.write(path, {"passed": True})
    assert path.read_bytes() == before


def test_preparation_timeout_preserves_original_failure_and_declared_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = TimeoutError("source-control-only")

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise original

    monkeypatch.setattr(driver.subprocess, "run", refuse)
    with pytest.raises(TimeoutError) as captured:
        driver.command(["finite-source-command"], tmp_path, tmp_path, "finite", 2)
    assert captured.value is original
    assert json.loads((tmp_path / "finite.command.json").read_text()) == {
        "argv": ["finite-source-command"],
        "timeout_seconds": 2,
    }
    assert json.loads((tmp_path / "finite.status.json").read_text()) == {
        "returncode": None,
        "failure_kind": "TimeoutError",
    }


def test_actual_driver_selects_only_resource_controller_after_untimed_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, driver_root, output = (tmp_path / name for name in ("source", "driver", "output"))
    source.mkdir()
    (driver_root / "scripts/ci").mkdir(parents=True)
    source_sha, driver_sha, base_sha = "a" * 40, "b" * 40, "c" * 40
    contract = {
        "base_sha": base_sha,
        "source_delta_paths": ["source.py"],
        "driver_paths": ["driver.py"],
        "source_paths": [{"path": "source.py"}],
        "providers": [],
        "ordered_nodes": ["exact::node"],
        "control_names": ["finite"],
    }
    (driver_root / "scripts/ci/kernel_resource_contract.json").write_text(json.dumps(contract))
    monkeypatch.setattr(driver.platform, "system", lambda: "Linux")
    monkeypatch.setattr(driver.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(driver.sys, "version_info", (3, 12, 14))
    monkeypatch.setattr(driver.sys, "prefix", "/finite/venv")
    monkeypatch.setattr(driver.sys, "base_prefix", "/finite/base")
    monkeypatch.setattr(driver.os, "getresuid", lambda: (1001, 1001, 1001))
    monkeypatch.setattr(driver.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(driver.os, "getuid", lambda: 1001)
    monkeypatch.setattr(driver.os, "getgid", lambda: 1001)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/hol-guard")
    monkeypatch.setenv("GITHUB_SHA", driver_sha)

    def git(root: Path, *args: str) -> str:
        if args == ("rev-parse", "HEAD"):
            return source_sha if root == source else driver_sha
        if args == ("show", "-s", "--format=%P", "HEAD"):
            return base_sha if root == source else source_sha
        if args == ("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"):
            return "source.py" if root == source else "driver.py"
        assert args == ("rev-parse", "HEAD^{tree}")
        return "d" * 40

    events = []
    monkeypatch.setattr(driver, "git", git)
    monkeypatch.setattr(driver, "interpreter", lambda *_args, **_kwargs: {})

    def snapshot(_root, _rows):
        events.append("snapshot")
        return ["unchanged"]

    def command(argv, _cwd, destination, label, timeout):
        events.append(label)
        if label == "finite-controller":
            assert argv[:5] == ["sudo", "-n", "/usr/bin/python3", "-I", "-S"]
            assert argv[-2:] == ["--control-kind", "resources"]
            assert argv[5] == str(source / "scripts/ci/qualification_cpu_controller.py")
            assert timeout == 45
            (destination / "finite-controller.stdout").write_text(json.dumps(complete()))
            (destination / "finite-controller.stderr").write_bytes(b"")
        elif label == "types":
            (destination / "types.stdout").write_text('{"summary":{"errorCount":0}}')
        return 0

    monkeypatch.setattr(driver, "snapshot", snapshot)
    monkeypatch.setattr(driver, "command", command)
    monkeypatch.setattr(driver, "verify_junit", lambda _path, nodes: events.append(tuple(nodes)))
    assert driver.run(source, driver_root, output, source_sha) is True
    assert events == [
        "snapshot",
        "ruff",
        "format",
        "types",
        "controls",
        ("exact::node",),
        "snapshot",
        "finite-controller",
        "snapshot",
    ]
    result = json.loads((output / "RESULT.json").read_text())
    assert result["finite_controller_offers"] == 1 and result["original_workload_executed"] is False
