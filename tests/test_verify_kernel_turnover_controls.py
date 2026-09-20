from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.qualification_turnover_contract import read_worker_report

_PATH = Path(__file__).resolve().parents[1] / "scripts/ci/verify_kernel_turnover_controls.py"
_SPEC = importlib.util.spec_from_file_location("turnover_finite_driver_under_test", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
driver = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(driver)


def complete() -> dict[str, Any]:
    return {
        "schema": "hol-guard.kernel-turnover-host-controller.v1",
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
            "schema": "hol-guard.finite-turnover-resource-control.v1",
            "admitted": True,
            "admission_refusal": None,
            "passed": True,
            "original_workload_executed": False,
            "facts": {
                "planned_children": 256,
                "planned_waves": 16,
                "concurrency": 16,
                "sampler_interval_seconds": 0.1,
                "offered": 256,
                "returned": 256,
                "exit_codes": [0] * 256,
                "waves_completed": 16,
                "locally_reaped": 256,
                "local_cleanup_complete": True,
                "only_worker_live_after": True,
                "failure_stage": None,
                "lifetime_cpu": {"usage_seconds": 1.0, "user_seconds": 0.5, "system_seconds": 0.5},
                "sampled_resources": {
                    "live_inventory_scope": "protected_kernel_group",
                    "live_inventory_identity": "pid_and_creation_time_before_and_after_each_sample",
                    "instantaneous_peak_proven": False,
                    "samples": 33,
                    "unavailable_samples": 0,
                    "baseline": {k: 100 for k in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")},
                    "peak": {k: 123 for k in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")},
                    "metric_samples": {
                        k: 33 for k in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
                    },
                    "metric_minimum_met": {
                        k: True for k in ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
                    },
                    "unavailable_metrics": {},
                },
            },
        },
    }


def test_original_finite_result_admits_without_modification() -> None:
    value = complete()
    before = json.dumps(value)
    driver.admit_result(value, read_worker_report)
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
        driver.admit_result(report, read_worker_report)


@pytest.mark.parametrize("change", ["missing", "over_count", "failed", "not_admitted"])
def test_actual_control_population_and_admission_are_required(change: str) -> None:
    report = complete()
    row = report["worker_report"]
    if change == "missing":
        row["facts"]["sampled_resources"]["peak"]["private_bytes"] = None
    elif change == "over_count":
        row["facts"]["sampled_resources"]["metric_samples"]["private_bytes"] = 34
    elif change == "failed":
        row["facts"]["local_cleanup_complete"] = False
    else:
        row["admitted"] = False
    with pytest.raises(ValueError):
        driver.admit_result(report, read_worker_report)


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


def test_actual_driver_selects_only_turnover_controller_after_untimed_gates(
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
    (driver_root / "scripts/ci/kernel_turnover_contract.json").write_text(json.dumps(contract))
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
            assert argv[-2:] == ["--control-kind", "turnover"]
            assert argv[5] == str(source / "scripts/ci/qualification_cpu_controller.py")
            assert timeout == 45
            (destination / "finite-controller.stdout").write_text(json.dumps(complete()))
            (destination / "finite-controller.stderr").write_bytes(b"")
        elif label == "host-facts":
            assert argv[-1] == "scripts/ci/qualification_host_facts.py" and timeout == 30
            (destination / "host-facts.stdout").write_text(
                json.dumps(
                    {
                        "schema": "hol-guard.pre-campaign-host-facts.v1",
                        "campaign_admission": False,
                        "all_declared_facts_available": False,
                        "unavailable": {"governors": "unexposed"},
                    }
                )
            )
        elif label == "types":
            (destination / "types.stdout").write_text('{"summary":{"errorCount":0}}')
        return 0

    monkeypatch.setattr(driver, "load_reader", lambda _source: read_worker_report)
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
        "host-facts",
        "finite-controller",
        "snapshot",
    ]
    result = json.loads((output / "RESULT.json").read_text())
    assert result["finite_controller_attempts"] == 1 and result["original_workload_executed"] is False


def test_bound_reader_is_actual_selected_source_without_product_import() -> None:
    root = Path(__file__).resolve().parents[1]
    reader = driver.load_reader(root)
    body = json.dumps(complete()["worker_report"]).encode()
    assert reader(body) == read_worker_report(body)
    value = complete()
    value["worker_report"]["facts"]["sampled_resources"]["peak"]["private_bytes"] = None
    with pytest.raises(ValueError):
        driver.admit_result(value, reader)
