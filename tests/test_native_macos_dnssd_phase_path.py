"""Exercise admission, capture accounting and report binding without native lookup claims."""

from __future__ import annotations

import copy
import hashlib
import json
import sys

import pytest

from scripts.ci import native_macos_dnssd_phase_path as collector
from tests.test_native_macos_dnssd_phase import BINARY, BRIDGE, RUNTIME, records, wire
from tests.test_native_macos_dnssd_python_path import capture
from tests.test_native_macos_dnssd_python_path import reports as base_reports


def reports(monkeypatch):
    prepared, prior, python = base_reports(monkeypatch)
    prepared["source"]["sha256"][str(collector.CHILD.relative_to(collector.original.ROOT))] = RUNTIME[
        collector.EXTRA_RUNTIME_KEY
    ]
    prepared["tools"]["machine"] = "arm64"
    dnssd = collector.original._base() | {
        "status": "experiment_finished",
        "stage": "complete",
        "source_before": prepared["source"],
        "tools_before": prepared["tools"],
        "source_unchanged": True,
        "tools_unchanged": True,
        "runtime_unchanged": True,
        "bridge_unchanged": True,
        "original_report_unchanged": True,
        "python_report_unchanged": True,
        "original_report_sha256": "f" * 64,
        "python_report_sha256": "e" * 64,
        "runtime_before": {key: value for key, value in RUNTIME.items() if key != collector.EXTRA_RUNTIME_KEY},
        "rows": [
            {"mode": mode, "capture": {"pid": 300 + index, "direct_child_reaped": True}, "lookup_passed": False}
            for index, mode in enumerate(collector.MODES)
        ],
    }
    return prepared, prior, python, dnssd


def test_all_failed_previous_lookups_remain_failed_while_bound_children_can_be_admitted(monkeypatch):
    cohort = reports(monkeypatch)
    assert collector.previous_admission(*cohort, "f" * 64, "e" * 64) is None
    assert all(report["diagnostic_passed"] is False for report in cohort[1:])


@pytest.mark.parametrize(
    "cohort,index", [(1, i) for i in range(5)] + [(2, i) for i in range(4)] + [(3, i) for i in range(2)]
)
@pytest.mark.parametrize("mutation", ({"pid": True}, {"direct_child_reaped": False}))
def test_each_of_the_eleven_prior_children_requires_valid_owned_retirement(monkeypatch, cohort, index, mutation):
    previous = reports(monkeypatch)
    previous[cohort]["rows"][index]["capture"].update(mutation)
    assert collector.previous_admission(*previous, "f" * 64, "e" * 64) is not None


@pytest.mark.parametrize(
    "key,value",
    [
        ("workflow_commit", "b" * 40),
        ("workflow_run", "456"),
        ("workflow_attempt", "2"),
        ("source_before", {}),
        ("tools_before", {}),
        ("original_report_sha256", "0" * 64),
        ("python_report_sha256", "0" * 64),
        ("status", "diagnostic_failed"),
        ("stage", "additional_controls"),
        ("source_unchanged", False),
        ("tools_unchanged", False),
        ("runtime_unchanged", False),
        ("bridge_unchanged", False),
        ("original_report_unchanged", False),
        ("python_report_unchanged", False),
        ("rows", []),
    ],
)
def test_newest_prior_report_requires_all_source_runtime_and_report_bindings(monkeypatch, key, value):
    previous = reports(monkeypatch)
    previous[3][key] = value
    assert collector.previous_admission(*previous, "f" * 64, "e" * 64) is not None


def bound(monkeypatch):
    previous = reports(monkeypatch)
    monkeypatch.setattr(collector.original, "_eligible", lambda: True)
    monkeypatch.setattr(collector.original, "source_identity", lambda: previous[0]["source"])
    monkeypatch.setattr(collector.original, "tool_identity", lambda: previous[0]["tools"])
    monkeypatch.setattr(collector, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(collector, "binary_identity", lambda _path, kind: BINARY if kind == 2 else BRIDGE)
    return previous


def lookup_identity(argv):
    context = "python" if "--mode" in argv else "standalone"
    return context, argv[argv.index("--mode") + 1] if context == "python" else argv[1]


def test_four_exact_controls_preserve_a_valid_unfinished_processing_observation(monkeypatch, tmp_path):
    prepared, _, _, previous = bound(monkeypatch)
    calls, saved = [], []

    def lookup(argv):
        calls.append(argv)
        context, mode = lookup_identity(argv)
        failed = context == "python" and mode == "dns_simple"
        rows = records(mode, context, cycles=2)[:12] if failed else records(mode, context)
        return capture(not failed), wire(rows)

    monkeypatch.setattr(collector, "run_lookup", lookup)
    binary, bridge = tmp_path / "probe", tmp_path / "bridge"
    result = collector.collect(prepared, binary, bridge, previous, lambda row: saved.append(copy.deepcopy(row)))
    assert [lookup_identity(argv) for argv in calls] == list(collector.CONTROLS)
    assert calls[:2] == [(str(binary), mode) for mode in collector.MODES]
    for argv, mode in zip(calls[2:], collector.MODES, strict=True):
        assert argv == (
            sys.executable,
            "-I",
            str(collector.CHILD),
            "--mode",
            mode,
            "--bridge",
            str(bridge),
            "--bridge-sha256",
            BRIDGE["sha256"],
        )
    assert [row["lookup_passed"] for row in result["rows"]] == [True, True, False, True]
    assert result["observation_complete"] and not result["diagnostic_passed"] and not result["qualification_pass"]
    assert result["rows"][2]["metadata"]["process_returns_without_callback_record"] == 1
    assert result["rows"][2]["metadata"]["pending_call"] == "poll" and len(saved) == 5


def test_unreaped_child_stops_the_remaining_controls(monkeypatch, tmp_path):
    prepared, _, _, previous = bound(monkeypatch)
    calls = []

    def lookup(argv):
        calls.append(argv)
        context, mode = lookup_identity(argv)
        return capture(False, False), wire(records(mode, context)[:3])

    monkeypatch.setattr(collector, "run_lookup", lookup)
    report = collector.collect(prepared, tmp_path / "probe", tmp_path / "bridge", previous, lambda _: None)
    assert len(calls) == 1 and report["status"] == "direct_child_cleanup_unproved"
    assert not report["diagnostic_passed"] and not report["observation_complete"]


def passing_lookup(argv):
    context, mode = lookup_identity(argv)
    return capture(), wire(records(mode, context))


def test_four_complete_bound_controls_can_only_pass_the_diagnostic(monkeypatch, tmp_path):
    prepared, _, _, previous = bound(monkeypatch)
    monkeypatch.setattr(collector, "run_lookup", passing_lookup)
    report = collector.collect(prepared, tmp_path / "probe", tmp_path / "bridge", previous, lambda _: None)
    assert report["diagnostic_passed"] and report["observation_complete"] and not report["qualification_pass"]


@pytest.mark.parametrize("binding", ("source_identity", "tool_identity", "runtime_identity", "binary", "bridge"))
def test_final_source_runtime_or_either_binary_change_invalidates_observation(monkeypatch, tmp_path, binding):
    prepared, _, _, previous = bound(monkeypatch)
    monkeypatch.setattr(collector, "run_lookup", passing_lookup)
    if binding in ("binary", "bridge"):
        selected, counts = (2 if binding == "binary" else 6), {2: 0, 6: 0}

        def changed(_path, kind):
            counts[kind] += 1
            return {} if kind == selected and counts[kind] > 1 else (BINARY if kind == 2 else BRIDGE)

        monkeypatch.setattr(collector, "binary_identity", changed)
    else:
        owner = collector.original if binding in ("source_identity", "tool_identity") else collector
        original = getattr(owner, binding)
        calls = []

        def changed():
            calls.append(True)
            return original() if len(calls) == 1 else {}

        monkeypatch.setattr(owner, binding, changed)
    report = collector.collect(prepared, tmp_path / "probe", tmp_path / "bridge", previous, lambda _: None)
    assert not report["diagnostic_passed"] and not report["observation_complete"]


def cli_files(tmp_path, monkeypatch, admit=True):
    prepared, prior, python, dnssd = reports(monkeypatch)
    paths = {label: tmp_path / (label + ".json") for label in ("prepared", "original", "python", "dnssd")}

    def write(label, report):
        paths[label].write_text(json.dumps(report))
        return hashlib.sha256(paths[label].read_bytes()).hexdigest()

    original_sha = write("original", prior)
    python["original_report_sha256"] = original_sha
    python_sha = write("python", python)
    dnssd.update(original_report_sha256=original_sha, python_report_sha256=python_sha)
    write("dnssd", dnssd)
    write("prepared", prepared)
    output = tmp_path / "out.json"
    argv = ["collector", "--prepared", str(paths["prepared"]), "--output", str(output)]
    for label in ("original", "python", "dnssd"):
        argv += ["--" + label + "-report", str(paths[label])]
    if admit:
        argv.append("--admit-previous")
    monkeypatch.setattr(collector.original, "_eligible", lambda: True)
    monkeypatch.setattr(sys, "argv", argv)
    return paths, output, argv


def test_actual_cli_admission_binds_all_report_bytes_and_preserves_prior_failures(tmp_path, monkeypatch):
    paths, output, _ = cli_files(tmp_path, monkeypatch)
    before = {label: path.read_bytes() for label, path in paths.items()}
    assert collector.main() == 0
    report = json.loads(output.read_bytes())
    assert report["status"] == "admitted" and not report["qualification_pass"]
    for label, data in before.items():
        assert report[label + "_report_sha256"] == hashlib.sha256(data).hexdigest()
        assert paths[label].read_bytes() == data


@pytest.mark.parametrize("refused", (False, True))
def test_normal_invocation_handles_missing_arguments_or_refusal_without_exception(tmp_path, monkeypatch, refused):
    paths, output, _ = cli_files(tmp_path, monkeypatch, admit=False)
    if refused:
        prior = json.loads(paths["dnssd"].read_bytes())
        prior["rows"][1]["capture"]["direct_child_reaped"] = False
        paths["dnssd"].write_text(json.dumps(prior))
    assert collector.main() == 1
    report = json.loads(output.read_bytes())
    assert report["status"] == ("previous_report_refused" if refused else "binary_arguments_missing")
    assert not report["diagnostic_passed"]


def test_cli_rechecks_earlier_report_bytes_after_collection(tmp_path, monkeypatch):
    paths, output, argv = cli_files(tmp_path, monkeypatch, admit=False)
    argv += ["--binary", str(tmp_path / "probe"), "--bridge", str(tmp_path / "bridge")]

    def changed(*_args):
        paths["python"].write_text("{}")
        return collector.original._base() | {"diagnostic_passed": True, "observation_complete": True}

    monkeypatch.setattr(collector, "collect", changed)
    assert collector.main() == 1
    report = json.loads(output.read_bytes())
    assert (
        not report["python_report_unchanged"] and not report["diagnostic_passed"] and not report["observation_complete"]
    )


def test_source_closure_and_workflow_preserve_sdk_admission_and_capture_order():
    root = collector.original.ROOT
    for suffix in ("probe.c", "child.py", "evidence.py", "identity.py", "path.py"):
        assert "scripts/ci/native_macos_dnssd_phase_" + suffix in collector.original.SOURCES
    for suffix in ("", "_path", "_identity", "_forwarding"):
        assert "tests/test_native_macos_dnssd_phase" + suffix + ".py" in collector.original.SOURCES
    workflow = (root / ".github/workflows/native-macos-resolver-path.yml").read_text()
    finite = workflow.split("name: Validate finite parser and direct-child controls", 1)[1].split(
        "name: Bind actual source, SDK, compiler and Python runtime", 1
    )[0]
    assert "test_native_macos_dnssd_phase_forwarding.py" not in finite
    order = ("dnssd_lookups", "phase_admission", "phase_forwarding", "phase_build", "phase_lookups")
    assert [workflow.index("id: " + step) for step in order] == sorted(workflow.index("id: " + step) for step in order)
    assert "steps.phase_admission.outcome == 'success'" in workflow
    assert "steps.phase_forwarding.outcome == 'success'" in workflow
    assert "steps.phase_build.outcome == 'success'" in workflow
    assert "timeout-minutes: 8" in workflow and "cancel-in-progress: false" in workflow


@pytest.mark.parametrize(
    "mutation",
    [
        {"output_limit": True},
        {"stderr_bytes": 1},
        {"cleanup_error": "OSError"},
        {"kill_errno": 3},
        {"error_type": "OSError"},
        {"status": "unavailable"},
    ],
)
def test_censored_or_error_capture_cannot_complete_the_observation(monkeypatch, tmp_path, mutation):
    prepared, _, _, previous = bound(monkeypatch)

    def lookup(argv):
        context, mode = lookup_identity(argv)
        return capture() | mutation, wire(records(mode, context))

    monkeypatch.setattr(collector, "run_lookup", lookup)
    report = collector.collect(prepared, tmp_path / "probe", tmp_path / "bridge", previous, lambda _: None)
    assert all(row["metadata"]["valid"] for row in report["rows"])
    assert not report["observation_complete"] and not report["diagnostic_passed"] and not report["qualification_pass"]
