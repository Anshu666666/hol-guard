"""Fresh source/build/runtime binding and finite independent lookup admission."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import native_macos_resolver_path as diagnostic


@pytest.fixture
def harness(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic.sys, "platform", "darwin")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    state = {"calls": [], "failure": None, "cleanup": False, "changed": None, "observations": []}
    counts = {"source": 0, "tools": 0, "binary": 0}

    def identity(name):
        counts[name] += 1
        return {name: "changed" if state["changed"] == name and counts[name] > 1 else "same"}

    monkeypatch.setattr(diagnostic, "source_identity", lambda: identity("source"))
    monkeypatch.setattr(diagnostic, "tool_identity", lambda: identity("tools"))
    monkeypatch.setattr(diagnostic, "_sha", lambda _path: identity("binary"))

    def run(arguments):
        if arguments[0] == sys.executable:
            assert arguments == (sys.executable, "-I", "-c", diagnostic.PYTHON_CONTROL)
            mode = "python_fqdn"
        else:
            assert arguments[0] == str(tmp_path / "probe")
            mode = arguments[1]
        state["calls"].append(mode)
        row = {"kind": "identity", "mode": mode, "pid": 123}
        if mode != "python_fqdn":
            row.update(libinfo_uuid="a" * 32, dnssd_uuid="b" * 32, cpu_type=12, cpu_subtype=0)
        rows = [row]
        capture = {
            "pid": 123,
            "status": "completed",
            "return_code": 0,
            "direct_child_reaped": True,
            "termination_attempted": False,
            "stderr_bytes": 0,
        }
        if mode == state["failure"]:
            capture.update(
                status="deadline_exceeded",
                return_code=-9,
                termination_attempted=True,
                direct_child_reaped=not state["cleanup"],
            )
        elif mode.startswith("dns_"):
            rows.extend(
                [
                    {
                        "kind": "query",
                        "shared": mode == "dns_shared",
                        "requested_flags": 0x15000 if mode == "dns_shared" else 0,
                        "error": 0,
                    },
                    {
                        "kind": "callback",
                        "sequence": 1,
                        "flags": 2,
                        "interface_index": 0,
                        "error": 0,
                        "type": 12,
                        "class": 1,
                        "data_bytes": 11,
                        "question_matches": True,
                        "loopback_label": True,
                    },
                    {
                        "kind": "result",
                        "error": 0,
                        "callback_error": 0,
                        "callbacks": 1,
                        "overflow": False,
                        "loopback_label": True,
                    },
                ]
            )
        else:
            rows.append({"kind": "result", "error": 0, "loopback_label": True})
        return capture, b"".join(json.dumps(item).encode() + b"\n" for item in rows)

    monkeypatch.setattr(diagnostic, "run_lookup", run)
    prepared = diagnostic._base() | {"status": "prepared", "source": {"source": "same"}, "tools": {"tools": "same"}}
    state["collect"] = lambda: diagnostic.collect(
        prepared, tmp_path / "probe", lambda report: state["observations"].append(copy.deepcopy(report))
    )
    state["prepared"] = prepared
    return state


def test_all_five_fixed_controls_keep_separate_metadata_and_never_qualify(harness):
    report = harness["collect"]()
    assert harness["calls"] == list(diagnostic.MODES)
    assert report["diagnostic_passed"] is True and report["loaded_images_consistent"] is True
    assert report["qualification_pass"] is False and report["installed_baseline_startup_verified"] is False
    assert report["descendant_retirement_verified"] is False
    assert report["service_intervention_attempted"] is False and report["configuration_modified"] is False
    assert report["libinfo_binary_source_equivalence_claimed"] is False


@pytest.mark.parametrize("mode", diagnostic.MODES)
def test_actual_failed_prefix_remains_failed_and_other_independent_controls_continue(harness, mode):
    harness["failure"] = mode
    report = harness["collect"]()
    assert harness["calls"] == list(diagnostic.MODES)
    assert report["diagnostic_passed"] is False
    failed = next(row for row in report["rows"] if row["mode"] == mode)
    assert failed["capture"]["status"] == "deadline_exceeded" and failed["capture"]["return_code"] == -9
    assert failed["metadata"]["valid"] and not failed["metadata"]["complete"] and not failed["lookup_passed"]


def test_unreaped_child_stops_suffix_and_preserves_checkpoint(harness):
    harness.update(failure="dns_shared", cleanup=True)
    report = harness["collect"]()
    assert report["status"] == "direct_child_cleanup_unproved" and not report["diagnostic_passed"]
    assert harness["calls"] == ["dns_simple", "dns_shared"]
    assert harness["observations"][-1]["rows"][-1]["capture"]["direct_child_reaped"] is False


@pytest.mark.parametrize("changed", ["source", "tools", "binary"])
def test_changed_final_identity_rejects_otherwise_successful_controls(harness, changed):
    harness["changed"] = changed
    report = harness["collect"]()
    assert report[changed + "_unchanged"] is False and not report["diagnostic_passed"]


@pytest.mark.parametrize("changed", ["workflow_run", "workflow_attempt", "workflow_commit", "tools"])
def test_stale_build_receipt_cannot_launch_a_control(harness, changed):
    harness["prepared"][changed] = "stale"
    report = harness["collect"]()
    assert harness["calls"] == [] and not report["diagnostic_passed"]


def test_actual_git_binding_rejects_modified_helper_without_exporting_it(monkeypatch, tmp_path):
    def git(*arguments):
        return subprocess.check_output(
            ["git", "-C", str(tmp_path), *arguments], stderr=subprocess.DEVNULL, text=True
        ).strip()

    git("init")
    git("config", "user.email", "finite@example.invalid")
    git("config", "user.name", "Finite source control")
    (tmp_path / "helper.py").write_text("pass\n")
    git("add", "helper.py")
    git("commit", "-m", "fixed source")
    monkeypatch.setenv("GITHUB_SHA", git("rev-parse", "HEAD"))
    monkeypatch.setattr(diagnostic, "ROOT", tmp_path)
    monkeypatch.setattr(diagnostic, "SOURCES", ("helper.py",))
    assert diagnostic.source_identity()["head"] == git("rev-parse", "HEAD")
    (tmp_path / "helper.py").write_text("private modification\n")
    with pytest.raises(ValueError, match="source bytes changed"):
        diagnostic.source_identity()


def test_standalone_preparation_refuses_non_ci_without_a_lookup(tmp_path):
    source = Path(__file__).resolve().parents[1] / "scripts/ci/native_macos_resolver_path.py"
    output = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "-I", str(source), "--prepare", "--output", str(output)],
        env={"PATH": str(Path(sys.executable).parent)},
        capture_output=True,
        timeout=10,
        check=False,
    )
    report = json.loads(output.read_text())
    assert result.returncode == 1 and report["stage"] == "platform"
    assert report["diagnostic_passed"] is False and report["service_intervention_attempted"] is False


def test_failed_identity_command_retains_status_without_private_output(monkeypatch):
    monkeypatch.setattr(
        diagnostic,
        "_capture",
        lambda _arguments: {
            "status": "deadline_exceeded",
            "return_code": -9,
            "stderr_bytes": 12,
            "stdout": "/private/tool/path",
            "stderr": "private text",
            "argv": ["/private/tool"],
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
        },
    )
    with pytest.raises(diagnostic.IdentityCommandError) as error:
        diagnostic._fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"))
    assert error.value.metadata["operation"] == "--show-sdk-path"
    assert error.value.metadata["status"] == "deadline_exceeded"
    assert "private" not in json.dumps(error.value.metadata)
