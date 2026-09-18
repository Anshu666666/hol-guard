"""The fresh service identity gates one bounded cache experiment."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import native_macos_observed_cache as diagnostic


def _service(label="com.apple.mDNSResponder.reloaded"):
    return {
        "service_identity_verified": True,
        "service": {"label": label, "service_target": "system/" + label},
        "plist_before": {"sha256": "plist"},
        "plist_after": {"sha256": "plist"},
        "executable_before": {"sha256": "executable"},
        "executable_after": {"sha256": "executable"},
    }


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(diagnostic.sys, "platform", "darwin")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    state = {
        "events": [],
        "hosts": [{"identity": "same"}, {"identity": "same"}],
        "dns": ["same", "same"],
        "service": [_service(), _service()],
        "signal": {"status": "completed", "return_code": 0},
        "before_completed": False,
        "after_completed": True,
    }
    monkeypatch.setattr(diagnostic.cache, "hosts_mapping_witness", lambda: state["hosts"].pop(0))
    monkeypatch.setattr(diagnostic.cache, "_hosts_eligible", lambda report: report["identity"] == "same")

    def fixed(arguments, *, limit):
        assert arguments == ("/usr/sbin/scutil", "--dns") and limit == 256 * 1024
        state["events"].append("dns")
        return {"status": "completed", "stdout_sha256": state["dns"].pop(0)}, b""

    def libc(operation):
        state["events"].append(operation)
        completed = state["after_completed"] if "signal" in state["events"] else state["before_completed"]
        return {
            "operation": operation,
            "status": "completed" if completed else "deadline_exceeded",
            "loopback_label": completed,
        }

    def identity():
        state["events"].append("identity")
        return state["service"].pop(0)

    def capture(arguments):
        assert arguments == (
            "/usr/bin/sudo",
            "-n",
            "/bin/launchctl",
            "kill",
            "SIGHUP",
            "system/com.apple.mDNSResponder.reloaded",
        )
        assert state["events"] == ["dns", "getfqdn", "gethostbyaddr", "getnameinfo", "identity"]
        state["events"].append("signal")
        return state["signal"]

    monkeypatch.setattr(diagnostic.cache, "_fixed_command", fixed)
    monkeypatch.setattr(diagnostic.cache, "libc_probe", libc)
    monkeypatch.setattr(diagnostic.identity, "collect", identity)
    monkeypatch.setattr(diagnostic.identity, "_capture", capture)
    return state


@pytest.mark.parametrize(
    "mutation", [None, "signal_failed", "signal_timeout", "hosts", "dns", "service", "lookup", "already_completed"]
)
def test_signal_and_original_probes_retain_each_independent_failure(harness, mutation):
    if mutation == "signal_failed":
        harness["signal"] = {"status": "completed", "return_code": 113}
    elif mutation == "signal_timeout":
        harness["signal"] = {"status": "deadline_exceeded", "return_code": 0}
    elif mutation == "hosts":
        harness["hosts"][1] = {"identity": "changed"}
    elif mutation == "dns":
        harness["dns"][1] = "changed"
    elif mutation == "service":
        harness["service"][1]["executable_after"] = {"sha256": "changed"}
    elif mutation == "lookup":
        harness["after_completed"] = False
    elif mutation == "already_completed":
        harness["before_completed"] = True
    report = diagnostic.collect()
    assert report["signal_attempts"] == 1
    assert report["signal"] == harness["signal"]
    assert harness["events"] == [
        "dns",
        "getfqdn",
        "gethostbyaddr",
        "getnameinfo",
        "identity",
        "signal",
        "getfqdn",
        "gethostbyaddr",
        "getnameinfo",
        "dns",
        "identity",
    ]
    assert report["diagnostic_passed"] is (mutation in {None, "already_completed"})
    assert report["libc_recovered_after_signal"] is (mutation is None)
    assert report["qualification_pass"] is False
    assert report["installed_baseline_startup_verified"] is False
    assert report["service_signal_handled_verified"] is False
    assert report["ownership_verified"] is False
    assert report["baseline_artifact_modified"] is False
    assert report["fixture_deadline_changed"] is False


@pytest.mark.parametrize("mutation", ["signature", "label", "target", "not_ci", "hosts"])
def test_unverified_service_or_environment_cannot_be_signalled(harness, monkeypatch, mutation):
    if mutation == "signature":
        harness["service"][0]["service_identity_verified"] = False
    elif mutation == "label":
        harness["service"][0] = _service("unexpected.service")
    elif mutation == "target":
        harness["service"][0]["service"]["service_target"] = "system/other"
    elif mutation == "not_ci":
        monkeypatch.delenv("GITHUB_RUN_ID")
    else:
        harness["hosts"][0] = {"identity": "untrusted"}
    report = diagnostic.collect()
    assert report["signal_attempts"] == 0 and "signal" not in harness["events"]
    assert report["diagnostic_passed"] is False


def test_pending_signal_checkpoint_survives_interruption(harness, monkeypatch):
    saved = []

    def interrupt(_arguments):
        assert saved[-1]["status"] == "signal_pending"
        assert saved[-1]["signal_attempts"] == 1
        assert saved[-1]["libc_before"][0]["status"] == "deadline_exceeded"
        raise SystemExit(143)

    monkeypatch.setattr(diagnostic.identity, "_capture", interrupt)
    with pytest.raises(SystemExit):
        diagnostic.collect(progress=lambda report: saved.append(copy.deepcopy(report)))
    assert saved[-1]["launchctl_signal_accepted"] is False
    assert saved[-1]["diagnostic_passed"] is False


def test_original_label_is_selected_only_when_freshly_observed(harness, monkeypatch):
    harness["service"] = [_service("com.apple.mDNSResponder"), _service("com.apple.mDNSResponder")]
    calls = []

    def capture(arguments):
        calls.append(arguments)
        harness["events"].append("signal")
        return harness["signal"]

    monkeypatch.setattr(diagnostic.identity, "_capture", capture)
    report = diagnostic.collect()
    assert calls == [("/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGHUP", "system/com.apple.mDNSResponder")]
    assert report["signal_attempts"] == 1 and report["diagnostic_passed"] is True


def test_standalone_isolated_cli_refuses_a_non_macos_runner(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts/ci/native_macos_observed_cache.py"
    output = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--output", str(output)],
        env={"PATH": str(Path(sys.executable).parent)},
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    report = json.loads(output.read_text())
    assert report["status"] == "not_disposable_macos_ci"
    assert report["signal_attempts"] == 0 and report["diagnostic_passed"] is False
