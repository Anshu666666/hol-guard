from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot
from codex_plugin_scanner.guard.daemon import discovery
from scripts.ci import native_claude_discovery_witness as witness
from scripts.native_slo_contract import assert_privacy_safe


def _fixture(tmp_path):
    key = "19" * 32
    peer = {
        "compatibility_version": 2,
        "package_version": "3.0.1",
        "source_root": "private",
        "runtime_fingerprint": "a" * 64,
    }
    state = discovery.authenticate_daemon_state({**peer, "guard_home": str(tmp_path)}, discovery_key=key)
    config = json.dumps({"daemon": peer, "guard_home": str(tmp_path)}).encode()
    for name, raw in (
        ("daemon-discovery-key", key.encode()),
        ("daemon-state.json", json.dumps(state).encode()),
        ("config.json", config),
    ):
        path = tmp_path / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return tmp_path / "config.json", hashlib.sha256(config).hexdigest()


def test_non_windows_preflight_performs_no_filesystem_or_security_work(monkeypatch):
    monkeypatch.setattr(witness, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(witness, "_private_object", lambda *args, **kwargs: pytest.fail("unexpected object read"))
    result = witness.windows_discovery_preflight(Path("absent"), Path("absent"), "a" * 64)
    assert result["supported"] is False and result["observer_error"] is False
    assert result["config_read"] == "not_observed"


@pytest.mark.parametrize("failure", [None, "security", "config", "signature", "peer", "observer"])
def test_fixed_preflight_stages_preserve_bytes_and_never_become_authority(tmp_path, monkeypatch, failure):
    config, digest = _fixture(tmp_path)
    monkeypatch.setattr(witness, "os", SimpleNamespace(name="nt"))
    calls = []

    def check(path, *, directory):
        calls.append((path.name, directory))
        if failure == "observer":
            raise OSError("private path and diagnostic must not escape")
        return "security_rejected" if failure == "security" else "passed"

    monkeypatch.setattr(witness, "_private_object", check)
    if failure in {"signature", "peer"}:
        path = tmp_path / "daemon-state.json"
        value = json.loads(path.read_bytes())
        value["package_version"] = "changed"
        if failure == "peer":
            value.pop("state_signature")
            value = discovery.authenticate_daemon_state(value, discovery_key="19" * 32)
        path.write_bytes(json.dumps(value).encode())
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    result = witness.windows_discovery_preflight(tmp_path, config, "0" * 64 if failure == "config" else digest)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert result["observer_error"] is (failure == "observer")
    assert (
        result["native_reader_executed"]
        is result["authorization_evidence"]
        is result["failed_request_cause_proven"]
        is False
    )
    if failure != "observer":
        assert calls == [(tmp_path.name, True), ("daemon-discovery-key", False), ("daemon-state.json", False)]
    if failure not in {"observer", "config"}:
        assert result["config_read"] == result["key_read"] == result["state_read"] == "passed"
        assert result["state_authentication"] == ("rejected" if failure == "signature" else "passed")
        assert result["peer_identity"] == ("rejected" if failure in {"signature", "peer"} else "passed")
    assert assert_privacy_safe(result) == result
    assert str(tmp_path) not in json.dumps(result) and "private path" not in json.dumps(result)


@pytest.mark.parametrize("fault", [None, "open", "metadata", "reparse", "directory", "links", "security"])
def test_security_query_uses_read_only_handle_and_always_closes(monkeypatch, fault):
    class Information(ctypes.Structure):
        _fields_ = [("dwFileAttributes", ctypes.c_uint32), ("nNumberOfLinks", ctypes.c_uint32)]

    calls, closed = [], []

    def create(*args):
        calls.append(args)
        return ctypes.c_void_p(-1).value if fault == "open" else 123

    def information(handle, pointer):
        assert handle == 123
        pointer._obj.dwFileAttributes = 0x400 if fault == "reparse" else 0x10 if fault == "directory" else 0
        pointer._obj.nNumberOfLinks = 2 if fault == "links" else 1
        return fault != "metadata"

    def security(handle, **kwargs):
        assert handle == 123 and kwargs == {"owner_sid": "fixture", "directory": False}
        if fault == "security":
            raise RuntimeError("private ACL detail")

    monkeypatch.setattr(
        native_policy_snapshot,
        "_windows_dll",
        lambda name: SimpleNamespace(CreateFileW=create, GetFileInformationByHandle=information),
    )
    monkeypatch.setattr(native_policy_snapshot, "_windows_file_information_type", lambda: Information)
    monkeypatch.setattr(native_policy_snapshot, "_windows_owner_sid", lambda: "fixture")
    monkeypatch.setattr(native_policy_snapshot, "_windows_verify_private_dacl", security)
    monkeypatch.setattr(native_policy_snapshot, "_windows_close_handle", lambda kernel, handle: closed.append(handle))
    expected = {
        None: "passed",
        "open": "open_failed",
        "metadata": "metadata_unavailable",
        "reparse": "identity_rejected",
        "directory": "identity_rejected",
        "links": "identity_rejected",
        "security": "security_rejected",
    }[fault]
    assert witness._private_object(Path("fixed"), directory=False) == expected
    assert calls[0][1:] == (0x20080, 0x3, None, 3, 0x02200000, None)
    assert closed == ([] if fault == "open" else [123])


@pytest.mark.skipif(os.name != "nt", reason="actual Windows security descriptor check")
def test_actual_windows_inherited_discovery_file_differs_from_protected_file(tmp_path):
    from scripts.native_slo_evidence_files import _new_directory
    from scripts.native_slo_evidence_windows import write_private_file

    parent = tmp_path / "owned"
    _new_directory(parent)
    inherited = parent / "inherited"
    inherited.write_bytes(b"synthetic")
    private = parent / "protected"
    write_private_file(private, b"synthetic")
    assert witness._private_object(parent, directory=True) == "passed"
    assert witness._private_object(inherited, directory=False) == "security_rejected"
    assert witness._private_object(private, directory=False) == "passed"
    assert inherited.read_bytes() == private.read_bytes() == b"synthetic"


def test_existing_four_platform_experiment_runs_security_witness_without_relaxing_gate():
    import yaml

    root = Path(__file__).resolve().parents[1]
    value = yaml.safe_load((root / ".github/workflows/native-claude-launcher-experiment.yml").read_text())
    jobs = list(value["jobs"].values())
    steps = [step for job in jobs for step in job.get("steps", [])]
    step = next(step for step in steps if "test_native_claude_discovery_witness.py" in step.get("run", ""))
    assert "pytest" in step["run"] and "if" not in step and not step.get("continue-on-error", False)
    matrix = next(job["strategy"]["matrix"] for job in jobs if "strategy" in job)
    assert len(matrix["platform"]) == 4
    assert any(platform["runner"] == "windows-latest" for platform in matrix["platform"])
