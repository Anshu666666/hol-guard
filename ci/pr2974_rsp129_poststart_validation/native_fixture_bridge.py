"""Bind a producer-dependent collection to the original fresh native output."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exact_file(path: Path, maximum: int, *, executable: bool = False) -> tuple[bytes, dict]:
    assert path.is_absolute() and path == path.resolve(strict=True) and not path.is_symlink()
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
    assert 0 < before.st_size <= maximum
    assert not executable or before.st_mode & 0o111
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda info: [info.st_dev, info.st_ino, info.st_mode, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns]
    assert identity(before) == identity(after) and len(raw) == after.st_size
    return raw, {
        "path": str(path), "bytes": len(raw), "sha256": digest(raw),
        "uid": after.st_uid, "mode": oct(stat.S_IMODE(after.st_mode)),
        "identity": identity(after),
    }


def fixture_bridge(config: dict, source: Path, report: Path, scratch: Path) -> dict:
    assert __debug__
    path = report / "native-fixture-bridge.json"
    assert os.environ["VALIDATION_NATIVE_FIXTURE_BRIDGE"] == str(path)
    expected = os.environ["VALIDATION_NATIVE_FIXTURE_BRIDGE_SHA256"]
    assert re.fullmatch(r"[0-9a-f]{64}", expected)
    raw, bridge_file = exact_file(path, 1024 * 1024)
    assert digest(raw) == expected
    bridge = json.loads(raw)
    assert bridge["schema"] == "pr2974.native-producer-fixture-bridge.v1"
    assert bridge["source_sha"] == config["source_sha"]
    assert bridge["source_tree"] == config["source_tree"]
    assert bridge["producer_test"] == config["native_fixture"]["producer_test"]
    assert bridge["native_test_entries_passed"] == 1 and bridge["producer_case_count"] == 6
    assert bridge["qualification_complete"] is False
    assert "HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE" not in os.environ
    gate_path = report / "native-unit-gate.json"
    gate_raw, gate_file = exact_file(gate_path, 2 * 1024 * 1024)
    assert gate_file["bytes"] == bridge["native_unit_gate"]["bytes"]
    assert gate_file["sha256"] == bridge["native_unit_gate"]["sha256"]
    gate = json.loads(gate_raw)
    assert gate["source_sha"] == config["source_sha"] and gate["source_tree"] == config["source_tree"]
    assert gate["planned_test_entries"] == 24 and gate["passed"] is True and gate["errors"] == []
    expected_binary = gate["binaries"]["runtime"]["retained_binary"]
    binary_path = Path(expected_binary["path"])
    assert binary_path.is_relative_to(scratch)
    _binary_raw, binary = exact_file(binary_path, 256 * 1024 * 1024, executable=True)
    assert all(binary[key] == expected_binary[key] for key in ("path", "bytes", "sha256", "uid", "mode"))
    assert expected_binary == bridge["retained_unit_binary"]
    log_path = report / bridge["producer_log"]["path"]
    assert log_path.parent == report
    assert os.environ["HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE_LOG"] == str(log_path)
    log_raw, log_file = exact_file(log_path, 999999)
    assert log_file["bytes"] == bridge["producer_log"]["bytes"]
    assert log_file["sha256"] == bridge["producer_log"]["sha256"]
    assert log_raw.decode("utf-8").count("HOL_GUARD_NONCOMMAND_RECEIPTS=") == 1
    assert bridge["producer_command_passed"] is True
    inputs = {}
    for relative in config["native_fixture"]["provider_paths"]:
        path = source / relative
        body, observed = exact_file(path, 2 * 1024 * 1024)
        assert observed["sha256"] == config["source_inputs"][relative]
        inputs[relative] = {
            "bytes": len(body), "sha256": observed["sha256"],
            "git_blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest(),
        }
    assert (report / "native-fixture-bridge.json").read_bytes() == raw
    assert gate_path.read_bytes() == gate_raw and log_path.read_bytes() == log_raw
    return {
        "scope": "actual_fresh_native_single_producer_log_and_source_bound_python_fixtures",
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "bridge_file": bridge_file, "bridge": bridge, "native_unit_gate": gate_file,
        "retained_unit_binary": binary, "original_producer_log": log_file,
        "provider_inputs": inputs, "qualification_complete": False,
    }
