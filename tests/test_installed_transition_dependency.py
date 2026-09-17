"""Optional bundle dependency admission uses a contained installed interpreter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import verify_installed_artifact_transitions as driver


@pytest.mark.parametrize("fault", [None, "digest", "timeout", "containment", "overflow", "exit"])
def test_dependency_inventory_precedes_wheel_install_and_preserves_retirement(monkeypatch, tmp_path, fault):
    baseline, candidate = tmp_path / "baseline.whl", tmp_path / "candidate.whl"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    (tmp_path / "uv.lock").write_bytes(b"lock")
    calls, roots = [], []
    monkeypatch.setattr(driver.shutil, "which", lambda _: "/bounded/uv")
    monkeypatch.setattr(driver, "prepare_private_interpreter", lambda *_a, **_k: {"private_copy": True})
    monkeypatch.setattr(
        driver,
        "artifact_contract",
        lambda path, sha: {
            "build_sha": sha,
            "wheel_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "runtime_sha256": "c" * 64,
            "installed_package_sha256": "d" * 64,
        },
    )

    def required(argv, root):
        calls.append(argv)
        if root not in roots:
            roots.append(root)

    def run(argv, root):
        calls.append(argv)
        if len(calls) == 3:
            assert argv[1] == "-I" and Path(argv[2]).name == "native_slo_dependency_identity.py"
            assert root / "installation" in Path(argv[0]).parents
            return SimpleNamespace(
                returncode=1 if fault == "exit" else 0,
                timed_out=fault == "timeout",
                containment_failed=fault == "containment",
                output_limit_exceeded=fault == "overflow",
                stdout=("f" if fault == "digest" else "e") * 64 + "\n",
            )
        assert fault is None and len(calls) > 3
        return SimpleNamespace()

    monkeypatch.setattr(driver, "_required_command", required)
    monkeypatch.setattr(driver, "_run", run)
    monkeypatch.setattr(driver, "worker_evidence", lambda _result, _expected, phase: {"phase": phase, "passed": True})
    result = driver.verify(
        tmp_path / "controller/bin/python",
        baseline,
        candidate,
        "a" * 40,
        "b" * 40,
        dependency_root=tmp_path,
        expected_dependency_digest="e" * 64,
    )
    assert len(calls) == (13 if fault is None else 3)
    assert result["passed"] is (fault is None)
    assert (result.get("dependency_versions_sha256") == "e" * 64) is (fault is None)
    uncertain = fault in {"timeout", "containment", "overflow", "exit"}
    assert result["fixture_retained_for_unverified_retirement"] is uncertain
    assert roots[0].exists() is uncertain
    if fault:
        assert result["completed_phase_count"] == 0
        assert result["failure"]["worker_timed_out"] is (fault == "timeout")
        assert result["failure"]["worker_containment_failed"] is (fault == "containment")
        assert result["failure"]["worker_limit_exceeded"] is (fault == "overflow")
        assert "f" * 64 not in json.dumps(result)
    if uncertain:
        driver.shutil.rmtree(roots[0])
