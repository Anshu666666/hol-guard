"""Strict interpreter representation controls; no product or launcher workload."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci.cline_witness import invocation
from scripts.ci.cline_witness.installation import canonical


def facts(*, changed=False) -> dict[str, Any]:
    return {
        "executable": "/owned/bin/python",
        "orig_argv": ["/framework/Python" if changed else "/owned/bin/python", "-I", "-c", invocation.PROBE],
        "python": [3, 12, 10],
        "platform": "darwin" if changed else "linux",
        "prefix": "/owned",
        "framework": changed,
    }


def parse(value):
    return invocation.parse(canonical(value), "/owned/bin/python", "/owned", [3, 12, 10])


@pytest.mark.parametrize("changed", [False, True])
def test_exact_identity_and_framework_argv0_have_separate_proofs(changed):
    observed, report = parse(facts(changed=changed))
    assert observed == facts(changed=changed)["orig_argv"][0]
    assert (report["registered_probe_argv_sha256"] != report["observed_probe_argv_sha256"]) is changed
    assert report["all_arguments_after_argv0_exact"] is True
    assert report["original_launcher_invoked"] is False and report["product_imported"] is False
    assert "/owned" not in json.dumps(report) and "/framework" not in json.dumps(report)


@pytest.mark.parametrize(
    "changed", ["executable", "prefix", "version", "tail", "relative", "platform", "framework", "extra", "duplicate"]
)
def test_unproven_transform_or_changed_argument_is_refused(changed):
    value = facts(changed=True)
    if changed in {"executable", "prefix"}:
        value[changed] = "/other"
    elif changed == "version":
        value["python"] = [3, 12, 11]
    elif changed == "tail":
        value["orig_argv"][1] = "-s"
    elif changed == "relative":
        value["orig_argv"][0] = "Python"
    elif changed == "platform":
        value["platform"] = "linux"
    elif changed == "framework":
        value["framework"] = False
    elif changed == "extra":
        value["private"] = "not allowed"
    else:
        raw = canonical(value)[:-1] + b',"framework":true}'
        with pytest.raises(ValueError, match="duplicate"):
            invocation.parse(raw, "/owned/bin/python", "/owned", [3, 12, 10])
        return
    with pytest.raises(ValueError):
        parse(value)


@pytest.mark.parametrize("failure", ["exit", "stderr", "changed", "timeout"])
def test_preflight_failure_never_admits_workload(monkeypatch, failure):
    calls = []
    image_count = 0

    def image(_path):
        nonlocal image_count
        image_count += 1
        return {"sha256": "changed" if failure == "changed" and image_count == 2 else "a", "bytes": 1}

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {"capture_output": True, "timeout": 5, "check": False}
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 5)
        value = facts()
        value["python"] = list(invocation.sys.version_info[:3])
        return SimpleNamespace(
            returncode=1 if failure == "exit" else 0,
            stderr=b"error" if failure == "stderr" else b"",
            stdout=canonical(value),
        )

    monkeypatch.setattr(invocation, "image", image)
    monkeypatch.setattr(invocation.subprocess, "run", run)
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        invocation.preflight("/owned/bin/python", "/owned")
    assert calls == [["/owned/bin/python", "-I", "-c", invocation.PROBE]]
