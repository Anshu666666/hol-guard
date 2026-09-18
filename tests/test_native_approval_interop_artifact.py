"""Component-only export boundary checks; genuine resident output is separate."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_result
from codex_plugin_scanner.guard.runtime.native_review_executor import execute_exact_review_job
from tests.native_approval_interop_artifact import fixture_build_provenance, synthetic_delivery_companion
from tests.native_approval_resident_fixtures import connected_fixture_store
from tests.test_native_approval_queue_state import _NOW
from tests.test_native_review_delivery import _never_resume, _ready


@pytest.fixture
def delivered(tmp_path: Path):
    store, row, job = _ready(tmp_path)
    claim = build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)
    execution = execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    return job, exact_result(job, execution), claim


def test_original_public_assertion_and_waiting_result_are_preserved(delivered):
    job, result, claim = delivered
    exported = synthetic_delivery_companion(job=job, result=result, source_claim=claim)
    assert set(exported) == {"queuedCommand", "deliveryResult"}
    assert exported["queuedCommand"] == {key: value for key, value in job.items() if key != "_guardCommandTransport"}
    assert exported["deliveryResult"] == result
    assert "_guardCommandTransport" not in json.dumps(exported)
    before = json.dumps(exported, sort_keys=True)
    job["payload"]["nativeApprovalProof"]["assertion"]["response"]["signature"] = "changed"
    assert json.dumps(exported, sort_keys=True) == before


@pytest.mark.parametrize(
    "target", ["job", "binding", "payload", "context", "proof", "assertion", "response", "challenge", "result"]
)
def test_unexpected_secret_bearing_fields_are_not_exported(delivered, target):
    job, result, claim = delivered
    proof = job["payload"]["nativeApprovalProof"]
    objects = {
        "job": job,
        "binding": job["serverResolvedBinding"],
        "payload": job["payload"],
        "context": job["payload"]["nativeApprovalContext"],
        "proof": proof,
        "assertion": proof["assertion"],
        "response": proof["assertion"]["response"],
        "challenge": proof["challenge"],
        "result": result,
    }
    objects[target]["privateKey"] = "SYNTHETIC_PRIVATE_MATERIAL_MUST_NOT_EXPORT"
    with pytest.raises(ValueError):
        synthetic_delivery_companion(job=job, result=result, source_claim=claim)


@pytest.mark.parametrize("target", ["binding", "result", "proof"])
def test_substituted_delivery_cannot_be_exported_as_original(delivered, target):
    job, result, claim = (copy.deepcopy(value) for value in delivered)
    if target == "binding":
        job["serverResolvedBinding"]["claimDigest"] = "f" * 64
    elif target == "result":
        result["receiptId"] = "33333333-3333-4333-8333-333333333333"
    else:
        job["payload"]["nativeApprovalProof"]["challenge"]["nonce"] = "e" * 64
    with pytest.raises(ValueError):
        synthetic_delivery_companion(job=job, result=result, source_claim=claim)


def test_registration_fixture_uses_original_local_installation(tmp_path: Path):
    store = connected_fixture_store(tmp_path)
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    assert oauth.machine_id == oauth.installation_id == store.get_or_create_installation_id()
    assert oauth.device_id == oauth.dpop_thumbprint
    assert oauth.machine_id != oauth.device_id


def test_build_provenance_requires_exact_clean_source_and_run(tmp_path: Path, monkeypatch):
    repository = tmp_path / "source"
    repository.mkdir()

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=repository, text=True, stderr=subprocess.DEVNULL).strip()

    git("init")
    tracked = repository / "synthetic.txt"
    tracked.write_text("Synthetic fixture source\n")
    git("add", "synthetic.txt")
    git("-c", "user.name=Codex", "-c", "user.email=codex@users.noreply.github.com", "commit", "-m", "Fixture source")
    commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    monkeypatch.setenv("GITHUB_SHA", commit)
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    assert fixture_build_provenance(repository) == {"sourceCommit": commit, "sourceTree": tree, "buildRunId": "12345"}
    monkeypatch.setenv("GITHUB_SHA", "0" * 40)
    with pytest.raises(ValueError):
        fixture_build_provenance(repository)
    monkeypatch.setenv("GITHUB_SHA", commit)
    monkeypatch.delenv("GITHUB_RUN_ID")
    with pytest.raises(ValueError):
        fixture_build_provenance(repository)
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    tracked.write_text("Changed after build\n")
    with pytest.raises(subprocess.CalledProcessError):
        fixture_build_provenance(repository)
