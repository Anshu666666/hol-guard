"""Immutable bundle admission and required retention for the independent scenario."""

from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts import native_slo_evidence_archive as encrypted
from scripts.ci import installed_transition_ci as ci
from scripts.native_slo_evidence_files import atomic_exclusive
from scripts.native_slo_pair_io import canonical, read_public, write_public

CONTEXT = {"source_sha": "c" * 40, "target": "x86_64-unknown-linux-musl", "run_id": 17, "run_attempt": 2}


def _bundle():
    return {
        "target": CONTEXT["target"],
        "arms": {
            arm: {
                "build_sha": ci.BASELINE_SHA if arm == "baseline" else CONTEXT["source_sha"],
                "wheel": arm + ".whl",
                "wheel_sha256": char * 64,
                "package_sha256": "d" * 64,
                "runtime_sha256": "e" * 64,
                "lock_sha256": "f" * 64,
                "requirements_sha256": "a" * 64,
                "dependency_versions_sha256": "b" * 64,
                "python_version": ".".join(map(str, ci.sys.version_info[:3])),
            }
            for arm, char in (("baseline", "1"), ("candidate", "2"))
        },
    }


def _probe(bundle):
    return {
        "passed": True,
        "completed_phase_count": 5,
        "required_phase_count": 5,
        "private_checkpoints_retained": 5,
        "private_checkpoint_retention": {"files": 5, "complete": True},
        "fixture_retained_for_unverified_retirement": False,
        "fixture_retained_for_evidence_failure": False,
        "dependency_lock_sha256": "f" * 64,
        "dependency_versions_sha256": "b" * 64,
        "phases": [{"phase": phase, "passed": True} for phase in ci.PHASES],
        "identities": {
            arm: {
                "build_sha": values["build_sha"],
                "wheel_sha256": values["wheel_sha256"],
                "installed_package_sha256": values["package_sha256"],
                "runtime_sha256": values["runtime_sha256"],
            }
            for arm, values in bundle["arms"].items()
        },
    }


def _run(monkeypatch, tmp_path, mutation=None):
    root, output = tmp_path / "bundle", tmp_path / "evidence"
    root.mkdir()
    bundle = _bundle()
    (root / "bundle.json").write_bytes(canonical(bundle))
    monkeypatch.setattr(ci, "_bundle_binding", lambda *_args: copy.deepcopy(bundle))

    def verify(*args, **kwargs):
        private = kwargs["private_evidence"]
        # The denominator and exact bundle exist before any hook/installation offer.
        assert read_public(output / "aggregate/plan.json") == ci.plan(CONTEXT)
        assert (private / "transition-plan.json").exists() and (private / "wheel-bundle.json").exists()
        assert args[1:3] == (root / "baseline/baseline.whl", root / "candidate/candidate.whl")
        assert kwargs["expected_dependency_digest"] == "b" * 64
        result = _probe(bundle)
        for phase in ci.PHASES:
            atomic_exclusive(private / f"installed-transition-{phase}.json", b'{"raw_private_witness":"fixture"}')
        if mutation is not None:
            mutation(result)
        return result

    monkeypatch.setattr(ci, "verify", verify)
    return output, ci.run(root, output, tmp_path, CONTEXT)


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    recipient = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    return public, private, recipient


def _archive(monkeypatch, tmp_path, output, keys):
    public, _, recipient = keys
    path = tmp_path / "key.pem"
    path.write_bytes(public)
    monkeypatch.setattr(ci, "RECIPIENT_ID", recipient)
    receipt = ci.archive(output, CONTEXT, path)
    write_public(output / "archive-receipt.json", receipt)
    return receipt


def test_complete_scenario_requires_exact_bundle_and_encrypted_checkpoints(monkeypatch, tmp_path, keys):
    output, summary = _run(monkeypatch, tmp_path)
    assert summary["passed"] is True
    assert summary["required_registered_cases"] == 10
    assert summary["maximum_contained_commands"] == 13
    assert summary["headline_timing_eligible"] is False
    receipt = _archive(monkeypatch, tmp_path, output, keys)
    ci.retention(output, CONTEXT)
    assert receipt["files"] == 8
    restored = dict(encrypted.open_archive((output / "encrypted/checkpoints.hge").read_bytes(), keys[1])[0])
    assert restored["transition-plan.json"] == canonical(ci.plan(CONTEXT)) + b"\n"
    assert all(
        restored[f"installed-transition-{phase}.json"] == b'{"raw_private_witness":"fixture"}' for phase in ci.PHASES
    )
    assert "raw_private_witness" not in json.dumps(summary)


@pytest.mark.parametrize("fault", ["phase", "count", "retirement", "dependency", "runtime"])
def test_probe_false_success_cannot_qualify_but_raw_evidence_is_sealed(monkeypatch, tmp_path, keys, fault):
    def mutate(result):
        if fault == "phase":
            result["phases"][3]["passed"] = False
        elif fault == "count":
            result["completed_phase_count"] = 5.0
        elif fault == "retirement":
            result["fixture_retained_for_unverified_retirement"] = True
        elif fault == "dependency":
            result["dependency_versions_sha256"] = "0" * 64
        else:
            result["identities"]["baseline"]["runtime_sha256"] = "0" * 64

    output, summary = _run(monkeypatch, tmp_path, mutate)
    assert summary["passed"] is False
    assert _archive(monkeypatch, tmp_path, output, keys)["files"] == 8
    with pytest.raises(ValueError, match="transition_scenario_incomplete"):
        ci.retention(output, CONTEXT)


@pytest.mark.parametrize("missing_private_summary", [False, True])
def test_interruption_preserves_remaining_checkpoints_without_inventing_completion(
    monkeypatch, tmp_path, keys, missing_private_summary
):
    output, _ = _run(monkeypatch, tmp_path)
    (output / "aggregate/summary.json").unlink()
    if missing_private_summary:
        (output / "private_samples/transition-summary.json").unlink()
    _archive(monkeypatch, tmp_path, output, keys)
    summary = read_public(output / "aggregate/summary.json")
    assert summary["passed"] is (not missing_private_summary)
    if missing_private_summary:
        assert summary["status"] == "interrupted"
        with pytest.raises(ValueError):
            ci.retention(output, CONTEXT)
    else:
        ci.retention(output, CONTEXT)


@pytest.mark.parametrize("mutation", ["delete", "replace"])
def test_checkpoint_loss_or_change_still_seals_remaining_bytes_and_fails_gate(monkeypatch, tmp_path, keys, mutation):
    output, _ = _run(monkeypatch, tmp_path)
    checkpoint = output / "private_samples/installed-transition-candidate_upgrade.json"
    if mutation == "delete":
        checkpoint.unlink()
    else:
        checkpoint.write_bytes(b'{"different":true}')
    receipt = _archive(monkeypatch, tmp_path, output, keys)
    assert receipt["status"] == "encrypted"
    assert read_public(output / "aggregate/archive-validation.json")["passed"] is False
    with pytest.raises(ValueError, match="transition_archive_invalid"):
        ci.retention(output, CONTEXT)


@pytest.mark.parametrize(
    "field,value", [("archive_sha256", "0" * 64), ("files", 7), ("archive_bytes", True), ("recipient_key_id", "0" * 64)]
)
def test_ciphertext_receipt_identity_count_and_size_are_required(monkeypatch, tmp_path, keys, field, value):
    output, _ = _run(monkeypatch, tmp_path)
    receipt = _archive(monkeypatch, tmp_path, output, keys)
    receipt[field] = value
    path = output / "archive-receipt.json"
    path.unlink()
    write_public(path, receipt)
    with pytest.raises(ValueError, match="transition_retention_incomplete"):
        ci.retention(output, CONTEXT)


@pytest.mark.parametrize("fault", ["source", "lock", "patch", "bundle"])
def test_admission_rejects_unbound_inputs_before_probe(monkeypatch, tmp_path, fault):
    bundle = _bundle()
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"candidate-lock")
    bundle["arms"]["candidate"]["lock_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
    if fault == "patch":
        bundle["arms"]["baseline"]["python_version"] = "3.12.0"
    if fault == "lock":
        lock.write_bytes(b"changed")
    monkeypatch.setattr(
        ci.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="d" * 40 if fault == "source" else CONTEXT["source_sha"]),
    )

    def load(*_args, **kwargs):
        assert kwargs == {"target": CONTEXT["target"], "candidate_sha": CONTEXT["source_sha"]}
        if fault == "bundle":
            raise ValueError("bundle_invalid")
        return bundle

    monkeypatch.setattr(ci, "load_bundle", load)
    monkeypatch.setattr(ci, "verify", lambda *_a, **_k: pytest.fail("admission must precede probe"))
    result = ci.run(tmp_path, tmp_path / "evidence", tmp_path, CONTEXT)
    assert result["passed"] is False
    assert (tmp_path / "evidence/private_samples/transition-plan.json").exists()


@pytest.mark.parametrize(
    "filename",
    [
        "installed-transition-candidate_upgrade.json",
        "transition-plan.json",
        "transition-summary.json",
        "wheel-bundle.json",
    ],
)
def test_replacement_after_validation_is_sealed_but_cannot_pass(monkeypatch, tmp_path, keys, filename):
    output, _ = _run(monkeypatch, tmp_path)
    original = ci.encrypt_samples
    replacement = b'{"raced_private_witness":true}'

    def race(**kwargs):
        (output / "private_samples" / filename).write_bytes(replacement)
        return original(**kwargs)

    monkeypatch.setattr(ci, "encrypt_samples", race)
    receipt = _archive(monkeypatch, tmp_path, output, keys)
    assert receipt["status"] == "encrypted"
    assert read_public(output / "aggregate/archive-validation.json")["passed"] is False
    restored = dict(encrypted.open_archive((output / "encrypted/checkpoints.hge").read_bytes(), keys[1])[0])
    assert restored[filename] == replacement
    with pytest.raises(ValueError, match="transition_archive_invalid"):
        ci.retention(output, CONTEXT)


def test_replacement_after_snapshot_cannot_change_sealed_validated_bytes(monkeypatch, tmp_path, keys):
    output, _ = _run(monkeypatch, tmp_path)
    original = encrypted.seal
    filename = "installed-transition-candidate_upgrade.json"
    expected = (output / "private_samples" / filename).read_bytes()

    def race(files, *args, **kwargs):
        (output / "private_samples" / filename).write_bytes(b'{"later_private_witness":true}')
        return original(files, *args, **kwargs)

    monkeypatch.setattr(encrypted, "seal", race)
    _archive(monkeypatch, tmp_path, output, keys)
    ci.retention(output, CONTEXT)
    restored = dict(encrypted.open_archive((output / "encrypted/checkpoints.hge").read_bytes(), keys[1])[0])
    assert restored[filename] == expected
