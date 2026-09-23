from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.evaluation_contracts import (
    EVALUATION_PROFILE_SCHEMA_VERSION,
    EVALUATION_RESULT_SCHEMA_VERSION,
    EvaluationContractError,
    EvaluationProfile,
    EvaluationResult,
    evaluation_profile_schema,
    evaluation_result_schema,
    validate_evaluation_profile,
)


def _profile(tmp_path: Path) -> dict[str, object]:
    root = tmp_path / "evaluation-root"
    endpoint = "http://127.0.0.1:8765/receiver"
    artifact_digest = "sha256:" + "b" * 64
    return {
        "schemaVersion": EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": "synthetic-local-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.4.2",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": {
            "product": "synthetic-agent",
            "version": "0.1.0",
            "os": "linux",
            "architecture": "x86_64",
            "runtimeLocation": "local",
            "requiredPrivilege": "standard_user",
        },
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.4.2",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "d" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root / "workspace")],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _result(profile: dict[str, object]) -> dict[str, object]:
    root = Path(profile["targetScope"]["rootPath"])  # type: ignore[index]
    endpoint = profile["targetScope"]["allowedEndpoints"][0]  # type: ignore[index]
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    return {
        "schemaVersion": EVALUATION_RESULT_SCHEMA_VERSION,
        "resultId": "result-1",
        "profileId": profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {
                    "kind": "loopback_receiver",
                    "path": str(root / "workspace" / "sentinel"),
                    "endpoint": endpoint,
                    "digest": "sha256:" + "e" * 64,
                    "note": "synthetic local witness",
                },
            }
        ],
    }


def test_evaluation_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(evaluation_profile_schema())
    Draft202012Validator.check_schema(evaluation_result_schema())


def test_profile_and_result_roundtrip_with_exact_identities(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile = EvaluationProfile.from_dict(profile_payload)
    result_payload = _result(profile_payload)
    result = EvaluationResult.from_dict(result_payload, profile=profile)

    assert profile.to_dict() == profile_payload
    assert result.to_dict() == result_payload


def test_result_cannot_omit_a_profile_capability(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"].append({"capabilityId": "synthetic.shell", "expectedAction": "block"})
    with pytest.raises(EvaluationContractError, match="cover exactly"):
        EvaluationResult.from_dict(_result(profile_payload), profile=EvaluationProfile.from_dict(profile_payload))


def test_passed_result_requires_a_profile_for_coverage(tmp_path: Path) -> None:
    with pytest.raises(EvaluationContractError, match="requires the evaluation profile"):
        EvaluationResult.from_dict(_result(_profile(tmp_path)))


def test_passed_enforcement_requires_live_host_witness(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"][0]["expectedAction"] = "block"
    result_payload = _result(profile_payload)
    result_payload["cases"][0]["expectedAction"] = "block"
    result_payload["cases"][0]["observedAction"] = "block"
    result_payload["cases"][0]["witness"] = {"kind": "none"}
    profile = EvaluationProfile.from_dict(profile_payload)
    with pytest.raises(EvaluationContractError, match="live installed host"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["evidenceIdentity"]["evidenceType"] = "live_installed_host_test"
    result_payload["cases"][0]["proofType"] = "live_installed_host_test"
    with pytest.raises(EvaluationContractError, match="side-effect witness"):
        EvaluationResult.from_dict(result_payload, profile=profile)


def test_unknown_profile_fields_are_rejected(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["unexpected"] = "must not be accepted"

    with pytest.raises(ValidationError):
        Draft202012Validator(evaluation_profile_schema()).validate(payload)
    with pytest.raises(EvaluationContractError, match="evaluation profile is invalid"):
        validate_evaluation_profile(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "targetScope",
            {
                "rootPath": "/Users/not-a-temp-root",
                "allowedPaths": ["/Users/not-a-temp-root"],
                "allowedEndpoints": ["http://127.0.0.1:8765"],
            },
        ),
        ("network", {"mode": "local_only", "allowedEndpoints": ["https://example.invalid/receiver"], "proxyUrl": None}),
    ],
)
def test_unsafe_scope_is_rejected_by_schema_and_runtime(
    tmp_path: Path,
    field: str,
    value: dict[str, object],
) -> None:
    payload = _profile(tmp_path)
    payload[field] = value

    with pytest.raises(ValidationError):
        Draft202012Validator(evaluation_profile_schema()).validate(payload)
    with pytest.raises(EvaluationContractError):
        validate_evaluation_profile(payload)


def test_absolute_path_escape_is_rejected_even_inside_tmp_prefix(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    root = Path(payload["targetScope"]["rootPath"])  # type: ignore[index]
    payload["targetScope"]["allowedPaths"] = [str(root / ".." / "outside")]  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="remain under"):
        validate_evaluation_profile(payload)


def test_temp_parent_itself_cannot_be_the_disposable_scope(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["targetScope"]["rootPath"] = "/tmp"  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="temporary test root"):
        validate_evaluation_profile(payload)


def test_foreign_windows_temp_path_is_rejected_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX validation boundary")
    payload = _profile(tmp_path)
    scope = payload["targetScope"]  # type: ignore[assignment]
    scope["rootPath"] = r"C:\Users\tester\AppData\Local\Temp\evaluation"
    scope["allowedPaths"] = [r"C:\Users\tester\AppData\Local\Temp\evaluation\workspace"]

    with pytest.raises(EvaluationContractError, match="temporary test root"):
        validate_evaluation_profile(payload)


def test_hostname_endpoint_cannot_rebind_outside_loopback(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["network"]["allowedEndpoints"] = ["http://localhost:8765/receiver"]  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="evaluation profile is invalid"):
        validate_evaluation_profile(payload)


def test_result_witness_must_stay_in_profile_scope(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0]["witness"]["endpoint"] = "http://127.0.0.1:8766/other"  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="outside the profile target scope"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_result_witness_must_be_in_an_allowed_path(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    root = Path(profile_payload["targetScope"]["rootPath"])  # type: ignore[index]
    result_payload["cases"][0]["witness"]["path"] = str(root / "other" / "sentinel")  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="outside the profile target scope"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_result_status_vocabulary_is_closed(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["status"] = "green"

    with pytest.raises(EvaluationContractError, match="evaluation result is invalid"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


@pytest.mark.parametrize(
    "case_change",
    [
        {"proofType": "not_run"},
        {"observedAction": "block"},
        {"observedAction": None},
        {"expectedAction": "unsupported", "observedAction": "unsupported"},
    ],
)
def test_passed_case_cannot_hide_missing_or_mismatched_proof(
    tmp_path: Path, case_change: dict[str, object]
) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0].update(case_change)  # type: ignore[index]
    with pytest.raises(EvaluationContractError):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_passed_result_cannot_hide_unrun_case(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0].update(  # type: ignore[index]
        {"status": "not_run", "proofType": "not_run", "observedAction": None}
    )
    with pytest.raises(EvaluationContractError, match="unpassed case"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))
