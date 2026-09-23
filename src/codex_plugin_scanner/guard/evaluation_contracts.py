"""Strict, versioned contracts for bounded local evaluation runs.

The contracts describe an evaluation profile and its results.  They do not
execute scenarios or change Guard policy.  JSON Schema provides the stable
wire shape; the semantic checks below bind paths and endpoints to a local,
temporary test scope.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import ntpath
import os
import tempfile
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator

EVALUATION_PROFILE_SCHEMA_VERSION = "guard.evaluation-profile.v1"
EVALUATION_RESULT_SCHEMA_VERSION = "guard.evaluation-result.v1"

EvaluationStatus = Literal["passed", "failed", "unsupported", "blocked_environment", "not_run"]
EvidenceType = Literal[
    "source_inspection",
    "unit_test",
    "property_test",
    "synthetic_adapter_test",
    "live_installed_host_test",
    "independent_review",
    "not_run",
]

EVALUATION_STATUSES: frozenset[str] = frozenset({"passed", "failed", "unsupported", "blocked_environment", "not_run"})
EVIDENCE_TYPES: frozenset[str] = frozenset(
    {
        "source_inspection",
        "unit_test",
        "property_test",
        "synthetic_adapter_test",
        "live_installed_host_test",
        "independent_review",
        "not_run",
    }
)

_POSIX_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/var/folders")


class EvaluationContractError(ValueError):
    """A profile or result failed structural or local-scope validation."""


def _load_schema(filename: str) -> dict[str, object]:
    schema_path = Path(__file__).resolve().parent / "schemas" / filename
    try:
        return cast(dict[str, object], json.loads(schema_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationContractError(f"unable to load evaluation schema {filename}") from exc


def evaluation_profile_schema() -> dict[str, object]:
    """Return a copy of the profile JSON Schema."""

    return copy.deepcopy(_load_schema("evaluation-profile-v1.schema.json"))


def evaluation_result_schema() -> dict[str, object]:
    """Return a copy of the result JSON Schema."""

    return copy.deepcopy(_load_schema("evaluation-result-v1.schema.json"))


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EvaluationContractError(f"{name} must be an object")
    return dict(value)


def _schema_validate(payload: object, schema: dict[str, object], name: str) -> dict[str, object]:
    candidate = _mapping(payload, name)
    validator = Draft202012Validator(schema)
    error = next(iter(validator.iter_errors(cast(Any, candidate))), None)
    if error is not None:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise EvaluationContractError(f"{name} is invalid at {location}: {error.message}") from error
    return candidate


def _path_is_within(path: str, root: str) -> bool:
    candidate = os.path.realpath(path)
    root_path = os.path.realpath(root)
    try:
        return os.path.commonpath((candidate, root_path)) == root_path
    except ValueError:
        return False


def _is_posix_temp_path(path: str) -> bool:
    if "\x00" in path or not os.path.isabs(path):
        return False
    candidate = os.path.realpath(path)
    roots = {os.path.realpath(root) for root in _POSIX_TEMP_ROOTS}
    return any(candidate.startswith(f"{root}{os.sep}") for root in roots)


def _is_windows_temp_path(path: str) -> bool:
    if os.name != "nt" or "\x00" in path or not ntpath.isabs(path) or path.startswith("\\\\"):
        return False
    candidate = ntpath.normcase(ntpath.normpath(path))
    temp_root = ntpath.normcase(ntpath.normpath(tempfile.gettempdir()))
    try:
        return candidate != temp_root and ntpath.commonpath((candidate, temp_root)) == temp_root
    except ValueError:
        return False


def _validate_local_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvaluationContractError(f"{name} must be an absolute temporary path")
    if not (_is_posix_temp_path(value) or _is_windows_temp_path(value)):
        raise EvaluationContractError(f"{name} must remain under a temporary test root")
    return value


def _validate_local_endpoint(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(char.isspace() for char in value):
        raise EvaluationContractError(f"{name} must be a loopback HTTP(S) endpoint")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise EvaluationContractError(f"{name} must be a loopback HTTP(S) endpoint") from exc
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        raise EvaluationContractError(f"{name} must be a loopback HTTP(S) endpoint")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise EvaluationContractError(f"{name} must not contain credentials or a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise EvaluationContractError(f"{name} has an invalid port")
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise EvaluationContractError(f"{name} must use a numeric loopback IP")
    return value


def _validate_profile_semantics(profile: Mapping[str, object]) -> None:
    build = _mapping(profile["buildIdentity"], "buildIdentity")
    artifacts = [_mapping(item, "installedArtifacts[]") for item in cast(list[object], profile["installedArtifacts"])]
    artifact_digests = {cast(str, item["digest"]) for item in artifacts}
    if build["artifactDigest"] not in artifact_digests:
        raise EvaluationContractError("buildIdentity.artifactDigest must identify an installed artifact")
    capability_ids = [
        _mapping(item, "expectedCapabilities[]")["capabilityId"]
        for item in cast(list[object], profile["expectedCapabilities"])
    ]
    if len(capability_ids) != len(set(capability_ids)):
        raise EvaluationContractError("profile has duplicate expected capability IDs")

    scope = _mapping(profile["targetScope"], "targetScope")
    root_path = _validate_local_path(scope["rootPath"], "targetScope.rootPath")
    for path in cast(list[object], scope["allowedPaths"]):
        candidate = _validate_local_path(path, "targetScope.allowedPaths[]")
        if not _path_is_within(candidate, root_path):
            raise EvaluationContractError("targetScope.allowedPaths[] must remain under targetScope.rootPath")
    scope_endpoints = {
        _validate_local_endpoint(endpoint, "targetScope.allowedEndpoints[]")
        for endpoint in cast(list[object], scope["allowedEndpoints"])
    }

    network = _mapping(profile["network"], "network")
    network_endpoints = {
        _validate_local_endpoint(endpoint, "network.allowedEndpoints[]")
        for endpoint in cast(list[object], network["allowedEndpoints"])
    }
    if not network_endpoints.issubset(scope_endpoints):
        raise EvaluationContractError("network.allowedEndpoints must be within targetScope.allowedEndpoints")
    if network.get("proxyUrl") is not None:
        proxy_url = _validate_local_endpoint(network["proxyUrl"], "network.proxyUrl")
        if proxy_url not in scope_endpoints:
            raise EvaluationContractError("network.proxyUrl must be within targetScope.allowedEndpoints")


def validate_evaluation_profile(payload: object) -> None:
    """Validate a profile's wire shape and local-only execution scope."""

    profile = _schema_validate(payload, evaluation_profile_schema(), "evaluation profile")
    _validate_profile_semantics(profile)


def _validate_result_semantics(result: Mapping[str, object], profile: Mapping[str, object] | None) -> None:
    artifact = _mapping(result["artifactIdentity"], "artifactIdentity")
    build = _mapping(result["buildIdentity"], "buildIdentity")
    evidence = _mapping(result["evidenceIdentity"], "evidenceIdentity")
    artifact_digest = artifact["digest"]
    if build["artifactDigest"] != artifact_digest:
        raise EvaluationContractError("buildIdentity.artifactDigest must match artifactIdentity.digest")
    if evidence["artifactDigest"] != artifact_digest:
        raise EvaluationContractError("evidenceIdentity.artifactDigest must match artifactIdentity.digest")
    if result["status"] == "passed" and evidence["evidenceType"] == "not_run":
        raise EvaluationContractError("passed evaluation result requires executed evidence")

    case_ids: set[str] = set()
    case_statuses: list[str] = []
    for raw_case in cast(list[object], result["cases"]):
        case = _mapping(raw_case, "cases[]")
        case_id = cast(str, case["caseId"])
        if case_id in case_ids:
            raise EvaluationContractError(f"duplicate result caseId: {case_id}")
        case_ids.add(case_id)
        case_status = cast(str, case["status"])
        case_statuses.append(case_status)
        if case_status == "passed" and (
            case["proofType"] == "not_run"
            or case["expectedAction"] in {"unsupported", "not_run"}
            or case["observedAction"] != case["expectedAction"]
        ):
            raise EvaluationContractError(f"passed case {case_id} requires executed proof and matching action")
        witness = _mapping(case["witness"], "cases[].witness")
        if witness.get("path") is not None:
            _ = _validate_local_path(witness["path"], "cases[].witness.path")
        if witness.get("endpoint") is not None:
            _ = _validate_local_endpoint(witness["endpoint"], "cases[].witness.endpoint")
        if case_status == "passed" and case["expectedAction"] in {
            "block",
            "approval",
            "rewrite",
            "redact-before-forward",
        }:
            if (
                case["proofType"] != "live_installed_host_test"
                or evidence["evidenceType"] != "live_installed_host_test"
            ):
                raise EvaluationContractError("passed enforcement case requires live installed host evidence")
            if witness["kind"] == "none" or not (witness.get("path") or witness.get("endpoint")):
                raise EvaluationContractError("passed enforcement case requires a side-effect witness")
    if result["status"] == "passed" and any(status != "passed" for status in case_statuses):
        raise EvaluationContractError("passed evaluation result cannot include an unpassed case")

    if profile is None:
        if result["status"] == "passed" or "passed" in case_statuses:
            raise EvaluationContractError("passed result requires the evaluation profile for complete coverage")
        return
    profile_id = cast(str, profile["profileId"])
    if result["profileId"] != profile_id:
        raise EvaluationContractError("result.profileId does not match the supplied profile")
    if result["buildIdentity"] != profile["buildIdentity"]:
        raise EvaluationContractError("result.buildIdentity does not match the supplied profile")
    profile_artifacts = {
        _mapping(item, "installedArtifacts[]")["digest"] for item in cast(list[object], profile["installedArtifacts"])
    }
    if artifact_digest not in profile_artifacts:
        raise EvaluationContractError("result.artifactIdentity is not installed by the supplied profile")
    expected_items = [
        _mapping(item, "expectedCapabilities[]") for item in cast(list[object], profile["expectedCapabilities"])
    ]
    expected_capabilities = {
        cast(str, item["capabilityId"]): cast(str, item["expectedAction"]) for item in expected_items
    }
    if len(expected_capabilities) != len(expected_items):
        raise EvaluationContractError("profile has duplicate expected capability IDs")
    if case_ids != expected_capabilities.keys():
        raise EvaluationContractError("result cases must cover exactly the profile expected capabilities")
    scope = _mapping(profile["targetScope"], "targetScope")
    root_path = cast(str, scope["rootPath"])
    allowed_paths = cast(list[str], scope["allowedPaths"])
    allowed_endpoints = set(cast(list[str], scope["allowedEndpoints"]))
    for raw_case in cast(list[object], result["cases"]):
        case = _mapping(raw_case, "cases[]")
        if case["expectedAction"] != expected_capabilities[cast(str, case["caseId"])]:
            raise EvaluationContractError("result case expected action differs from the profile")
        witness = _mapping(case["witness"], "cases[].witness")
        if witness.get("path") is not None:
            witness_path = cast(str, witness["path"])
            if not _path_is_within(witness_path, root_path) or not any(
                _path_is_within(witness_path, allowed_path) for allowed_path in allowed_paths
            ):
                raise EvaluationContractError("result witness path is outside the profile target scope")
        endpoint = witness.get("endpoint")
        if endpoint is not None and endpoint not in allowed_endpoints:
            raise EvaluationContractError("result witness endpoint is outside the profile target scope")


def validate_evaluation_result(payload: object, profile: object | None = None) -> None:
    """Validate a result and, when supplied, bind it to its profile."""

    result = _schema_validate(payload, evaluation_result_schema(), "evaluation result")
    profile_mapping = None
    if profile is not None:
        profile_mapping = _mapping(profile.data if isinstance(profile, EvaluationProfile) else profile, "profile")
        validate_evaluation_profile(profile_mapping)
    _validate_result_semantics(result, profile_mapping)


@dataclass(frozen=True, slots=True)
class EvaluationProfile:
    """Validated profile payload retained for deterministic round-tripping."""

    data: dict[str, object]

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> EvaluationProfile:
        validate_evaluation_profile(payload)
        return cls(copy.deepcopy(dict(payload)))

    def to_dict(self) -> dict[str, object]:
        return copy.deepcopy(self.data)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Validated result payload retained for deterministic round-tripping."""

    data: dict[str, object]

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, object],
        *,
        profile: EvaluationProfile | Mapping[str, object] | None = None,
    ) -> EvaluationResult:
        validate_evaluation_result(payload, profile)
        return cls(copy.deepcopy(dict(payload)))

    def to_dict(self) -> dict[str, object]:
        return copy.deepcopy(self.data)


__all__ = [
    "EVALUATION_PROFILE_SCHEMA_VERSION",
    "EVALUATION_RESULT_SCHEMA_VERSION",
    "EVALUATION_STATUSES",
    "EVIDENCE_TYPES",
    "EvaluationContractError",
    "EvaluationProfile",
    "EvaluationResult",
    "evaluation_profile_schema",
    "evaluation_result_schema",
    "validate_evaluation_profile",
    "validate_evaluation_result",
]
