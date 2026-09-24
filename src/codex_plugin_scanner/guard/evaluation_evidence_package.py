"""Deterministic, local packaging of validated evaluation records.

An archive preserves caller-supplied profile and result records. Its hashes
detect accidental corruption when a separately trusted archive digest is
available; they do not authenticate a host action or upgrade proof level.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import zipfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .evaluation_contracts import (
    EvaluationContractError,
    EvaluationProfile,
    EvaluationResult,
    validate_evaluation_profile,
    validate_evaluation_result,
)
from .evaluation_preflight import _safe_temp_parent

EVALUATION_EVIDENCE_PACKAGE_SCHEMA_VERSION = "guard.evaluation-evidence-package.v1"
_PROFILE_NAME = "profile.json"
_RESULT_NAME = "result.json"
_MANIFEST_NAME = "manifest.json"
_ARCHIVE_NAMES = (_PROFILE_NAME, _RESULT_NAME, _MANIFEST_NAME)
_MAX_PACKAGE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class EvaluationEvidencePackage:
    """One newly written local archive, with its separately pinnable digest."""

    path: Path
    digest: str
    size_bytes: int


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _record_payloads(
    profile: EvaluationProfile | Mapping[str, object],
    result: EvaluationResult | Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    profile_payload = profile.to_dict() if isinstance(profile, EvaluationProfile) else copy.deepcopy(dict(profile))
    result_payload = result.to_dict() if isinstance(result, EvaluationResult) else copy.deepcopy(dict(result))
    validate_evaluation_profile(profile_payload)
    validate_evaluation_result(result_payload, profile_payload)
    return profile_payload, result_payload


def _manifest(
    profile: Mapping[str, object], result: Mapping[str, object], profile_bytes: bytes, result_bytes: bytes
) -> dict[str, object]:
    return {
        "schemaVersion": EVALUATION_EVIDENCE_PACKAGE_SCHEMA_VERSION,
        "profileId": profile["profileId"],
        "resultId": result["resultId"],
        "proofBoundary": "caller_supplied_unverified",
        "files": [
            {
                "path": _PROFILE_NAME,
                "sha256": hashlib.sha256(profile_bytes).hexdigest(),
                "sizeBytes": len(profile_bytes),
            },
            {"path": _RESULT_NAME, "sha256": hashlib.sha256(result_bytes).hexdigest(), "sizeBytes": len(result_bytes)},
        ],
    }


def build_evaluation_evidence_package(
    profile: EvaluationProfile | Mapping[str, object],
    result: EvaluationResult | Mapping[str, object],
) -> bytes:
    """Return reproducible archive bytes without reading host files or logs."""

    profile_payload, result_payload = _record_payloads(profile, result)
    profile_bytes = _json_bytes(profile_payload)
    result_bytes = _json_bytes(result_payload)
    manifest_bytes = _json_bytes(_manifest(profile_payload, result_payload, profile_bytes, result_bytes))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in (
            (_PROFILE_NAME, profile_bytes),
            (_RESULT_NAME, result_bytes),
            (_MANIFEST_NAME, manifest_bytes),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    packaged = buffer.getvalue()
    limits = cast(Mapping[str, object], profile_payload["resourceLimits"])
    if len(packaged) > min(cast(int, limits["maxOutputBytes"]), _MAX_PACKAGE_BYTES):
        raise EvaluationContractError("evaluation evidence package exceeds the declared output limit")
    return packaged


def verify_evaluation_evidence_package(data: bytes) -> dict[str, object]:
    """Verify archive integrity and record contracts, without claiming authenticity."""

    if not isinstance(data, bytes) or len(data) > _MAX_PACKAGE_BYTES:
        raise EvaluationContractError("evaluation evidence package is invalid or oversized")
    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as archive:
            if archive.namelist() != list(_ARCHIVE_NAMES):
                raise EvaluationContractError("evaluation evidence package has unexpected entries")
            entries = archive.infolist()
            if (
                any(info.compress_type != zipfile.ZIP_STORED for info in entries)
                or sum(info.file_size for info in entries) > _MAX_PACKAGE_BYTES
            ):
                raise EvaluationContractError("evaluation evidence package has an oversized entry")
            profile_bytes = archive.read(_PROFILE_NAME)
            result_bytes = archive.read(_RESULT_NAME)
            manifest_bytes = archive.read(_MANIFEST_NAME)
        profile = json.loads(profile_bytes)
        result = json.loads(result_bytes)
        manifest = json.loads(manifest_bytes)
        if not isinstance(profile, Mapping) or not isinstance(result, Mapping):
            raise EvaluationContractError("evaluation evidence records must be objects")
        profile_payload, result_payload = _record_payloads(profile, result)
        expected_manifest = _manifest(profile_payload, result_payload, profile_bytes, result_bytes)
        if manifest != expected_manifest:
            raise EvaluationContractError("evaluation evidence manifest does not match its records")
        if build_evaluation_evidence_package(profile_payload, result_payload) != data:
            raise EvaluationContractError("evaluation evidence package is not in canonical form")
        return expected_manifest
    except (OSError, UnicodeError, json.JSONDecodeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise EvaluationContractError("evaluation evidence package could not be read") from exc


def write_evaluation_evidence_package(
    profile: EvaluationProfile | Mapping[str, object],
    result: EvaluationResult | Mapping[str, object],
    *,
    output_dir: str | Path,
) -> EvaluationEvidencePackage:
    """Write one archive exclusively under the profile's private temp root."""

    profile_payload, result_payload = _record_payloads(profile, result)
    scope = cast(Mapping[str, object], profile_payload["targetScope"])
    declared_root = Path(cast(str, scope["rootPath"]))
    destination_root = Path(output_dir)
    if (
        not destination_root.is_absolute()
        or not _safe_temp_parent(destination_root)
        or os.path.normcase(os.path.realpath(destination_root)) != os.path.normcase(os.path.realpath(declared_root))
    ):
        raise EvaluationContractError("evaluation evidence output must be the profile's private temporary root")
    packaged = build_evaluation_evidence_package(profile_payload, result_payload)
    digest = hashlib.sha256(packaged).hexdigest()
    destination = destination_root / f"hol-guard-eval-evidence-{digest[:24]}.zip"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(packaged)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if created:
            with suppress(OSError):
                destination.unlink()
        raise EvaluationContractError("unable to write evaluation evidence package without overwriting") from exc
    return EvaluationEvidencePackage(destination, f"sha256:{digest}", len(packaged))


__all__ = [
    "EVALUATION_EVIDENCE_PACKAGE_SCHEMA_VERSION",
    "EvaluationEvidencePackage",
    "build_evaluation_evidence_package",
    "verify_evaluation_evidence_package",
    "write_evaluation_evidence_package",
]
