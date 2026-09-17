"""Bounded public pair evidence; identifiers never select filesystem paths."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from scripts.native_slo_evidence_files import atomic_exclusive, read_file

REPORT_LIMIT = 256 * 1024
MANIFEST_LIMIT = 64 * 1024


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "pair_duplicate_json_key")
        result[key] = value
    return result


def decode(encoded: bytes) -> dict[str, Any]:
    def invalid(_value: str) -> object:
        raise ValueError("pair_nonfinite_json")

    try:
        value = json.loads(encoded, object_pairs_hook=_unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("pair_invalid_json") from error
    require(isinstance(value, dict), "pair_json_object_required")
    return cast(dict[str, Any], value)


def read_public(path: Path, limit: int = REPORT_LIMIT) -> dict[str, Any]:
    from scripts.native_slo_contract import assert_privacy_safe

    value = decode(read_file(path, limit))
    require(assert_privacy_safe(value) == value, "pair_public_evidence_not_safe")
    return value


def write_public(path: Path, value: Mapping[str, object], limit: int = REPORT_LIMIT) -> None:
    from scripts.native_slo_contract import assert_privacy_safe

    require(assert_privacy_safe(value) == value, "pair_public_evidence_not_safe")
    encoded = canonical(value) + b"\n"
    require(len(encoded) <= limit, "pair_public_evidence_bound")
    atomic_exclusive(path, encoded)


def digest_file(path: Path, limit: int) -> str:
    # Reuse the retained-directory reader for regular-file/type/size/race checks.
    # This runs outside measured work and bounds memory by the declared artifact
    # limit; a FIFO/device or a replaced path cannot turn hashing into a wait.
    return hashlib.sha256(read_file(path, limit)).hexdigest()
